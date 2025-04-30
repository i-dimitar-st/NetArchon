import os
import time
import sched
import sqlite3
import logging
import socket
import json
import ipaddress
import subprocess
import sys
import re
import queue
from typing import Callable
from collections import deque
import scapy.all as scapy
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from threading import Thread, Lock
from services import MainLogger

# fmt: off
sys.path.append('/projects/gitlab/netarchon/venv/lib/python3.12/site-packages')
import pika # type: ignore
# fmt: on

INBOUND_REQUESTS_DEDUPLICATE_QUEUE_SIZE = 30

dhcp_logger = MainLogger.get_logger(service_name="DHCP", log_level=logging.DEBUG)


class Config:
    """Configuration manager for DHCP settings and paths."""
    config_file = 'config/dhcp_config.json'
    _config = {}

    @classmethod
    def initialize(cls):
        """Ensure required directories exist and load config."""
        os.makedirs(os.path.dirname(cls.config_file), exist_ok=True)
        cls._load_config()

    @classmethod
    def _load_config(cls):
        """Load the configuration file as a dictionary."""
        try:
            with open(cls.config_file, "r") as file_handle:
                cls._config = json.load(file_handle)
        except Exception as e:
            print(f'Error loading config file {cls.config_file}: {str(e)}')
            cls._config = {}  # Ensure _config is always initialized

    @classmethod
    def get_config(cls) -> dict:
        """Return the loaded config."""
        return cls._config


Config.initialize()


class Scheduler:
    def __init__(self: "Scheduler", interval: int = 60, function: Callable = None, function_arguments: list = None) -> None:
        """Initialize the Scheduler."""
        if function is None:
            raise ValueError("Function missing")
        self._scheduler = sched.scheduler(timefunc=time.monotonic, delayfunc=time.sleep)
        self._schedule_interval = interval
        self._schedule_function = function
        self._schedule_arguments = function_arguments or []
        self._schedule_status_running = False

    def start_schedule(self: "Scheduler") -> None:
        """Start the scheduler."""
        self._schedule_status_running = True
        self._enter_task()
        scheduler_thread = Thread(
            target=self._scheduler.run,
            daemon=True,
            name=f"scheduler-{str(self._schedule_function.__name__)}")
        scheduler_thread.start()

    def _enter_task(self: "Scheduler") -> None:
        """Queue next task for scheduling."""
        if self._schedule_status_running:  # Check if the scheduler is still running
            self._scheduler.enter(delay=self._schedule_interval,
                                  priority=1,
                                  action=self.task_runner,
                                  argument=self._schedule_arguments)

    def task_runner(self: "Scheduler") -> None:
        """Execute the scheduled function with its arguments."""
        if self._schedule_function:
            try:
                self._schedule_function(*self._schedule_arguments)
            except Exception as e:
                dhcp_logger.error(f"Error while executing the scheduled function: {e}")

        # This is what schedules the next taks
        if self._schedule_status_running:
            self._enter_task()

    def stop_schedule(self: "Scheduler") -> None:
        """Stop the scheduler."""
        self._schedule_status_running = False
        dhcp_logger.info("Scheduler stopped.")


class Stats:
    _stats = {
        'DHCP_TOTAL': 0,
        'DHCP_DISCOVER': 0,
        'DHCP_REQUEST': 0,
        'DHCP_RELEASE': 0,
        'DHCP_DECLINE': 0,
        'DHCP_INFORM': 0
    }
    _lock = Lock()

    @classmethod
    def increment(cls, key: str, value: int = 1) -> None:
        """Increment a specific statistic counter."""
        with cls._lock:
            if key in cls._stats:
                cls._stats[key] += value

    @classmethod
    def decrement(cls, key: str, value: int = 1) -> None:
        """Decrement a specific statistic counter."""
        with cls._lock:
            if key in cls._stats and cls._stats[key] > 0:
                cls._stats[key] -= value

    @classmethod
    def get_all_statistics(cls) -> dict:
        """Retrieve all statistics."""
        return cls._stats.copy()

    @classmethod
    def print_all_statistics(cls) -> None:
        """Print all statistics."""
        stats = ','.join([f"{key}:{value}" for key, value in cls.get_all_statistics().items()])
        dhcp_logger.debug(f"Statistics: {stats}")


class RabbitMqProducer:
    consumer_tag = 'dhcp_server_producer'
    queue_name = 'dhcp_server'
    host = '127.0.0.1'
    connection = None
    channel = None

    @classmethod
    def _connect(class_self: "RabbitMqProducer") -> None:
        """
        Establish a RabbitMQ connection and declare the queue with specific configurations.
        """
        try:
            # Create connection and declare the queue
            class_self.connection = pika.BlockingConnection(pika.ConnectionParameters(class_self.host))
            class_self.channel = class_self.connection.channel()
            class_self.channel.queue_declare(
                queue=class_self.queue_name,  # Queue name
                durable=True,                 # Survive server restarts
                exclusive=False,              # Shared with other consumers
                auto_delete=False,            # Don't auto-delete
                # arguments={
                # "x-message-ttl": 60000,  # Message TTL (30 seconds)
                # "x-max-length": 1000,     # Max 250 messages in the queue
                # "x-dead-letter-exchange": "dlx_exchange"  # Dead-letter exchange
                # }
            )
        except Exception as e:
            dhcp_logger.error(f"RabbitMQ Connection error: {e}")
            class_self.connection = None
            class_self.channel = None

    @classmethod
    def send_message(class_self: "RabbitMqProducer", message: dict = None) -> None:
        """
        Publish a message to the RabbitMQ queue and close the connection.
        """

        if message is None:
            dhcp_logger.error('RabbitMQ - no message provided to send.')
            return

        if not class_self.channel or class_self.channel.is_closed:
            class_self._connect()
            if not class_self.channel:
                dhcp_logger.error('RabbitMQ - unable to establish connection to send message.')
                return

        try:

            message_properties = pika.BasicProperties(
                delivery_mode=2,                       # Persistent message (default: None)
                priority=0,                            # No priority set (default: None)
                correlation_id=None,                   # No correlation ID (default: None)
                reply_to=None,                         # No reply-to queue (default: None)
                expiration=None,                       # No expiration time set (default: None)
                message_id=None,                       # No message ID (default: None)
                timestamp=None,                        # No timestamp set (default: None)
                type=None,                             # No type set (default: None)
                user_id=None,                          # No user ID (default: None)
                app_id=None,                           # No app ID (default: None)
                cluster_id=None,                       # No cluster ID (default: None)
                headers=None                           # No custom headers (default: None)
            )

            class_self.channel.basic_publish(
                exchange='',                                          # Default direct exchange
                routing_key=class_self.queue_name,                    # Queue name as routing key
                body=json.dumps(message).encode('utf-8'),             # Serialize message
                properties=message_properties,
                mandatory=False,                                      # Do not return undeliverable messages
            )

        except Exception as e:
            dhcp_logger.error(f"RabbitMQ Producer error sending message: {e}")
        finally:
            class_self.close()

    @classmethod
    def close(class_self: "RabbitMqProducer") -> None:
        """
        Close the RabbitMQ connection gracefully if it's open.
        """
        if class_self.connection and not class_self.connection.is_closed:
            class_self.connection.close()


class DHCPUtilities:

    @staticmethod
    def convert_dhcp_lease_to_string(dhcpType: int = 1) -> str:
        DHCPTypes = {
            1: "discover",
            2: "offer",
            3: "request",
            4: "decline",
            5: "ack",
            6: "nak",
            7: "release",
            8: "inform",
            9: "force_renew",
            10: "lease_query",
            11: "lease_unassigned",
            12: "lease_unknown",
            13: "lease_active",
        }
        return DHCPTypes.get(dhcpType, 'unknown')

    @staticmethod
    def extract_dhcp_type_from_packet(packet: DHCP) -> str:
        """Extract the DHCP message type from the packet."""
        for opt in packet[DHCP].options:
            if opt[0] == "message-type":
                return opt[1]
        return None

    @staticmethod
    def extract_requested_addr_from_dhcp_packet(packet: DHCP) -> str | None:
        """Extract the requested IP address from a DHCP packet."""
        for option in packet[DHCP].options:
            if option[0] == "requested_addr":
                return option[1]
        return None

    @staticmethod
    def extract_source_mac_from_ethernet_packet(packet: Ether) -> str:
        """Extract the source MAC address from the Ethernet layer of the packet."""
        return packet[Ether].src

    @staticmethod
    def extract_client_mac_from_dhcp_packet(packet: DHCP) -> str:
        """Extract the first 6 bytes of the MAC address from the packet."""
        return DHCPUtilities.format_mac(packet[BOOTP].chaddr[:6])

    @staticmethod
    def extract_client_ip_address_from_dhcp_packet(packet: DHCP) -> str:
        """Extract the 'Client IP Address' (ciaddr) from a DHCP request packet (renewal)."""
        return packet[BOOTP].ciaddr

    @staticmethod
    def extract_your_ip_address_from_dhcp_packet(packet: DHCP) -> str:
        """Extract the 'Your IP Address' (yiaddr) from the DHCP offer packet."""
        return packet[BOOTP].yiaddr

    @staticmethod
    def extract_secs_from_dhcp_packet(packet: DHCP) -> str:
        """Extract the 'Seconds Elapsed' (secs) from the DHCP packet."""
        return packet[BOOTP].secs

    @staticmethod
    def is_packet_from_server(packet: Ether) -> bool:
        return packet[Ether].src == '18:c0:4d:46:f4:11'

    @staticmethod
    def extract_source_ip_from_ethernet_packet(packet: Ether) -> str:
        """Extract the client IP address from the Ethernet frame."""
        if packet.haslayer(IP):
            return packet[IP].src
        else:
            raise ValueError("No IP layer found in the Ethernet frame")

    @staticmethod
    def extract_transaction_id_from_dhcp_packet(packet: DHCP) -> str:
        """Extract the XID from packet."""
        return packet[BOOTP].xid

    @staticmethod
    def extract_lease_time_from_offer(offer: DHCP) -> int:
        """Extract lease time from a DHCP offer packet."""
        for opt in offer[DHCP].options:
            if opt[0] == "lease_time":
                return opt[1]
        return None

    @staticmethod
    def extract_hostname_from_dhcp_packet(packet: DHCP) -> str:
        for option in packet[scapy.DHCP].options:
            if option[0] == 'hostname':
                return DHCPUtilities.convert_binary_to_string(option[1])
        return 'unknown'

    @staticmethod
    def extract_vendor_cid_from_dhcp_packet(packet: DHCP) -> str:
        for option in packet[scapy.DHCP].options:
            if option[0] == "vendor_class_id":
                return DHCPUtilities.convert_binary_to_string(option[1])
        return 'unknown'

    @staticmethod
    def extract_client_FQDN(packet: DHCP) -> str:
        for option in packet[scapy.DHCP].options:
            if option[0] == "client_FQDN":
                return DHCPUtilities.convert_binary_to_string(option[1])
        return 'unknown'

    @staticmethod
    def extract_client_param_req_list_from_dhcp_packet(packet: DHCP) -> str:
        """Extracts the 'param_req_list' from the DHCP packet."""
        for option in packet[scapy.DHCP].options:
            if option[0] == "param_req_list":
                return option[1]
        return []

    @staticmethod
    def is_packet_ethernet(packet: scapy.Packet) -> bool:
        """Check if the packet is an Ethernet packet."""
        return bool(packet.haslayer(Ether))

    @staticmethod
    def is_packet_ip(packet: Ether) -> bool:
        """Check if the packet is a DHCP packet."""
        return bool(packet.haslayer(IP))

    @staticmethod
    def is_packet_ipv6(packet: Ether) -> bool:
        """Check if the packet is an IPv6 packet."""
        return bool(packet.haslayer(IPv6))

    @staticmethod
    def is_packet_dhcp(packet: Ether) -> bool:
        """Check if the packet is a DHCP packet."""
        return bool(packet.haslayer(DHCP))

    @staticmethod
    def is_packet_bootp(packet: scapy.Packet) -> bool:
        """Check if the packet is a BOOTP packet."""
        return bool(packet.haslayer(BOOTP))

    @staticmethod
    def is_dhcp_discover(packet: scapy.Packet) -> bool:
        """Check if the given DHCP packet is a DHCP Discover message."""
        return DHCPUtilities.extract_dhcp_type_from_packet(packet) == 1

    @staticmethod
    def is_dhcp_offer(packet: scapy.Packet) -> bool:
        """Check if the given DHCP packet is a DHCP Offer message."""
        return DHCPUtilities.extract_dhcp_type_from_packet(packet) == 2

    @staticmethod
    def is_dhcp_request(packet: scapy.Packet) -> bool:
        """Check if the given DHCP packet is a DHCP Request message."""
        return DHCPUtilities.extract_dhcp_type_from_packet(packet) == 3

    @staticmethod
    def is_dhcp_decline(packet: scapy.Packet) -> bool:
        """Check if the given DHCP packet is a DHCP Decline message."""
        return DHCPUtilities.extract_dhcp_type_from_packet(packet) == 4

    @staticmethod
    def is_dhcp_ack(packet: scapy.Packet) -> bool:
        """Check if the given DHCP packet is a DHCP ACK message."""
        return DHCPUtilities.extract_dhcp_type_from_packet(packet) == 5

    @staticmethod
    def is_dhcp_nack(packet: scapy.Packet) -> bool:
        """Check if the given DHCP packet is a DHCP NACK message."""
        return DHCPUtilities.extract_dhcp_type_from_packet(packet) == 6

    @staticmethod
    def is_dhcp_release(packet: scapy.Packet) -> bool:
        """Check if the given DHCP packet is a DHCP Release message."""
        return DHCPUtilities.extract_dhcp_type_from_packet(packet) == 7

    @staticmethod
    def is_dhcp_inform(packet: scapy.Packet) -> bool:
        """Check if the given DHCP packet is a DHCP Discover message."""
        return DHCPUtilities.extract_dhcp_type_from_packet(packet) == 8

    @staticmethod
    def is_dhcp_force_renew(packet: scapy.Packet) -> bool:
        """Check if the given DHCP packet is a DHCP Force Renew message."""
        return DHCPUtilities.extract_dhcp_type_from_packet(packet) == 9

    @staticmethod
    def is_dhcp_lease_query(packet: scapy.Packet) -> bool:
        """Check if the given DHCP packet is a DHCP Lease query message."""
        return DHCPUtilities.extract_dhcp_type_from_packet(packet) == 10

    @staticmethod
    def is_dhcp_lease_unassigned(packet: scapy.Packet) -> bool:
        """Check if the given DHCP packet is a DHCP Lease unassigned message."""
        return DHCPUtilities.extract_dhcp_type_from_packet(packet) == 11

    @staticmethod
    def is_dhcp_lease_unknown(packet: scapy.Packet) -> bool:
        """Check if the given DHCP packet is a DHCP Lease Unknown message."""
        return DHCPUtilities.extract_dhcp_type_from_packet(packet) == 12

    @staticmethod
    def is_dhcp_lease_active(packet: scapy.Packet) -> bool:
        """Check if the given DHCP packet is a DHCP Lease Active message."""
        return DHCPUtilities.extract_dhcp_type_from_packet(packet) == 13

    @staticmethod
    def format_mac(raw_mac: bytes) -> str:
        """ Format a raw MAC address to human-readable format """
        return ":".join(f"{b:02x}" for b in raw_mac[:6])

    @staticmethod
    def convert_binary_to_string(data_to_convert: bytes) -> str:
        """ Format a raw MAC address to human-readable format """
        return data_to_convert.decode('utf-8', errors='ignore')

    @staticmethod
    def get_network_details(interface_name: str = None):
        """Retrieve network details (IP, netmask, broadcast, MAC) for a specified interface or all interfaces."""

        try:
            result = subprocess.check_output("ifconfig -a", shell=True).decode("utf-8")
            interfaces = result.split("\n\n")

            for interface in interfaces:
                if 'inet ' in interface:
                    iface_name = interface.split(":")[0].strip()
                    ip = re.search(
                        r"inet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
                        interface
                    )
                    netmask = re.search(
                        r"netmask (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
                        interface
                    )
                    broadcast = re.search(
                        r"broadcast (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
                        interface
                    )
                    mac = re.search(
                        r"ether ([A-Za-z0-9]{2}(:[A-Za-z0-9]{2}){5})",
                        interface
                    )

                    if ip and netmask and broadcast and mac:
                        if interface_name == iface_name:
                            return {
                                'ip': ip.group(1),
                                'netmask': netmask.group(1),
                                'broadcast': broadcast.group(1),
                                'mac': mac.group(1)
                            }

        except Exception as e:
            print(f"Error: {e}")

        return None

    @staticmethod
    def discover_client_via_arp(ip: str = '', iface: str = "eth0", source_ip: str = '', source_mac: str = '', timeout: float = 1.5) -> bool:
        """Send an ARP request to check if the IP is still busy."""

        try:
            packet = (
                Ether(dst="ff:ff:ff:ff:ff:ff", src=source_mac) /
                ARP(pdst=ip, psrc=source_ip, op=1)
            )
            answered, unanswered = scapy.srp(packet, timeout=timeout, verbose=False, iface=iface)
            if answered:
                source_mac_response = answered[0][1].hwsrc
                # source_ip_response = answered[0][1].psrc
                return True, source_mac_response

        except Exception as e:
            dhcp_logger.error(f"Unexpected error sending ARP request to {ip}: {e}")

        return False, None

    @staticmethod
    def discover_clients_via_arp(interface: str = "enp2s0", source_ip: str = "", source_mac: str = "", timeout: float = 2) -> dict:
        """Send a broadcast ARP request to discover all active clients on the network."""

        try:

            network = ipaddress.IPv4Network(f"{source_ip}/24", strict=False)
            subnet = str(network.network_address) + '/24'

            arp_request = ARP(pdst=subnet, psrc=source_ip, op=1)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=source_mac)
            packet = ether / arp_request

            request_start = time.time()
            answered, unanswered = scapy.srp(packet, timeout=timeout, verbose=False, iface=interface)
            request_duration = time.time() - request_start

            discovered_clients = {}
            for sent, received in answered:
                discovered_clients[received.hwsrc] = received.psrc

            dhcp_logger.debug(f"ARP discovery complete in {request_duration:.2f} sec, {len(discovered_clients)} clients found")
            return discovered_clients

        except Exception as e:
            dhcp_logger.error(f"Unexpected error during ARP discovery: {e}")
            return {}

    @staticmethod
    def print_all_clients_on_subnet(interface: str = 'enp2s0', source_ip: str = '192.168.20.100', source_mac: str = '18:c0:4d:46:f4:11') -> dict:
        """Discover all active clients on the given subnet via ARP."""
        dhcp_logger.debug(f"Starting subnet discovery for active clients ...")
        active_clients = DHCPUtilities.discover_clients_via_arp(interface=interface, source_ip=source_ip, source_mac=source_mac)
        dhcp_logger.debug(f"Discovery complete => {active_clients}")

    @staticmethod
    def _is_ip_in_subnet(ip_to_validate, subnet: str = "192.168.20.0/24"):
        """
        Checks if an IP address is in the specified subnet.

        :param ip_to_validate: IP address to check.
        :param subnet: The subnet to check against (e.g., '192.168.1.0/24').
        :return: True if the IP is within the subnet, False otherwise.
        """
        ip = ipaddress.ip_address(ip_to_validate)
        network = ipaddress.ip_network(subnet, strict=False)

        return ip in network


class DHCPStorage:

    def __init__(self):
        """Initialize the database connection and create tables on startup."""
        self.lock = Lock()
        self.db_connection = self._get_connection()
        self.db_cursor = self.db_connection.cursor()
        self._create_tables()

    def _get_connection(self):
        """Return a new SQLite connection."""
        return sqlite3.connect(':memory:', check_same_thread=False)

    def _create_tables(self) -> None:
        """Initialize the database tables only once."""
        try:
            with self.lock, self.db_connection:
                sql_statement_create_table_leases = '''
                    CREATE TABLE IF NOT EXISTS leases (
                        mac TEXT PRIMARY KEY,
                        ip TEXT NOT NULL,
                        hostname TEXT DEFAULT 'unknown',
                        timestamp INTEGER NOT NULL,
                        expiry_time INTEGER NOT NULL,
                        type TEXT DEFAULT 'dynamic'
                    )'''
                sql_statement_create_table_client_interactions = '''
                    CREATE TABLE IF NOT EXISTS client_interactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp INTEGER NOT NULL,
                    mac TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    hostname TEXT DEFAULT 'unknown',
                    interaction_type TEXT NOT NULL,
                    failed_attempts INTEGER DEFAULT 0,
                    last_failed_attempt INTEGER,
                    blacklisted BOOLEAN DEFAULT 0,
                    blacklist_reason TEXT,
                    additional_info TEXT
                    )'''

                self.db_cursor.execute(sql_statement_create_table_leases)
                self.db_cursor.execute(sql_statement_create_table_client_interactions)
                self.db_connection.commit()
                dhcp_logger.debug("SQLite database for leases initialized.")

        except Exception as e:
            dhcp_logger.error(f"Failed to initialize in-memory SQLite database: {e}")

    def add_lease(self, mac: str, ip: str, hostname: str, lease_time: int = 14*24*60*60, lease_type: str = 'dynamic') -> None:
        """Insert a new lease into the database."""

        try:
            with self.lock, self.db_connection:

                current_time = int(time.time())
                expiry_time = int(current_time + lease_time)

                sql_statement = '''
                    INSERT OR REPLACE INTO leases (mac, ip, hostname, timestamp, expiry_time, type)
                    VALUES (?, ?, ?, ?, ?, ?)
                    '''
                sql_statement_values = (mac, ip, hostname, current_time, expiry_time, lease_type)
                self.db_connection.execute(sql_statement, sql_statement_values)
                self.db_connection.commit()

                dhcp_logger.debug(f"Added MAC:{mac} IP:{ip}")

        except Exception as e:
            dhcp_logger.error(f"Failed to add lease: {str(e)}")

    def renew_lease(self, mac: str, lease_time: int = 7*24*60*60) -> None:
        """Renew an existing lease by updating its expiry time."""
        try:
            with self.lock, self.db_connection:
                current_time = int(time.time())
                expiry_time = int(current_time + lease_time)
                sql_statement = '''
                    UPDATE leases
                    SET
                        expiry_time = ?,
                        timestamp = ?
                    WHERE mac = ?
                '''
                sql_values = (expiry_time, current_time, mac)
                result = self.db_connection.execute(sql_statement, sql_values)
                self.db_connection.commit()

                if result.rowcount == 0:
                    dhcp_logger.warning(f"DB => Cannot renew lease, no existing lease found for MAC {mac}")
                else:
                    dhcp_logger.debug(f"DB => renewed:{mac} new expiry:{expiry_time})")

        except Exception as e:
            dhcp_logger.error(f"Failed to renew lease for {mac}: {e}")

    def get_lease_by_mac(self, mac: str) -> tuple | None:
        """Get the IP address assigned to a given MAC address."""
        try:
            with self.lock, self.db_connection:
                sql_statement = 'SELECT * FROM leases WHERE mac = ?'
                sql_values = (mac,)
                cursor = self.db_connection.execute(sql_statement, sql_values)
                result = cursor.fetchone()
                return result  # None if not found

        except Exception as e:
            dhcp_logger.error(f"Failed to get lease for {mac}: {e}")
            return None

    def get_mac_by_ip(self, ip: str) -> str:
        """Get the MAC address assigned to a given IP address."""
        try:
            with self.lock, self.db_connection:
                sql_statement = 'SELECT mac FROM leases WHERE ip = ?'
                sql_values = (ip,)
                cursor = self.db_connection.execute(sql_statement, sql_values)
                result = cursor.fetchone()
                return result[0] if result else None

        except Exception as e:
            dhcp_logger.error(f"Failed to get lease for {ip}: {e}")
            return None

    def get_all_leased_ips(self) -> set:
        """Get a list of currently leased IPs."""
        try:
            with self.db_connection:

                sql_statement = 'SELECT ip FROM leases'
                cursor = self.db_connection.execute(sql_statement)
                result = cursor.fetchall()
                leases_by_ip = {lease[0] for lease in result}
                return leases_by_ip

                # fetchall() returns a list of tuples. Each tuple contains the value(s) of the selected column(s).
                # Since we're only selecting 'ip', each row is a tuple with one element, e.g., [('192.168.1.10',), ('192.168.1.11',)]
                # lease[0] is used to extract the single value from each tuple (the IP in this case).

        except Exception as e:
            dhcp_logger.error(f"Failed to get active leases: {e}")
            return set()

    def get_all_leases(self) -> list:
        """Get all leases"""
        try:
            with self.lock, self.db_connection:
                sql_statment = 'SELECT * FROM leases'
                cursor = self.db_connection.execute(sql_statment)
                result = cursor.fetchall()
                return result
        except Exception as e:
            dhcp_logger.error(f"Failed to get active leases: {e}")
            return []

    def get_active_lease_count(self) -> int:
        """Return the number of active leases."""
        try:
            with self.lock, self.db_connection:
                sql_statement = 'SELECT COUNT(*) FROM leases'
                cursor = self.db_connection.execute(sql_statement)
                count = cursor.fetchone()[0]
                return count
        except Exception as e:
            dhcp_logger.error(f"Failed to get active lease count: {e}")
            return 0

    def is_ip_pool_full(self) -> list:
        """Check if the lease pool is exhausted."""
        try:
            with self.lock, self.db_connection:
                max_pool_size = 253
                sql_statement = 'SELECT COUNT(*) FROM leases'
                cursor = self.db_connection.execute(sql_statement)
                leases = cursor.fetchone()[0]
                if leases > max_pool_size:
                    return True
                return False

        except Exception as e:
            dhcp_logger.error(f"Error checking lease pool count: {e}")
            return False

    def remove_lease_by_mac(self, mac: str) -> None:
        """Remove a lease from the database."""
        try:
            with self.lock, self.db_connection:
                sql_statement = 'DELETE FROM leases WHERE mac = ?'
                sql_values = (mac,)
                result = self.db_connection.execute(sql_statement, sql_values)
                self.db_connection.commit()

                if result.rowcount == 0:
                    dhcp_logger.debug(f"DB -> Lease not found for MAC:{mac}, no deletion occured")
                else:
                    dhcp_logger.debug(f"DB -> Removed {result.rowcount} lease(s) for MAC:{mac}")
        except Exception as e:
            dhcp_logger.error(f"DB -> failed to remove lease: {e}")

    def remove_leases_by_mac(self, macs: set) -> None:
        """Remove multiple leases from the database based on a set of MAC addresses."""
        try:

            if not macs:
                return

            with self.lock, self.db_connection:

                sql_value = tuple(macs)
                sql_statement_list_of_mac_placeholdes = ",".join(["?"] * len(sql_value))

                sql_statement = f"""
                DELETE
                FROM leases
                WHERE mac IN ({sql_statement_list_of_mac_placeholdes})"""

                result = self.db_connection.execute(sql_statement, sql_value)
                self.db_connection.commit()

                if result.rowcount == 0:
                    dhcp_logger.debug(f"DB -> No matching leases found for removal. MACs: {str(macs)}")
                else:
                    dhcp_logger.debug(f"DB -> Deleted {result.rowcount} lease(s). Removed MACs: {set(macs)}")
        except Exception as e:
            dhcp_logger.error(f"DB -> failed to remove leases: {e}")

    def remove_expired_leases(self) -> None:
        """Remove expired leases."""
        try:
            dhcp_logger.debug(f"Checking for expired leases ...")
            with self.lock, self.db_connection:
                current_time = int(time.time())

                sql_statement = "DELETE FROM leases WHERE expiry_time < ?"
                sql_value = (current_time,)

                self.db_connection.execute(sql_statement, sql_value)
                self.db_connection.commit()

                deleted_leases = self.db_connection.total_changes

                dhcp_logger.debug(f"Found/deleted {deleted_leases} expired leases")
        except Exception as e:
            dhcp_logger.error(f"Error during lease cleanup: {e}")

    def remove_inactive_leases(self) -> list:
        """
        Delete non-active leases from the database.    
        This function does not use explicit locks as the underlying methods (get_all_leases and remove_leases_by_mac) handle locking internally.
        It removes leases where the associated client is not responding to ARP requests.
        """

        try:
            config = Config.get_config()
            interface = config.get("interface")
            source_ip = config.get("server_ip")
            source_mac = config.get("server_mac")

            active_leases = self.get_all_leases()
            active_clients = DHCPUtilities.discover_clients_via_arp(interface=interface, source_ip=source_ip, source_mac=source_mac)

            macs_to_be_removed = set()

            for lease_mac, lease_ip, *reset_items in active_leases:
                if lease_mac not in active_clients:
                    macs_to_be_removed.add(lease_mac)

            if macs_to_be_removed:
                self.remove_leases_by_mac(macs_to_be_removed)

        except Exception as e:
            dhcp_logger.error(f"Error during dead lease removal: {e}")


class DHCPServer:
    def __init__(self) -> None:
        dhcp_logger.info("Initialized")
        self.leased_ips = {}
        self.config = {}
        self.lease_db = DHCPStorage()
        self.denied_ips = {}
        self.lock = Lock()
        self.shutdown_flag = False
        self._inbound_packet_deduplication_queue = deque(maxlen=INBOUND_REQUESTS_DEDUPLICATE_QUEUE_SIZE)
        self._initialize_config()

    def _initialize_config(self) -> None:
        """Load DHCP configuration from the config file."""
        try:
            config = Config.get_config()
            hosting_interface = DHCPUtilities.get_network_details(interface_name=config["interface"])

            self._interface = config.get("interface")
            self._own_ip = config.get("server_ip")
            self._own_mac = config.get("server_mac")
            self._own_subnet = config.get("server_subnet_mask")
            self._server_ip_range_start = config.get("server_ip_range_start")
            self._server_ip_range_end = config.get("server_ip_range_end")
            self._broadcast = config.get("server_broadcast")
            self._router_ip = config.get("router_ip")
            self._dns_server = config.get("dns_server")
            self._ntr_server = config.get("ntp_server")
            self._lease_time = config.get("lease_time")
            self._rebinding_time = int(self._lease_time * 0.875)
            self._renewal_time = int(self._lease_time * 0.5)
            self._mtu = int(config.get("mtu"))
            self._dns_ports = config.get("dns_ports")

            self.config = {
                "interface": config.get("interface", "eth0"),
                "server_ip": hosting_interface.get("server_ip", "192.168.20.100"),
                "server_subnet_mask": hosting_interface.get("server_subnet_mask", "255.255.255.0"),
                "server_broadcast": hosting_interface.get("server_broadcast", "192.168.20.255"),
                "server_mac": hosting_interface.get("server_mac", "00:00:00:00:00:00"),
                "server_ip_range_start": config.get("server_ip_range_start", "192.168.20.101"),
                "server_ip_range_end": config.get("server_ip_range_end", "192.168.20.254"),
                "router_ip": config.get("router_ip", "192.168.20.1"),
                "dns_server": config.get("dns_server", "9.9.9.9"),
                "ntp_server": config.get("ntp_server", "9.9.9.9"),
                "lease_time": int(config.get("lease_time", 86400)),
                "mtu": config.get("mtu", 1500),
                "rebinding_time": int(config.get("lease_time", 86400) * 0.875),
                "renewal_time": int(config.get("lease_time", 86400) * 0.5),
            }
            dhcp_logger.debug(
                f"Serving from {self._own_ip}:{self._dns_ports["server"]} {self._own_subnet} {self._own_mac}")
        except Exception as e:
            dhcp_logger.error(f"Failed to load DHCP config: {e}")

    def _get_candidate_ip(self, declined_ips: set = set()) -> str:
        """Find the next available IP, avoiding specified exclusions"""

        with self.lock:

            start_ip = ipaddress.IPv4Address(self._server_ip_range_start)
            end_ip = ipaddress.IPv4Address(self._server_ip_range_end)
            leased_ips = self.lease_db.get_all_leased_ips()

            for _ip in range(int(start_ip), int(end_ip) + 1):

                _proposed_ip = str(ipaddress.IPv4Address(_ip))
                if _proposed_ip in leased_ips or _proposed_ip in declined_ips:
                    continue

                is_lease_active_status, is_lease_active_mac = DHCPUtilities.discover_client_via_arp(ip=_proposed_ip,
                                                                                                    iface=self._interface,
                                                                                                    source_ip=self._own_ip,
                                                                                                    source_mac=self._own_mac
                                                                                                    )

                if is_lease_active_status:
                    continue

                dhcp_logger.debug(f"Proposing IP:{_proposed_ip}, {'Leased IPs: ' + str(leased_ips) if leased_ips else ''}")
                return _proposed_ip

        dhcp_logger.warning("No available IPs in the range.")
        return None

    def _helper_init_denied_ips_of_client_mac_if_required(self, source_mac: str):
        if source_mac not in self.denied_ips:
            self.denied_ips[source_mac] = set()

    def _helper_get_dhcp_bootp_options(self, client_mac: str, transaction_id: int, your_ip: str) -> dict:
        return {
            "op": 2,
            "xid": transaction_id,
            "chaddr": bytes.fromhex(client_mac.replace(':', '')) + b"\x00" * 10,  # Ensure 16 bytes
            "yiaddr": your_ip if your_ip else "0.0.0.0",
            "siaddr": self._own_ip,
            "flags": 0x8000
        }

    def _helper_get_ntp_server_ip(self, ntp_server_url: str) -> str:
        try:
            return socket.gethostbyname(ntp_server_url)
        except socket.gaierror:
            dhcp_logger.warning(f"Failed to resolve NTP server: {ntp_server_url}")
            return self._router_ip

    def _helper_get_dhcp_options(self, dhcp_type: str, message: str) -> list:

        ntp_server_ip = self._helper_get_ntp_server_ip(self._ntr_server)

        if dhcp_type == 'DHCPNAK':
            return [
                ("message-type", 6),
                ("server_id", self._own_ip),
                ("error_message", message),
                "end"
            ]
        elif dhcp_type == 'DHCPACK':
            return [
                ("message-type", 5),
                ("subnet_mask", self._own_subnet),
                ("router", self._router_ip),
                ("name_server", self._dns_server),
                ("NTP_server", ntp_server_ip),
                ("lease_time", self._lease_time),
                ("server_id", self._own_ip),
                ("renewal_time", self._renewal_time),
                ("rebinding_time", self._rebinding_time),
                ("interface-mtu",  self._mtu),
                ("error_message", message),
                "end"
            ]
        elif dhcp_type == 'DHCPOFFER':
            return [
                ("message-type", 2),
                ("subnet_mask", self._own_subnet),
                ("router", self._router_ip),
                ("name_server", self._dns_server),
                ("NTP_server", ntp_server_ip),
                ("lease_time", self._lease_time),
                ("server_id", self._own_ip),
                ("renewal_time", self._renewal_time),
                ("rebinding_time", self._rebinding_time),
                ("interface-mtu",  self._mtu),
                ("max_dhcp_size", self._mtu),
                ("param_req_list", [12, 43, 60, 61, 81]),
                ("error_message", message),
                "end"
            ]
        raise ValueError("DHCP Option couldn't be calculated")

    def _build_dhcp_response(self, dhcp_type: str, your_ip: str = "0.0.0.0", message: str = "not provided", request_packet: Ether = None) -> DHCP:
        """Builds a DHCP packet for the given client."""

        bootp_options = {
            "op": 2,
            "xid": request_packet[BOOTP].xid,
            "chaddr": request_packet[BOOTP].chaddr[:6] + b"\x00" * 10,  # 16 bytes last 10 are padded with 00
            "yiaddr": your_ip if your_ip else "0.0.0.0",
            "siaddr": self._own_ip,
            "flags": 0x8000
        }
        dhcp_options: list[tuple] = self._helper_get_dhcp_options(dhcp_type=dhcp_type, message=message)

        return (
            Ether(src=self._own_mac, dst='ff:ff:ff:ff:ff:ff') /
            IP(src=request_packet[IP].dst, dst="255.255.255.255") /
            UDP(sport=request_packet[UDP].dport, dport=request_packet[UDP].sport) /
            BOOTP(**bootp_options) /
            DHCP(options=dhcp_options)
        )

    def _send_dhcp_packet(self, packet: Ether, dhcp_type: str = ''):
        """Send a DHCP packet on the configured interface."""
        dhcp_logger.debug(
            f"[{dhcp_type}] sent to XID {packet[BOOTP].xid} CHADDR {":".join([f"{_each_char:02x}" for _each_char in packet[BOOTP].chaddr[:6]])}")
        scapy.sendp(packet, iface=self.config.get('interface'), verbose=False)

    def _is_received_packet_valid(self, packet: scapy.Packet) -> bool:

        if not packet.haslayer(IP):
            return False

        if packet.haslayer(IPv6):
            return False

        if not packet.haslayer(DHCP):
            return False

        key = (packet[Ether].src, packet[BOOTP].xid)
        if key in self._inbound_packet_deduplication_queue:
            return False

        self._inbound_packet_deduplication_queue.appendleft(key)

        return True

    def _log_dhcp_packet_details(self, packet: Ether) -> None:
        """Logs details of a DHCP packet."""

        source_mac = DHCPUtilities.extract_source_mac_from_ethernet_packet(packet)
        source_ip = DHCPUtilities.extract_source_ip_from_ethernet_packet(packet)

        dhcp_type = DHCPUtilities.extract_dhcp_type_from_packet(packet)
        transaction_id = DHCPUtilities.extract_transaction_id_from_dhcp_packet(packet)
        client_ip = DHCPUtilities.extract_client_ip_address_from_dhcp_packet(packet)
        client_hostname = DHCPUtilities.extract_hostname_from_dhcp_packet(packet)
        client_secs = DHCPUtilities.extract_secs_from_dhcp_packet(packet)
        your_ip = DHCPUtilities.extract_your_ip_address_from_dhcp_packet(packet)
        vendor_cid = DHCPUtilities.extract_vendor_cid_from_dhcp_packet(packet)
        client_FQDN = DHCPUtilities.extract_client_FQDN(packet)
        param_req_list = DHCPUtilities.extract_client_param_req_list_from_dhcp_packet(packet)

        Stats.increment("received_total")
        if DHCPUtilities.is_dhcp_discover(packet=packet):
            Stats.increment("received_discover")

        elif DHCPUtilities.is_dhcp_request(packet):
            Stats.increment("received_request")

        elif DHCPUtilities.is_dhcp_decline(packet):
            Stats.increment("received_decline")

        elif DHCPUtilities.is_dhcp_release(packet):
            Stats.increment("received_release")

        elif DHCPUtilities.is_dhcp_inform(packet):
            Stats.increment("received_inform")

        dhcp_logger.debug(
            f"Received DHCPTYPE:{dhcp_type} XID:{transaction_id} MAC:{source_mac} SIP:{source_ip} CIP:{client_ip} HOSTNAME:{client_hostname}")
        return

    def _handle_dhcp_discover(self, packet: Ether) -> None:
        """Handles DHCPDISCOVER messages (RFC 2131, Section 4.1) sent by clients to discover DHCP servers."""

        proposed_ip = self._get_candidate_ip(self.denied_ips[packet[Ether].src])
        dhcp_logger.debug(f"[DHCPDISCOVER] XID:{packet[BOOTP].xid} MAC:{packet[Ether].src} IP_proposed:{proposed_ip}")

        if not proposed_ip:
            dhcp_logger.warning(f"No available IPs for DHCPDISCOVER from {packet[Ether].src}. Ignoring request.")
            return

        with self.lock:

            dhcp_type = "DHCPOFFER"
            message = "Offering IP Address"
            server_response = self._build_dhcp_response(
                dhcp_type=dhcp_type,
                your_ip=proposed_ip,
                message=message,
                request_packet=packet
            )

            self._send_dhcp_packet(packet=server_response, dhcp_type=dhcp_type)

        return

    def _handle_dhcp_request(self, packet: DHCP) -> None:
        """Handles DHCP Request messages (RFC 2131, Section 4.3)"""

        source_mac = packet[Ether].src
        transaction_id = packet[BOOTP].xid
        client_hostname = DHCPUtilities.extract_hostname_from_dhcp_packet(packet)
        requested_ip = DHCPUtilities.extract_requested_addr_from_dhcp_packet(packet)
        client_ip = DHCPUtilities.extract_client_ip_address_from_dhcp_packet(packet)  # Extract 'ciaddr'

        dhcp_logger.info(f"[DHCPREQUEST] XID:{transaction_id} MAC:{source_mac} IP_requested:{requested_ip} CIP:{client_ip}")

        with self.lock:
            dhcp_type = None
            message = None
            your_ip = None

            existing_lease = self.lease_db.get_lease_by_mac(source_mac)
            lease_holder_mac = self.lease_db.get_mac_by_ip(requested_ip) if requested_ip else None

            # Ensure there's a valid IP to process (either 'requested_ip' or 'ciaddr')
            if requested_ip or client_ip:
                ip_to_validate = requested_ip if requested_ip else client_ip
                is_ip_active, active_mac = DHCPUtilities.discover_client_via_arp(
                    ip=ip_to_validate,
                    iface=self.config['interface'],
                    source_ip=self.config['server_ip'],
                    source_mac=self.config['server_mac']
                )

                # Case 1: Requested IP is already assigned to another MAC
                if is_ip_active and active_mac not in {source_mac, lease_holder_mac}:
                    dhcp_logger.debug(f"NAK (IP in use) MAC_src:{source_mac}, MAC_act:{active_mac}, MAC_leased:{lease_holder_mac}")
                    # self.denied_ips[source_mac].add(ip_to_validate)
                    dhcp_type, message, your_ip = "DHCPNAK", "Requested IP already in use", "0.0.0.0"

                # Case 2: Client in INIT-REBOOT requesting a previously assigned IP
                elif not is_ip_active and existing_lease and existing_lease[1] == ip_to_validate:
                    dhcp_logger.debug(f"ACK (INIT-REBOOT) Reassigning existing lease IP:{ip_to_validate} to MAC:{source_mac}")
                    self.lease_db.add_lease(
                        mac=source_mac,
                        ip=ip_to_validate,
                        hostname=client_hostname,
                        lease_time=self.config['lease_time'])
                    dhcp_type, message, your_ip = "DHCPACK", "Existing lease reassigned", ip_to_validate

                # Case 3: Client in RENEWING/REBINDING requesting the same IP
                elif is_ip_active and active_mac == source_mac and lease_holder_mac == source_mac:
                    dhcp_logger.debug(f"ACK (Lease Renewal) IP:{ip_to_validate} MAC:{source_mac}")
                    self.lease_db.add_lease(
                        mac=source_mac,
                        ip=ip_to_validate,
                        hostname=client_hostname,
                        lease_time=self.config['lease_time'])
                    dhcp_type, message, your_ip = "DHCPACK", "Lease renewed", ip_to_validate

                # Case 4: No existing lease, and IP is free
                elif not is_ip_active and not lease_holder_mac:
                    dhcp_logger.debug(f"ACK (New lease) Assigning IP:{ip_to_validate} to MAC:{source_mac}")
                    self.lease_db.add_lease(
                        mac=source_mac,
                        ip=ip_to_validate,
                        hostname=client_hostname,
                        lease_time=self.config['lease_time'])
                    dhcp_type, message, your_ip = "DHCPACK", "New lease assigned", ip_to_validate

                # Case 5: Client Requests an IP Outside the Subnet
                elif not DHCPUtilities._is_ip_in_subnet(ip_to_validate):
                    dhcp_logger.debug(f"NAK (IP outside subnet) Requested IP:{ip_to_validate} is not in allowed range")
                    # self.denied_ips[source_mac].add(ip_to_validate)
                    dhcp_type, message, your_ip = "DHCPNAK", "Requested IP is outside the subnet", "0.0.0.0"

                # Case 6: Client Requests a Different IP Than Its Current Lease (`ciaddr`)
                elif existing_lease and ip_to_validate != existing_lease[1]:
                    dhcp_logger.debug(
                        f"DHCPNAK discovery required Existing:{existing_lease[1]} -> New:{ip_to_validate} for MAC:{source_mac}")
                    dhcp_type, message, your_ip = "DHCPNAK", "DHCPDISCOVER first", "0.0.0.0"

                else:
                    # Default rejection case
                    dhcp_logger.debug(f"NAK (Default) IP:{ip_to_validate} MAC_src:{source_mac} MAC_leased:{lease_holder_mac}")
                    # self.denied_ips[source_mac].add(ip_to_validate)
                    dhcp_type, message, your_ip = "DHCPNAK", f"Could not fulfill DHCPREQUEST for IP {ip_to_validate}", "0.0.0.0"

            else:
                # Case 7: No IP requested and 'ciaddr' missing
                dhcp_logger.debug(f"NAK (no IP requested) MAC_src:{source_mac}")
                dhcp_type, message, your_ip = "DHCPNAK", "No IP requested", "0.0.0.0"

            server_response = self._build_dhcp_response(
                dhcp_type=dhcp_type,
                your_ip=your_ip,
                message=message,
                request_packet=packet
            )

            self._send_dhcp_packet(packet=server_response, dhcp_type=dhcp_type)

    def _handle_dhcp_decline(self, packet: DHCP) -> None:
        """Handles DHCP Decline messages (RFC 2131, Section 4.3.2)"""

        source_mac = DHCPUtilities.extract_source_mac_from_ethernet_packet(packet)
        transaction_id = DHCPUtilities.extract_transaction_id_from_dhcp_packet(packet)
        declined_ip = DHCPUtilities.extract_requested_addr_from_dhcp_packet(packet)

        dhcp_logger.info(f"DHCPDECLINE XID:{transaction_id} MAC:{source_mac} Declined IP:{declined_ip}")

        with self.lock:

            existing_lease = self.lease_db.get_lease_by_mac(source_mac)
            self.denied_ips[source_mac].add(declined_ip)

            # Case 1: The client has a lease and it is for the declined IP
            if existing_lease and existing_lease[1] == declined_ip:
                dhcp_logger.debug(f"Client MAC:{source_mac} declined IP:{declined_ip}, removing lease from database")
                self.lease_db.remove_lease_by_mac(source_mac)
            else:
                # Case 2: The client declined the IP and doesnt have active lease
                dhcp_logger.debug(f"Client {source_mac} declined IP {declined_ip}, but no lease found")

            dhcp_type = "DHCPNAK"
            message = f"IP {declined_ip} was declined by client"

            server_response = self._build_dhcp_response(
                dhcp_type=dhcp_type,
                your_ip="0.0.0.0",
                message=message,
                request_packet=packet
            )
            self._send_dhcp_packet(packet=server_response, dhcp_type=dhcp_type)

    def _handle_dhcp_release(self, packet: DHCP) -> None:
        """DHCP Release (Section 4.4 of RFC 2131) sent by the client to release an IP address that it no longer needs"""

        source_mac = DHCPUtilities.extract_source_mac_from_ethernet_packet(packet)
        transaction_id = DHCPUtilities.extract_transaction_id_from_dhcp_packet(packet)
        source_ip = DHCPUtilities.extract_source_ip_from_ethernet_packet(packet)

        dhcp_logger.info(f"DHCPRELEASE XID:{transaction_id} MAC:{source_mac} IP_src:{source_ip}")

        with self.lock:

            self.denied_ips[source_mac] = set()
            self.lease_db.remove_lease_by_mac(source_mac)

            dhcp_type = "DHCPACK"
            message = f"IP: {source_ip} released by MAC_src: {source_mac}"

            server_response = self._build_dhcp_response(
                dhcp_type=dhcp_type,
                your_ip="0.0.0.0",
                message=message,
                request_packet=packet
            )
            self._send_dhcp_packet(packet=server_response, dhcp_type=dhcp_type)

    def _handle_dhcp_inform(self,  packet: DHCP) -> None:
        """DHCPINFORM (Section 3.3.2 of RFC 2131)"""

        source_mac = DHCPUtilities.extract_source_mac_from_ethernet_packet(packet)
        source_ip = DHCPUtilities.extract_source_ip_from_ethernet_packet(packet)
        transaction_id = DHCPUtilities.extract_transaction_id_from_dhcp_packet(packet)
        param_req_list = DHCPUtilities.extract_client_param_req_list_from_dhcp_packet(packet)

        dhcp_logger.info(f"DHCPINFORM MAC:{source_mac} XID:{transaction_id} Requested Parameters:{param_req_list}")

        with self.lock:

            dhcp_type = "DHCPACK"
            message = f"Information provided"

            server_response = self._build_dhcp_response(
                dhcp_type=dhcp_type,
                transaction_id=transaction_id,
                your_ip=source_ip,
                message=message,
                request_packet=packet
            )
            self._send_dhcp_packet(packet=server_response, dhcp_type=dhcp_type)

    def main_dhcp_handler(self, packet: Ether) -> None:
        """Provides centralized point for processing DHCP packets"""

        if not self._is_received_packet_valid(packet=packet):
            return

        if packet[Ether].src == self._own_mac:
            return

        self._log_dhcp_packet_details(packet=packet)
        self._helper_init_denied_ips_of_client_mac_if_required(source_mac=packet[Ether].src)

        if DHCPUtilities.is_dhcp_discover(packet=packet):
            self._handle_dhcp_discover(packet)

        elif DHCPUtilities.is_dhcp_request(packet):
            self._handle_dhcp_request(packet)

        elif DHCPUtilities.is_dhcp_decline(packet):
            self._handle_dhcp_decline(packet)

        elif DHCPUtilities.is_dhcp_release(packet):
            self._handle_dhcp_release(packet)

        elif DHCPUtilities.is_dhcp_inform(packet):
            self._handle_dhcp_inform(packet)

        else:
            dhcp_logger.warning(f'This DHCP packet type is not handled yet')

        RabbitMqProducer.send_message({'timestamp': time.time(), 'type': 'statistics', 'payload': Stats.get_all_statistics()})
        RabbitMqProducer.send_message({'timestamp': time.time(), 'type': 'dhcp-leases', 'payload': self.lease_db.get_all_leases()})

    def listen_dhcp(self) -> None:
        """ Start sniffing for DHCP packets on the interface """
        scapy.sniff(
            iface='enp2s0',
            filter="ip and udp and (port 67 or 68)",
            prn=self.main_dhcp_handler,
            count=0,
            timeout=None,
            store=False,
            session=None
        )

    def start(self):
        """ Start all necessary threads """

        listen_thread = Thread(
            target=self.listen_dhcp,
            name="dhcp-service-listener",
            daemon=True)
        listen_thread.start()

        schedule_discover_all_leases = Scheduler(interval=1*30*60, function=DHCPUtilities.print_all_clients_on_subnet)
        schedule_discover_all_leases.start_schedule()

        schedule_cleanup_dead_leases = Scheduler(interval=1*60*60, function=self.lease_db.remove_inactive_leases)
        schedule_cleanup_dead_leases.start_schedule()

        schedule_cleanup_expired_leases = Scheduler(interval=2*60*60, function=self.lease_db.remove_expired_leases)
        schedule_cleanup_expired_leases.start_schedule()

        dhcp_logger.info("Started")


if __name__ == "__main__":

    # server = DHCPServer()
    # server.start()

    # keep_running_event = threading.Event()
    # keep_running_event.wait()  # This keeps the main thread alive indefinitely

    while True:
        time.sleep(1)


# | Step | Message Type   | Trigger                              | Server Action                              | Client Action                              | State     |
# |------|----------------|--------------------------------------|--------------------------------------------|--------------------------------------------|-----------|
# |  1   | DHCPDISCOVER   | Client starts looking for an IP      | Records request, selects an available IP   | Broadcasts discovery to find a DHCP server | **INIT**  |
# |  2   | DHCPOFFER      | Server offers an IP                  | Assigns an IP from the pool, sends offer   | Waits for offers from servers              | **OFFERED** |
# |  3   | DHCPREQUEST    | Client accepts an offer              | Receives request, verifies availability    | Requests the selected IP                   | **REQUESTED** |
# |  4   | DHCPACK        | Server confirms lease                | Saves lease to database, sends ACK         | Configures IP and starts using it          | **BOUND** |
# |  5   | DHCPNAK        | IP conflict or lease expired         | Rejects request, client must restart       | Receives NAK, restarts process             | **REJECTED** |
# |  6   | DHCPDECLINE    | Client detects conflict              | Marks IP as bad, removes it from pool      | Rejects IP, restarts with DISCOVER         | **DECLINED** |
# |  7   | DHCPRELEASE    | Client leaves network                | Frees up the IP in the pool                | Sends RELEASE, stops using IP              | **RELEASED** |
# |  8   | DHCPINFORM     | Client wants config info             | Provides extra options (e.g., DNS)         | Requests additional DHCP settings          | **INFORMED** |


# DHCPOptions = {
#     0: "pad",
#     1: IPField("subnet_mask", "0.0.0.0"),
#     2: IntField("time_zone", 500),
#     3: IPField("router", "0.0.0.0"),
#     4: IPField("time_server", "0.0.0.0"),
#     5: IPField("IEN_name_server", "0.0.0.0"),
#     6: IPField("name_server", "0.0.0.0"),
#     7: IPField("log_server", "0.0.0.0"),
#     8: IPField("cookie_server", "0.0.0.0"),
#     9: IPField("lpr_server", "0.0.0.0"),
#     10: IPField("impress-servers", "0.0.0.0"),
#     11: IPField("resource-location-servers", "0.0.0.0"),
#     12: "hostname",
#     13: ShortField("boot-size", 1000),
#     14: "dump_path",
#     15: "domain",
#     16: IPField("swap-server", "0.0.0.0"),
#     17: "root_disk_path",
#     18: "extensions-path",
#     19: ByteField("ip-forwarding", 0),
#     20: ByteField("non-local-source-routing", 0),
#     21: IPField("policy-filter", "0.0.0.0"),
#     22: ShortField("max_dgram_reass_size", 300),
#     23: ByteField("default_ttl", 50),
#     24: IntField("pmtu_timeout", 1000),
#     25: ShortField("path-mtu-plateau-table", 1000),
#     26: ShortField("interface-mtu", 50),
#     27: ByteField("all-subnets-local", 0),
#     28: IPField("broadcast_address", "0.0.0.0"),
#     29: ByteField("perform-mask-discovery", 0),
#     30: ByteField("mask-supplier", 0),
#     31: ByteField("router-discovery", 0),
#     32: IPField("router-solicitation-address", "0.0.0.0"),
#     33: IPField("static-routes", "0.0.0.0"),
#     34: ByteField("trailer-encapsulation", 0),
#     35: IntField("arp_cache_timeout", 1000),
#     36: ByteField("ieee802-3-encapsulation", 0),
#     37: ByteField("tcp_ttl", 100),
#     38: IntField("tcp_keepalive_interval", 1000),
#     39: ByteField("tcp_keepalive_garbage", 0),
#     40: StrField("NIS_domain", "www.example.com"),
#     41: IPField("NIS_server", "0.0.0.0"),
#     42: IPField("NTP_server", "0.0.0.0"),
#     43: "vendor_specific",
#     44: IPField("NetBIOS_server", "0.0.0.0"),
#     45: IPField("NetBIOS_dist_server", "0.0.0.0"),
#     46: ByteField("NetBIOS_node_type", 100),
#     47: "netbios-scope",
#     48: IPField("font-servers", "0.0.0.0"),
#     49: IPField("x-display-manager", "0.0.0.0"),
#     50: IPField("requested_addr", "0.0.0.0"),
#     51: IntField("lease_time", 43200),
#     52: ByteField("dhcp-option-overload", 100),
#     53: ByteEnumField("message-type", 1, DHCPTypes),
#     54: IPField("server_id", "0.0.0.0"),
#     55: _DHCPParamReqFieldListField(
#         "param_req_list", [],
#         ByteField("opcode", 0)),
#     56: "error_message",
#     57: ShortField("max_dhcp_size", 1500),
#     58: IntField("renewal_time", 21600),
#     59: IntField("rebinding_time", 37800),
#     60: StrField("vendor_class_id", "id"),
#     61: StrField("client_id", ""),
#     62: "nwip-domain-name",
#     64: "NISplus_domain",
#     65: IPField("NISplus_server", "0.0.0.0"),
#     66: "tftp_server_name",
#     67: StrField("boot-file-name", ""),
#     68: IPField("mobile-ip-home-agent", "0.0.0.0"),
#     69: IPField("SMTP_server", "0.0.0.0"),
#     70: IPField("POP3_server", "0.0.0.0"),
#     71: IPField("NNTP_server", "0.0.0.0"),
#     72: IPField("WWW_server", "0.0.0.0"),
#     73: IPField("Finger_server", "0.0.0.0"),
#     74: IPField("IRC_server", "0.0.0.0"),
#     75: IPField("StreetTalk_server", "0.0.0.0"),
#     76: IPField("StreetTalk_Dir_Assistance", "0.0.0.0"),
#     77: "user_class",
#     78: "slp_service_agent",
#     79: "slp_service_scope",
#     81: "client_FQDN",
#     82: "relay_agent_information",
#     85: IPField("nds-server", "0.0.0.0"),
#     86: StrField("nds-tree-name", ""),
#     87: StrField("nds-context", ""),
#     88: "bcms-controller-namesi",
#     89: IPField("bcms-controller-address", "0.0.0.0"),
#     91: IntField("client-last-transaction-time", 1000),
#     92: IPField("associated-ip", "0.0.0.0"),
#     93: "pxe_client_architecture",
#     94: "pxe_client_network_interface",
#     97: "pxe_client_machine_identifier",
#     98: StrField("uap-servers", ""),
#     100: StrField("pcode", ""),
#     101: StrField("tcode", ""),
#     112: IPField("netinfo-server-address", "0.0.0.0"),
#     113: StrField("netinfo-server-tag", ""),
#     114: StrField("default-url", ""),
#     116: ByteField("auto-config", 0),
#     117: ShortField("name-service-search", 0,),
#     118: IPField("subnet-selection", "0.0.0.0"),
#     121: ClasslessFieldListField(
#         "classless_static_routes",
#         [],
#         ClasslessStaticRoutesField("route", 0)),
#     124: "vendor_class",
#     125: "vendor_specific_information",
#     128: IPField("tftp_server_ip_address", "0.0.0.0"),
#     136: IPField("pana-agent", "0.0.0.0"),
#     137: "v4-lost",
#     138: IPField("capwap-ac-v4", "0.0.0.0"),
#     141: "sip_ua_service_domains",
#     146: "rdnss-selection",
#     150: IPField("tftp_server_address", "0.0.0.0"),
#     159: "v4-portparams",
#     160: StrField("v4-captive-portal", ""),
#     161: StrField("mud-url", ""),
#     208: "pxelinux_magic",
#     209: "pxelinux_configuration_file",
#     210: "pxelinux_path_prefix",
#     211: "pxelinux_reboot_time",
#     212: "option-6rd",
#     213: "v4-access-domain",
#     255: "end"
# }
