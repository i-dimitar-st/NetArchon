
import time
import sqlite3
import socket
import json
import ipaddress
import sys
import queue
import threading
from collections import deque
import scapy.all as scapy
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, UDP
from threading import RLock
from pathlib import Path
from services import MainLogger

# fmt: off
sys.path.append('/projects/gitlab/netarchon/venv/lib/python3.12/site-packages')
import pika # type: ignore
# fmt: on

ROOT_PATH = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT_PATH / 'config'
CONFIG_FULLPATH = CONFIG_PATH / 'dhcp_config.json'

DB_PATH = ROOT_PATH / 'db'
DB_FILENAME = 'dhcp.sqlite3'
DB_FULLPATH = DB_PATH / DB_FILENAME

DB_CONN_TIMEOUT = 10
DB_CONN_CHECK_SAME_THREAD = False
DB_CONN_ISOLATION_LEVEL = None
DB_CONN_CACHED_STATEMENTS = 100

DB_JOURNAL_MODE = "WAL"
DB_SYNC_MODE = "NORMAL"
DB_CACHE_SIZE = -8192   # 8KB
DB_MMAP_SIZE = 25165824  # 24MB
DB_AUTO_VACCUM = 'INCREMENTAL'

NETWORK_IFACE = "enp2s0",
SERVER_IP = "192.168.20.100"
SERVER_MAC = "18:c0:4d:46:f4:11"
BROADCAST_IP = "255.255.255.255"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
UNASSIGNED_IP = "0.0.0.0"


INBOUND_REQUESTS_DEDUPLICATE_QUEUE_SIZE = 60
DEDUPLICATION_TIME_BUFFER_SEC = 60
DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_DECLINE = 4
DHCP_ACK = 5
DHCP_NAK = 6
DHCP_INFORM = 8
DEFAULT_LEASE_TIME = 14*24*60*60
BOOTP_FLAG_BROADCAST = 0x8000
DHCP_PARAMS_REQUEST = [12, 43, 60, 61, 81]

ARP_DICOVERY_TIMEOUT = 3
LEASE_CLEANER_PERIOD = 1*60*60


dhcp_logger = MainLogger.get_logger(service_name="DHCP", log_level="debug")


class Utilities:

    @staticmethod
    def create_db():
        DB_PATH.mkdir(parents=True, exist_ok=True)
        sqlite3.connect(DB_FULLPATH).close()

    @staticmethod
    def delete_db_files() -> None:
        """Deletes files with given suffixes from the base path."""

        dhcp_logger.debug(f"Deleting DHCP DB files ...")
        for file in DB_PATH.iterdir():
            if file.is_file() and file.name.startswith(DB_FILENAME):
                try:
                    file.unlink()
                    dhcp_logger.debug(f"{file} deleted.")
                except FileNotFoundError:
                    dhcp_logger.error(f"{file} does not exist.")

    @staticmethod
    def get_connection_settings() -> dict:
        return {
            'database': DB_FULLPATH,
            'check_same_thread': DB_CONN_CHECK_SAME_THREAD,
            'timeout': DB_CONN_TIMEOUT,
            'isolation_level': DB_CONN_ISOLATION_LEVEL,
            'cached_statements': DB_CONN_CACHED_STATEMENTS
        }

    @staticmethod
    def enrich_connection(connection: sqlite3.Connection):
        connection.execute(f"PRAGMA journal_mode = {DB_JOURNAL_MODE}")
        connection.execute(f"PRAGMA synchronous = {DB_SYNC_MODE}")
        connection.execute(f"PRAGMA cache_size = {DB_CACHE_SIZE}")
        connection.execute(f"PRAGMA mmap_size = {DB_MMAP_SIZE}")
        connection.execute(f"PRAGMA auto_vacuum = {DB_AUTO_VACCUM}")
        return connection


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
    def extract_client_mac_from_dhcp_packet(packet: DHCP) -> str:
        """Extract the first 6 bytes of the MAC address from the packet."""
        return DHCPUtilities.format_mac(packet[BOOTP].chaddr[:6])

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
    def extract_client_param_req_list_from_dhcp_packet(packet: DHCP) -> str:
        """Extracts the 'param_req_list' from the DHCP packet."""
        for option in packet[scapy.DHCP].options:
            if option[0] == "param_req_list":
                return option[1]
        return []

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
    def is_dhcp_release(packet: scapy.Packet) -> bool:
        """Check if the given DHCP packet is a DHCP Release message."""
        return DHCPUtilities.extract_dhcp_type_from_packet(packet) == 7

    @staticmethod
    def is_dhcp_inform(packet: scapy.Packet) -> bool:
        """Check if the given DHCP packet is a DHCP Discover message."""
        return DHCPUtilities.extract_dhcp_type_from_packet(packet) == 8

    @staticmethod
    def format_mac(raw_mac: bytes) -> str:
        """ Format a raw MAC address to human-readable format """
        return ":".join(f"{b:02x}" for b in raw_mac[:6])

    @staticmethod
    def convert_binary_to_string(data_to_convert: bytes) -> str:
        """ Format a raw MAC address to human-readable format """
        return data_to_convert.decode('utf-8', errors='ignore')

    @staticmethod
    def discover_client_via_arp(ip: str = '', iface: str = NETWORK_IFACE, source_ip: str = SERVER_IP, source_mac: str = SERVER_MAC, timeout: float = ARP_DICOVERY_TIMEOUT) -> bool:
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
    def discover_clients_via_arp() -> dict:
        """Send a broadcast ARP request to discover all active clients on the network."""

        discovered_clients = {}

        try:
            network = ipaddress.IPv4Network(f"{SERVER_IP}/24", strict=False)
            subnet = str(network.network_address) + '/24'

            packet = Ether(dst=BROADCAST_MAC, src=SERVER_MAC) / ARP(pdst=subnet, psrc=SERVER_IP, op=1)
            answered, unanswered = scapy.srp(packet, timeout=ARP_DICOVERY_TIMEOUT, verbose=False, iface="enp2s0")

            for sent, received in answered:
                discovered_clients[received.hwsrc] = received.psrc

            return discovered_clients

        except Exception as err:
            dhcp_logger.error(f"Unexpected error during ARP discovery: {str(err)}")
            return {}

    @staticmethod
    def is_ip_in_subnet(ip_to_validate: str = None, subnet: str = "192.168.20.0/24"):
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

    _lock = threading.RLock()
    _conn = None
    _cursor = None
    _running = False
    _is_initialised = False

    @classmethod
    def init(cls):

        if cls._is_initialised:
            return

        with cls._lock:
            cls._running = True
            cls._conn = Utilities.enrich_connection(sqlite3.connect(**Utilities.get_connection_settings()))
            cls._cursor = cls._conn.cursor()
            cls._create_tables()
            cls._is_initialised = True

    @classmethod
    def _create_tables(cls) -> None:
        """Initialize the database tables only once."""
        with cls._lock:
            try:
                _create_table_leases_statement = f"""
                        CREATE TABLE IF NOT EXISTS leases (
                            mac TEXT PRIMARY KEY,
                            ip TEXT NOT NULL,
                            hostname TEXT DEFAULT 'unknown',
                            timestamp INTEGER NOT NULL,
                            expiry_time INTEGER NOT NULL,
                            type TEXT DEFAULT 'dynamic')
                        """
                cls._cursor.execute(_create_table_leases_statement)
                cls._conn.commit()
                dhcp_logger.debug("Leases DB initialized")

            except Exception as err:
                dhcp_logger.error(f"Failed to initialize in-memory SQLite database: {str(err)}")

    @classmethod
    def add_lease(cls, mac: str, ip: str, hostname: str = 'unknown', lease_time: int = DEFAULT_LEASE_TIME, lease_type: str = 'dynamic') -> None:
        """Insert a new lease into the database."""

        try:
            with cls._lock:

                current_time = int(time.time())
                expiry_time = int(current_time + lease_time)

                _statement = """
                    INSERT OR REPLACE INTO
                    leases (mac, ip, hostname, timestamp, expiry_time, type)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """
                _values = (mac, ip, hostname, current_time, expiry_time, lease_type)
                cls._cursor.execute(_statement, _values)
                cls._conn.commit()

                dhcp_logger.debug(f"Added MAC:{mac} IP:{ip}")

        except Exception as e:
            dhcp_logger.error(f"Failed to add lease: {str(e)}")

    @classmethod
    def renew_lease(cls, mac: str, lease_time: int = DEFAULT_LEASE_TIME) -> None:
        """Renew an existing lease by updating its expiry time."""
        try:
            with cls._lock:
                current_time = int(time.time())
                expiry_time = int(current_time + lease_time)
                _statement = """
                    UPDATE leases
                    SET
                        expiry_time = ?,
                        timestamp = ?
                    WHERE mac = ?
                """
                _values = (expiry_time, current_time, mac)
                _result = cls._cursor.execute(_statement, _values)
                cls._conn.commit()

                if _result.rowcount == 0:
                    dhcp_logger.warning(f"DB => Cannot renew lease, no existing lease found for MAC {mac}")
                else:
                    dhcp_logger.debug(f"DB => renewed:{mac} new expiry:{expiry_time})")

        except Exception as e:
            dhcp_logger.error(f"Failed to renew lease for {mac}: {e}")

    @classmethod
    def get_lease_by_mac(cls, mac: str) -> tuple | None:
        """Get the IP address assigned to a given MAC address."""
        try:
            with cls._lock:
                _statement = 'SELECT * FROM leases WHERE mac = ?'
                _values = (mac,)
                cls._cursor.execute(_statement, _values)
                return cls._cursor.fetchone()

        except Exception as e:
            dhcp_logger.error(f"Failed to get lease for {mac}: {e}")
            return None

    @classmethod
    def get_mac_by_ip(cls, ip: str) -> str | None:
        """Get the MAC address assigned to a given IP address."""
        try:
            with cls._lock:
                _statement = 'SELECT mac FROM leases WHERE ip = ?'
                _value = (ip,)
                cls._cursor.execute(_statement, _value)
                result = cls._cursor.fetchone()
                return result[0] if result else None

        except Exception as e:
            dhcp_logger.error(f"Failed to get lease for {ip}: {e}")
            return None

    @classmethod
    def get_all_leased_ips(cls) -> set:
        """Get a list of currently leased IPs."""
        try:
            with cls._lock:

                cls._cursor.execute('SELECT ip FROM leases')
                _result = cls._cursor.fetchall()
                return {lease[0] for lease in _result}

        except Exception as e:
            dhcp_logger.error(f"Failed to get active leases: {e}")
            return set()

    @classmethod
    def get_all_leases(cls) -> list:
        """Get all leases"""

        with cls._lock:
            try:
                cls._cursor.execute('SELECT * FROM leases')
                return cls._cursor.fetchall()

            except Exception as e:
                dhcp_logger.error(f"Failed to get active leases: {e}")
                return []

    @classmethod
    def remove_lease_by_mac(cls, mac: str):
        """Remove a lease from the database."""

        with cls._lock:
            try:
                _statement = 'DELETE FROM leases WHERE mac = ?'
                _values = (mac,)
                _result = cls._cursor.execute(_statement, _values)
                cls._conn.commit()

                if _result.rowcount == 0:
                    dhcp_logger.debug(f"DB -> Lease not found for MAC:{mac}, no deletion occured")
                else:
                    dhcp_logger.debug(f"DB -> Removed {_result.rowcount} lease(s) for MAC:{mac}")

            except Exception as e:
                dhcp_logger.error(f"DB -> failed to remove lease: {e}")

    @classmethod
    def remove_leases_by_mac(cls, macs: set):
        """Remove multiple leases from the database based on a set of MAC addresses."""

        if not macs:
            return

        with cls._lock:
            try:
                _value = tuple(macs)
                _statement = f"""
                    DELETE
                    FROM leases
                    WHERE mac IN ({",".join(["?"] * len(_value))})"""

                _result = cls._cursor.execute(_statement, _value)
                cls._conn.commit()

                if _result.rowcount == 0:
                    dhcp_logger.debug(f"DB -> No matching leases found for removal. MACs: {str(macs)}")
                else:
                    dhcp_logger.debug(f"DB -> Deleted {_result.rowcount} lease(s). Removed MACs: {set(macs)}")
            except Exception as e:
                dhcp_logger.error(f"DB -> failed to remove leases: {e}")

    @classmethod
    def remove_expired_leases(cls):
        """Remove expired leases."""

        with cls._lock:

            dhcp_logger.debug(f"Checking for expired leases ...")
            try:
                current_time = int(time.time())

                _statement = "DELETE FROM leases WHERE expiry_time < ?"
                _value = (current_time,)

                cls._cursor.execute(_statement, _value)
                cls._conn.commit()

                deleted_leases = cls._conn.total_changes
                dhcp_logger.debug(f"Found/deleted {deleted_leases} expired leases")

            except Exception as e:
                dhcp_logger.error(f"Error during lease cleanup: {e}")

    @classmethod
    def service_lease_cleaner(cls) -> list:
        while cls._running:
            with cls._lock:
                try:

                    cls.remove_expired_leases()

                    _active_leases = cls.get_all_leases()
                    _active_leases_macs = {lease[0] for lease in _active_leases}
                    _active_clients: dict = DHCPUtilities.discover_clients_via_arp()
                    _macs_to_be_removed = set()

                    for _active_lease_mac in _active_leases_macs:
                        if _active_lease_mac not in _active_clients:
                            _macs_to_be_removed.add(_active_lease_mac)

                    if _macs_to_be_removed:
                        cls.remove_leases_by_mac(_macs_to_be_removed)
                        dhcp_logger.info(f"Removed leases for MACs: {_macs_to_be_removed}")

                    for _active_client_mac, _active_client_ip in _active_clients.items():
                        if _active_client_mac not in _active_leases_macs:
                            cls.add_lease(
                                mac=_active_client_mac,
                                ip=_active_client_ip,
                                lease_type='static'
                            )

                except Exception as e:
                    dhcp_logger.error(f"Error during dead lease removal: {e}")

            time.sleep(LEASE_CLEANER_PERIOD)


class DHCPStatsStorage:
    _lock = threading.RLock()
    _is_initialised = False
    _conn = None
    _cursor = None
    _valid_columns = None

    @classmethod
    def init(cls):
        """Initializes the class-level SQLite connection and cursor."""

        if cls._is_initialised:
            return

        cls._conn = Utilities.enrich_connection(sqlite3.connect(**Utilities.get_connection_settings()))
        cls._cursor = cls._conn.cursor()
        cls._create_table()
        cls._init_table()
        cls._is_initialised = True
        cls._valid_columns = set()

    @classmethod
    def _create_table(cls):
        with cls._lock:
            cls._cursor.execute("""
                                CREATE TABLE IF NOT EXISTS stats (
                                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                                    last_updated TEXT DEFAULT CURRENT_TIMESTAMP,
                                    received_total INTEGER DEFAULT 0,
                                    received_total_valid INTEGER DEFAULT 0,
                                    received_discover INTEGER DEFAULT 0,
                                    received_request INTEGER DEFAULT 0,
                                    received_decline INTEGER DEFAULT 0,
                                    received_release INTEGER DEFAULT 0,
                                    received_inform INTEGER DEFAULT 0,
                                    sent_total INTEGER DEFAULT 0,
                                    sent_offer INTEGER DEFAULT 0,
                                    sent_ack INTEGER DEFAULT 0,
                                    sent_nak INTEGER DEFAULT 0
                                )
                                """)
            cls._conn.commit()

    @classmethod
    def _init_table(cls):

        with cls._lock:
            cls._cursor.execute("DELETE FROM stats")
            cls._cursor.execute("DELETE FROM sqlite_sequence WHERE name='stats'")
            cls._cursor.execute("INSERT INTO stats (id) VALUES (1)")
            cls._conn.commit()

    @classmethod
    def _is_key_valid(cls, key: str) -> bool:
        """Validates that the key exists as a column in the `stats` table, and caches it if found."""

        if not cls._valid_columns:
            with cls._lock:
                cls._cursor.execute("PRAGMA table_info(stats)")
                columns_info = cls._cursor.fetchall()
                cls._valid_columns.update({col[1] for col in columns_info})

        return bool(key in cls._valid_columns)

    @classmethod
    def increment(cls, key: str, count: int = 1):

        if not cls._is_key_valid(key):
            dhcp_logger.warning(f"Invalid key: {key}")
            return

        with cls._lock:
            cls._cursor.execute(f"""
                                UPDATE stats
                                SET {key} = {key} + ?,last_updated = CURRENT_TIMESTAMP
                                WHERE id = 1
                                """, (count,))
            cls._conn.commit()

    @classmethod
    def close(cls):
        with cls._lock:
            if cls._conn:
                cls._cursor.close()
                cls._conn.close()
                cls._cursor = None
                cls._conn = None


class DHCPServer:
    def __init__(self) -> None:
        self._running = True
        self.lock = RLock()
        self.leased_ips = {}
        self.denied_ips = {}
        self.offered_ips = {}
        self._threads = {}
        self._inbound_packet_buffer_queue = queue.Queue(maxsize=100)
        self._inbound_packet_deduplication_queue = deque(maxlen=INBOUND_REQUESTS_DEDUPLICATE_QUEUE_SIZE)
        self._initialize_config()

    def _initialize_config(self) -> None:
        """Load DHCP configuration from the config file."""
        try:
            with open(CONFIG_FULLPATH, "r") as file_handle:
                _config = json.load(file_handle)
                self._interface = _config.get("interface")
                self._own_ip = _config.get("server_ip")
                self._own_mac = _config.get("server_mac")
                self._own_subnet = _config.get("server_subnet_mask")
                self._server_ip_range_start = _config.get("server_ip_range_start")
                self._server_ip_range_end = _config.get("server_ip_range_end")
                self._broadcast = _config.get("server_broadcast")
                self._router_ip = _config.get("router_ip")
                self._dns_server = _config.get("dns_server")
                self._ntr_server = _config.get("ntp_server")
                self._lease_time = _config.get("lease_time")
                self._rebinding_time = int(self._lease_time * 0.875)
                self._renewal_time = int(self._lease_time * 0.5)
                self._mtu = int(_config.get("mtu"))
                self._dhcp_port = _config.get("dhcp_port")

        except Exception as err:
            dhcp_logger.error(f"Failed to load DHCP config: {str(err)}")

    def _init_denied_ips_by_client(self, packet: Ether):
        if packet[Ether].src not in self.denied_ips:
            self.denied_ips[packet[Ether].src] = set()

    def _helper_get_dhcp_bootp_options(self, client_mac: str, transaction_id: int, your_ip: str) -> dict:
        return {
            "op": 2,
            "xid": transaction_id,
            "chaddr": bytes.fromhex(client_mac.replace(':', '')) + b"\x00" * 10,  # Ensure 16 bytes
            "yiaddr": your_ip if your_ip else "0.0.0.0",
            "siaddr": self._own_ip,
            "flags": 0x8000
        }

    def _resolve_url_to_ip(self, ntp_server_url: str) -> str:

        try:
            return socket.gethostbyname(ntp_server_url)

        except socket.gaierror:
            dhcp_logger.warning(f"Failed to resolve NTP server: {ntp_server_url}")
            return self._router_ip

    def _get_dhcp_options(self, dhcp_type: str, message: str) -> list:

        if dhcp_type == 'NAK':
            return [
                ("message-type", 6),
                ("server_id", self._own_ip),
                ("error_message", message),
                "end"
            ]

        if dhcp_type == 'ACK':
            return [
                ("message-type", 5),
                ("server_id", self._own_ip),
                ("subnet_mask", self._own_subnet),
                ("router", self._router_ip),
                ("name_server", self._dns_server),
                ("lease_time", self._lease_time),
                ("renewal_time", self._renewal_time),
                ("rebinding_time", self._rebinding_time),
                ("interface-mtu", self._mtu),
                "end"
            ]

        if dhcp_type == 'OFFER':
            return [
                ("message-type", 2),
                ("server_id", self._own_ip),
                ("subnet_mask", self._own_subnet),
                ("router", self._router_ip),
                ("name_server", self._dns_server),
                ("lease_time", self._lease_time),
                ("renewal_time", self._renewal_time),
                ("rebinding_time", self._rebinding_time),
                ("interface-mtu", self._mtu),
                ("param_req_list", [1, 3, 6, 15, 28, 51, 58, 59]),
                "end"
            ]

        raise ValueError(f"DHCP Option couldn't be calculated provided:{dhcp_type}")

    def _build_dhcp_response(self, dhcp_type: str, your_ip: str, message: str, request_packet: Ether) -> DHCP:
        """Builds a DHCP packet for the given client."""

        bootp_options = {
            "op": 2,
            "xid": request_packet[BOOTP].xid,
            "chaddr": request_packet[BOOTP].chaddr[:6] + b"\x00" * 10,
            "yiaddr": your_ip,
            "siaddr": self._own_ip,
            "flags": BOOTP_FLAG_BROADCAST
        }

        dhcp_options: list[tuple] = self._get_dhcp_options(dhcp_type=dhcp_type, message=message)

        return (
            Ether(src=self._own_mac, dst=BROADCAST_MAC) /
            IP(src=self._own_ip, dst=BROADCAST_IP) /
            UDP(sport=self._dhcp_port, dport=request_packet[UDP].sport) /
            BOOTP(**bootp_options) /
            DHCP(options=dhcp_options)
        )

    def _send_dhcp_packet(self, packet: Ether):
        """Send a DHCP packet on the configured interface."""

        dhcp_type = DHCPUtilities.extract_dhcp_type_from_packet(packet)
        dhcp_type_string = DHCPUtilities.convert_dhcp_lease_to_string(dhcp_type)

        DHCPStatsStorage.increment(key="sent_total")
        DHCPStatsStorage.increment(key=f"sent_{dhcp_type_string}")

        dhcp_logger.debug(
            f"Send {dhcp_type_string} XID {packet[BOOTP].xid} CHADDR {":".join([f"{_each_char:02x}" for _each_char in packet[BOOTP].chaddr[:6]])}")
        scapy.sendp(packet, iface=self._interface, verbose=False)

    def _find_available_ip(self, packet: Ether) -> str:
        """Find the next available IP, avoiding specified exclusions"""

        with self.lock:

            start_ip = ipaddress.IPv4Address(self._server_ip_range_start)
            end_ip = ipaddress.IPv4Address(self._server_ip_range_end)
            leased_ips = DHCPStorage.get_all_leased_ips()

            discovered_clients = DHCPUtilities.discover_clients_via_arp()

            # This means we already offered this IP to this client and it did not reject or accept it
            # matching_ip = next((ip for ip, mac in self.offered_ips.items() if mac == packet[Ether].src), None)

            for _ip in range(int(start_ip), int(end_ip) + 1):
                _proposed_ip = str(ipaddress.IPv4Address(_ip))
                if (
                    _proposed_ip in leased_ips or
                    _proposed_ip in self.offered_ips or
                    _proposed_ip in self.denied_ips[packet[Ether].src] or
                    _proposed_ip in discovered_clients.values()
                ):
                    continue

                is_ip_active, _ = DHCPUtilities.discover_client_via_arp(
                    ip=_proposed_ip,
                    iface=self._interface,
                    source_ip=self._own_ip,
                    source_mac=self._own_mac,
                    timeout=ARP_DICOVERY_TIMEOUT
                )

                if not is_ip_active:

                    dhcp_logger.debug(f"Proposing IP => {_proposed_ip}")
                    return _proposed_ip
                else:
                    dhcp_logger.debug(f"{_proposed_ip} busy")
                    continue

        dhcp_logger.warning(f"No available IPs found")
        return None

    def _handle_dhcp_decline(self, packet: Ether) -> None:
        """Handles DHCP Decline messages (RFC 2131, Section 4.3.2)"""

        source_mac = packet[Ether].src
        transaction_id = packet[BOOTP].xid
        declined_ip = DHCPUtilities.extract_requested_addr_from_dhcp_packet(packet)

        dhcp_logger.info(f"DHCPDECLINE XID:{transaction_id} MAC:{source_mac} Declined IP:{declined_ip}")

        with self.lock:

            existing_lease = DHCPStorage.get_lease_by_mac(source_mac)
            self.denied_ips[source_mac].add(declined_ip)

            # Case 1: The client has a lease and it is for the declined IP
            if existing_lease and existing_lease[1] == declined_ip:
                dhcp_logger.debug(f"Client MAC:{source_mac} declined IP:{declined_ip}, removing lease from database")
                DHCPStorage.remove_lease_by_mac(source_mac)
            else:
                # Case 2: The client declined the IP and doesnt have active lease
                dhcp_logger.debug(f"Client {source_mac} declined IP {declined_ip}, but no lease found")

            server_response = self._build_dhcp_response(
                dhcp_type="NAK",
                your_ip="0.0.0.0",
                message=f"IP {declined_ip} declined",
                request_packet=packet
            )
            self._send_dhcp_packet(packet=server_response)

    def _handle_dhcp_release(self, packet: Ether) -> None:
        """DHCP Release (Section 4.4 of RFC 2131) sent by the client to release an IP address that it no longer needs"""

        source_mac = packet[Ether].src
        transaction_id = packet[BOOTP].xid
        source_ip = packet[IP].src

        dhcp_logger.info(f"DHCPRELEASE XID:{transaction_id} MAC:{source_mac} IP_src:{source_ip}")

        with self.lock:

            self.denied_ips[source_mac] = set()
            DHCPStorage.remove_lease_by_mac(source_mac)

            server_response = self._build_dhcp_response(
                dhcp_type="ACK",
                your_ip="0.0.0.0",
                message=f"IP: {source_ip} released by MAC_src: {source_mac}",
                request_packet=packet
            )
            self._send_dhcp_packet(server_response)

    def _handle_dhcp_inform(self,  packet: Ether) -> None:
        """DHCPINFORM (Section 3.3.2 of RFC 2131)"""

        source_mac = packet[Ether].src
        source_ip = packet[IP].src
        transaction_id = packet[BOOTP].xid
        param_req_list = DHCPUtilities.extract_client_param_req_list_from_dhcp_packet(packet)

        dhcp_logger.info(f"DHCPINFORM MAC:{source_mac} XID:{transaction_id} Requested Parameters:{param_req_list}")

        with self.lock:

            server_response = self._build_dhcp_response(
                dhcp_type="ACK",
                transaction_id=transaction_id,
                your_ip=source_ip,
                message=f"Information provided",
                request_packet=packet
            )
            self._send_dhcp_packet(server_response)

    def _handle_dhcp_request_old(self, packet: Ether) -> None:
        """Handles DHCP Request messages (RFC 2131, Section 4.3)"""

        source_mac = packet[Ether].src
        transaction_id = packet[BOOTP].xid
        client_hostname = DHCPUtilities.extract_hostname_from_dhcp_packet(packet)
        requested_ip = DHCPUtilities.extract_requested_addr_from_dhcp_packet(packet)
        client_ip = packet[BOOTP].ciaddr

        dhcp_logger.info(f"REQUEST XID:{transaction_id} MAC:{source_mac} IP_requested:{requested_ip} Hostname:{client_hostname}")

        with self.lock:
            dhcp_type = None
            message = None
            your_ip = None

            existing_lease = DHCPStorage.get_lease_by_mac(source_mac)
            lease_holder_mac = DHCPStorage.get_mac_by_ip(requested_ip) if requested_ip else None

            # Ensure there's a valid IP to process (either 'requested_ip' or 'ciaddr')
            if requested_ip or client_ip:
                ip_to_validate = requested_ip if requested_ip else client_ip
                is_ip_active, active_mac = DHCPUtilities.discover_client_via_arp(
                    ip=ip_to_validate,
                    iface=self._interface,
                    source_ip=self._own_ip,
                    source_mac=self._own_mac
                )

                # Case 1: Requested IP is already assigned to another MAC
                if is_ip_active and active_mac not in {source_mac, lease_holder_mac}:
                    dhcp_logger.debug(f"NAK (IP in use) MAC_src:{source_mac}, MAC_act:{active_mac}, MAC_leased:{lease_holder_mac}")
                    # self.denied_ips[source_mac].add(ip_to_validate)
                    dhcp_type, message, your_ip = "NAK", "Requested IP already in use", "0.0.0.0"

                # Case 2: Client in INIT-REBOOT requesting a previously assigned IP
                elif not is_ip_active and existing_lease and existing_lease[1] == ip_to_validate:
                    dhcp_logger.debug(f"ACK (INIT-REBOOT) Reassigning existing lease IP:{ip_to_validate} to MAC:{source_mac}")
                    DHCPStorage.add_lease(
                        mac=source_mac,
                        ip=ip_to_validate,
                        hostname=client_hostname,
                        lease_time=self._lease_time)
                    dhcp_type, message, your_ip = "ACK", "Existing lease reassigned", ip_to_validate

                # Case 3: Client in RENEWING/REBINDING requesting the same IP
                elif is_ip_active and active_mac == source_mac and lease_holder_mac == source_mac:
                    dhcp_logger.debug(f"ACK (Lease Renewal) IP:{ip_to_validate} MAC:{source_mac}")
                    DHCPStorage.add_lease(
                        mac=source_mac,
                        ip=ip_to_validate,
                        hostname=client_hostname,
                        lease_time=self._lease_time)
                    dhcp_type, message, your_ip = "ACK", "Lease renewed", ip_to_validate

                # Case 4: No existing lease, and IP is free
                elif not is_ip_active and not lease_holder_mac:
                    dhcp_logger.debug(f"ACK (New lease) Assigning IP:{ip_to_validate} to MAC:{source_mac}")
                    DHCPStorage.add_lease(
                        mac=source_mac,
                        ip=ip_to_validate,
                        hostname=client_hostname,
                        lease_time=self._lease_time)
                    dhcp_type, message, your_ip = "ACK", "New lease assigned", ip_to_validate

                # Case 5: Client Requests an IP Outside the Subnet
                elif not DHCPUtilities.is_ip_in_subnet(ip_to_validate):
                    dhcp_logger.debug(f"NAK (IP outside subnet) Requested IP:{ip_to_validate} is not in allowed range")
                    # self.denied_ips[source_mac].add(ip_to_validate)
                    dhcp_type, message, your_ip = "NAK", "Requested IP is outside the subnet", "0.0.0.0"

                # Case 6: Client Requests a Different IP Than Its Current Lease (`ciaddr`)
                elif existing_lease and ip_to_validate != existing_lease[1]:
                    dhcp_logger.debug(
                        f"DHCPNAK discovery required Existing:{existing_lease[1]} -> New:{ip_to_validate} for MAC:{source_mac}")
                    dhcp_type, message, your_ip = "NAK", "DHCPDISCOVER first", "0.0.0.0"

                else:
                    # Default rejection case
                    dhcp_logger.debug(f"NAK (Default) IP:{ip_to_validate} MAC_src:{source_mac} MAC_leased:{lease_holder_mac}")
                    # self.denied_ips[source_mac].add(ip_to_validate)
                    dhcp_type, message, your_ip = "NAK", f"Could not fulfill DHCPREQUEST for IP {ip_to_validate}", "0.0.0.0"

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
            print(source_mac, transaction_id, dhcp_type, message, your_ip)

            self._send_dhcp_packet(server_response)

    def _handle_dhcp_request(self, packet: Ether) -> None:
        """Handles DHCP Request messages (RFC 2131, Section 4.3)"""
        source_mac = packet[Ether].src
        transaction_id = packet[BOOTP].xid
        client_hostname = DHCPUtilities.extract_hostname_from_dhcp_packet(packet)
        requested_ip = DHCPUtilities.extract_requested_addr_from_dhcp_packet(packet)
        client_ip = packet[BOOTP].ciaddr

        ip_to_validate = requested_ip if requested_ip else client_ip
        dhcp_logger.info(f"REQUEST XID:{transaction_id} MAC:{source_mac} IP_requested:{requested_ip} Hostname:{client_hostname}")

        with self.lock:
            dhcp_type = None
            message = None
            your_ip = "0.0.0.0"  # default for NAK

            existing_lease = DHCPStorage.get_lease_by_mac(source_mac)
            lease_holder_mac = DHCPStorage.get_mac_by_ip(ip_to_validate) if ip_to_validate else None

            # Validate subnet early
            if ip_to_validate and not DHCPUtilities.is_ip_in_subnet(ip_to_validate):
                dhcp_logger.debug(f"NAK (IP outside subnet) Requested IP:{ip_to_validate} is not in allowed range")
                dhcp_type, message = "NAK", "Requested IP is outside the subnet"

            elif ip_to_validate:
                is_ip_active, active_mac = DHCPUtilities.discover_client_via_arp(
                    ip=ip_to_validate,
                    iface=self._interface,
                    source_ip=self._own_ip,
                    source_mac=self._own_mac
                )

                # IP in use by someone else
                if is_ip_active and active_mac not in {source_mac, lease_holder_mac}:
                    dhcp_logger.debug(f"NAK (IP in use) MAC_src:{source_mac}, MAC_act:{active_mac}, MAC_leased:{lease_holder_mac}")
                    dhcp_type, message = "NAK", "Requested IP already in use"

                # INIT-REBOOT
                elif not is_ip_active and existing_lease and existing_lease[1] == ip_to_validate:
                    dhcp_logger.debug(f"ACK (INIT-REBOOT) Reassigning IP:{ip_to_validate} to MAC:{source_mac}")
                    DHCPStorage.add_lease(source_mac, ip_to_validate, client_hostname, self._lease_time)
                    dhcp_type, message, your_ip = "ACK", "Existing lease reassigned", ip_to_validate

                # RENEW / REBIND
                elif is_ip_active and active_mac == source_mac and lease_holder_mac == source_mac:
                    dhcp_logger.debug(f"ACK (Lease Renewal) IP:{ip_to_validate} MAC:{source_mac}")
                    DHCPStorage.add_lease(source_mac, ip_to_validate, client_hostname, self._lease_time)
                    dhcp_type, message, your_ip = "ACK", "Lease renewed", ip_to_validate

                # Free IP, no conflicts
                elif not is_ip_active and not lease_holder_mac:
                    dhcp_logger.debug(f"ACK (New lease) Assigning IP:{ip_to_validate} to MAC:{source_mac}")
                    DHCPStorage.add_lease(source_mac, ip_to_validate, client_hostname, self._lease_time)
                    dhcp_type, message, your_ip = "ACK", "New lease assigned", ip_to_validate

                # Client changing IP without DISCOVER
                elif existing_lease and ip_to_validate != existing_lease[1]:
                    dhcp_logger.warning(
                        f"NAK (IP change without DISCOVER) Existing:{existing_lease[1]} → New:{ip_to_validate} MAC:{source_mac}")
                    dhcp_type, message = "NAK", "Use DHCPDISCOVER before requesting new IP"

                else:
                    # Fallback case
                    dhcp_logger.debug(f"NAK (Default) IP:{ip_to_validate} MAC_src:{source_mac} MAC_leased:{lease_holder_mac}")
                    dhcp_type, message = "NAK", f"Could not fulfill DHCPREQUEST for IP {ip_to_validate}"

            else:
                # No IP to validate (neither requested_ip nor ciaddr present)
                dhcp_logger.debug(f"NAK (no IP requested) MAC_src:{source_mac}")
                dhcp_type, message = "NAK", "No IP requested"

            server_response = self._build_dhcp_response(
                dhcp_type=dhcp_type,
                your_ip=your_ip,
                message=message,
                request_packet=packet
            )

            self._send_dhcp_packet(server_response)

    def _handle_dhcp_discover(self, packet: Ether) -> None:
        """Handles DHCPDISCOVER messages (RFC 2131, Section 4.1) sent by clients to discover DHCP servers."""
        with self.lock:

            proposed_ip = self._find_available_ip(packet)
            if not proposed_ip:
                dhcp_logger.warning(f"No available IPs, ignoring DISCOVER from {packet[Ether].src}")
                return

            dhcp_logger.debug(
                f"DISCOVER XID:{packet[BOOTP].xid} MAC:{packet[Ether].src} proposed IP:{proposed_ip}, lease:{self._lease_time}s"
            )

            # if proposed_ip not in self.offered_ips:
            #     self.offered_ip[proposed_ip] = packet[Ether].src

            _response = self._build_dhcp_response(
                dhcp_type="OFFER",
                your_ip=proposed_ip,
                message="offer_ip",
                request_packet=packet
            )
            self._send_dhcp_packet(_response)

    def _log_inbound_packet(self, packet: Ether) -> None:
        """Logs details of a DHCP packet."""

        dhcp_type = DHCPUtilities.extract_dhcp_type_from_packet(packet)
        dhcp_type_string = DHCPUtilities.convert_dhcp_lease_to_string(dhcp_type)

        DHCPStatsStorage.increment(key="received_total_valid")
        DHCPStatsStorage.increment(key=f"received_{dhcp_type_string}")

    def _handle_inbound_dhcp_packet(self, packet: Ether):

        with self.lock:

            self._log_inbound_packet(packet)
            self._init_denied_ips_by_client(packet)

            if DHCPUtilities.is_dhcp_discover(packet):
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
                dhcp_logger.warning(f'DHCP type unknown')

            # RabbitMqProducer.send_message({'timestamp': time.time(), 'type': 'statistics', 'payload': Stats.get_all_statistics()})
            RabbitMqProducer.send_message({'timestamp': time.time(), 'type': 'dhcp-leases', 'payload': DHCPStorage.get_all_leases()})

    def service_queue_worker_processor(self) -> None:

        thread_name = threading.current_thread().name
        while self._running:
            try:
                packet = self._inbound_packet_buffer_queue.get(timeout=0.5)
                dhcp_logger.debug(f"{thread_name} processing XID {packet[BOOTP].xid}")

                self._handle_inbound_dhcp_packet(packet)
                self._inbound_packet_buffer_queue.task_done()
                dhcp_logger.debug(f"{thread_name} processing done")
                time.sleep(0.05)

            except queue.Empty:
                time.sleep(0.1)

            except Exception as err:
                dhcp_logger.error(f"{thread_name} processing DHCP packet:{str(err)}")
                self._inbound_packet_buffer_queue.task_done()
                time.sleep(0.1)

    def _is_received_packet_valid(self, packet: Ether) -> bool:
        return bool(
            packet.haslayer(IP) and
            packet.haslayer(DHCP) and
            packet[Ether].src != self._own_mac
        )

    def main_processor(self, packet: Ether) -> None:
        """Provides centralized point for processing DHCP packets"""
        try:

            if not self._is_received_packet_valid(packet=packet):
                return

            if self._inbound_packet_buffer_queue.full():
                raise queue.Full

            _dhcp_type = DHCPUtilities.extract_dhcp_type_from_packet(packet)
            _time = packet.time//DEDUPLICATION_TIME_BUFFER_SEC

            DHCPStatsStorage.increment(key="received_total")
            with open("./logs/dhcp_packets.log", "a", encoding="utf-8") as f:
                f.write(f"{packet.time:.4f} {_time} {packet[Ether].src} {packet[BOOTP].xid} {_dhcp_type} - RAW\n")

            key = (packet[Ether].src, packet[BOOTP].xid, _dhcp_type, _time)
            if key in self._inbound_packet_deduplication_queue:
                return

            with open("./logs/dhcp_packets.log", "a", encoding="utf-8") as f:
                f.write(f"{packet.time:.4f} {_time} {packet[Ether].src} {packet[BOOTP].xid} {_dhcp_type} - OK\n")

            self._inbound_packet_deduplication_queue.appendleft(key)
            self._inbound_packet_buffer_queue.put(packet)

        except queue.Full:
            dhcp_logger.warning(f"packet queue is full")

        except Exception as err:
            dhcp_logger.warning(f"failed to enqueue DNS packet: {str(err)}")

    def service_traffic_listener(self) -> None:
        """ Start sniffing for DHCP packets on the interface """
        scapy.sniff(
            iface='enp2s0',
            filter="ip and udp and port 67",
            prn=self.main_processor,
            count=0,
            timeout=None,
            store=False,
            session=None
        )

    def start(self):
        """ Start all necessary threads """

        self._running = True

        Utilities.delete_db_files()
        Utilities.create_db()

        DHCPStorage.init()
        DHCPStatsStorage.init()

        traffic_listener = threading.Thread(target=self.service_traffic_listener, name="traffic_listener", daemon=True)
        traffic_listener.start()
        self._threads["traffic_listener"] = traffic_listener

        for i in range(5):
            queue_worker = threading.Thread(target=self.service_queue_worker_processor, name=f"queue_worker_{i}", daemon=True)
            queue_worker.start()
            self._threads[f"queue_worker_{i}"] = queue_worker

        service_lease_cleaner = threading.Thread(target=DHCPStorage.service_lease_cleaner,
                                                 name="service_lease_cleaner", daemon=True)
        service_lease_cleaner.start()
        self._threads[f"service_lease_cleaner"] = service_lease_cleaner

        dhcp_logger.info("Started")

    def stop_service(self):

        self._running = False

        for thread_name, thread in self._threads.items():
            if thread.is_alive():
                dhcp_logger.info(f"Stopping thread: {thread_name}")
                thread.join()

        dhcp_logger.info("All threads stopped, stopping the DNS server")


if __name__ == "__main__":

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
