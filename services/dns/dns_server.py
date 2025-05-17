#!/usr/bin/env python3.12

import sys
import re
import time
import json
import random
import queue
import threading
import signal
import scapy.all as scapy
from collections import deque
from scapy.all import Ether # type: ignore
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSRR
from services.config.config import Config
from services.logger.logger import MainLogger
from services.dns.dns_utilities import DNSQueries
from services.dns.dns_db import DNSCache,DNSHistory,DNSStats

dns_logger = MainLogger.get_logger(service_name="DNS", log_level="debug")

DNS_CONTROL_LIST_FULL_PATH = Config.get_paths().get("config") / 'dns_control_list.json' # type: ignore
DNS_DB_PATH = Config.get_paths().get("db")
DB_PERSISTENCE_INTERVAL = 60 

DEFAULT_DNS_SERVERS = ["1.1.1.1", "9.9.9.9", "1.1.1.3"]
UNSUPPORTED_QUERY_TYPES = [12,28,64,65]
BLOCKED_LISTS_LOADING_INTERVAL = 60

DNS_WORKERS = 100
INBOUND_QUEUE_BUFFER_SIZE = 100
INBOUND_QUEUE_BUFFER_LIMIT = 50
INBOUND_REQUESTS_DEDUPLICATE_QUEUE_SIZE = 50
INBOUND_PACKET_HIGH_LIMIT = 100

WORKER_QUEUE_GET_TIMEOUT = 0.5
WORKER_QUEUE_EMPTY_TIMEOUT = 0.1
WORKER_ERROR_SLEEP_TIMEOUT = 0.1


class Services:

    @staticmethod
    def db_persistence():
        while True:
            try:
                DNSStats.save_to_disk()
                DNSHistory.save_to_disk()
                DNSCache.save_to_disk()
            except Exception as err:
                dns_logger.warning(f"Persistence error: {str(err)}")
            time.sleep(DB_PERSISTENCE_INTERVAL)
    
    @staticmethod
    def delete_dns_db_files():

        if not DNS_DB_PATH:
            return

        dns_logger.debug(f"Deleting DNS DB files ...")
        for file in DNS_DB_PATH.iterdir():
            if file.is_file() and file.name.endswith('.sqlite3'):
                try:
                    file.unlink()
                    dns_logger.debug(f"{file} deleted.")
                except FileNotFoundError:
                    dns_logger.warning(f"{file} does not exist.")


class ControlLists:
    _running = True
    _blacklisted = set()
    _whitelisted = set()
    _lock = threading.RLock()

    @classmethod
    def load_control_list(cls):
        with cls._lock:
            try:
                with open(DNS_CONTROL_LIST_FULL_PATH, mode="r", encoding="utf-8") as file_handle:
                    _control_list = json.load(file_handle)
                    _blacklist_urls = set(_control_list.get("blacklist", {}).get("urls", []))
                    _blacklist_rules = set(_control_list.get("blacklist", {}).get("rules", []))
                    _blacklist_new = _blacklist_urls | _blacklist_rules
                    _whitelist_new = set(_control_list.get("whitelist", []))
                    if _blacklist_new != cls._blacklisted or _whitelist_new != cls._whitelisted:
                        cls._blacklisted = _blacklist_new
                        cls._whitelisted = _whitelist_new
                        dns_logger.debug(f'Loaded blacklist:{len(cls._blacklisted)} whitelist:{len(cls._whitelisted)}')
            except Exception as err:
                dns_logger.error(
                    f'Error processing control lists file: {str(err)}')

    @classmethod
    def service_control_list_loader(cls):
        while cls._running:
            with cls._lock:
                cls.load_control_list()
            time.sleep(BLOCKED_LISTS_LOADING_INTERVAL)
    
    @classmethod
    def is_query_blacklisted(cls, packet: Ether) -> bool:
        decoded_query = packet[DNS].qd.qname.decode('utf-8').rstrip('.').lower()
        for _blacklist_rule_raw in cls._blacklisted:
            blacklist_rule = f"^{_blacklist_rule_raw.strip().lower().replace('*', '.*')}$"
            if re.search(blacklist_rule, decoded_query):
                return True
        return False


class DNSUtilities:

    @staticmethod
    def is_packet_ipv4(packet: Ether) -> bool:
        return bool(packet[IP].proto == 17)

    @staticmethod
    def is_dns_request_query(packet: DNS) -> bool:
        return bool(packet[DNS].opcode == 0)

    @staticmethod
    def is_query_type_not_supported(packet: DNS) -> bool:
        return bool(packet[DNS].qd.qtype in UNSUPPORTED_QUERY_TYPES)

    @staticmethod
    def extract_max_ttl_from_answers(packet: DNS) -> int:
        """Extracts and returns the maximum TTL from DNSRR records in the answer chain."""

        max_ttl = 0
        # We have to iterate through DNSRR like this
        for _index in range(packet[DNS].ancount):
            if packet[DNS].an[_index].ttl > max_ttl:
                max_ttl = packet[DNS].an[_index].ttl
        return max_ttl

    @staticmethod
    def extract_ips_from_answers(answers: DNSRR) -> list:
        """Extracts all A and AAAA record IPs from DNS answer section."""
        ip_addresses = []
        current = answers

        while isinstance(current, DNSRR):
            if current.type == 1:
                ip_addresses.append(str(current.rdata))
            elif current.type == 28:
                ip_addresses.append(str(current.rdata))
            current = current.payload

        return ip_addresses

    @staticmethod
    def generate_random_port() -> int:
        return random.randint(1024, 65535)

    @staticmethod
    def convert_request_type(request_type: int = 1) -> str:
        query_type_map =  {
    1: 'request_type_a',
    2: 'request_type_ns',
    5: 'request_type_cname',
    6: 'request_type_soa',
    12: 'request_type_ptr',
    15: 'request_type_mx',
    16: 'request_type_txt',
    28: 'request_type_aaaa',
    33: 'request_type_srv',
    35: 'request_type_naptr',
    36: 'request_type_kx',
    37: 'request_type_cert',
    38: 'request_type_a6',
    39: 'request_type_dname',
    43: 'request_type_ds',
    44: 'request_type_sshfp',
    46: 'request_type_rrsig',
    47: 'request_type_nsec',
    48: 'request_type_dnskey',
    50: 'request_type_nsec3',
    51: 'request_type_nsec3param',
    52: 'request_type_tlsa',
    53: 'request_type_smimea',
    55: 'request_type_hip',
    59: 'request_type_cds',
    60: 'request_type_cdnskey',
    61: 'request_type_openpgpkey',
    64: 'request_type_svcb',
    65: 'request_type_https',
    99: 'request_type_spf',
    108: 'request_type_eui48',
    109: 'request_type_eui64',
    249: 'request_type_tkey',
    250: 'request_type_tsig',
    251: 'request_type_ixfr',
    252: 'request_type_axfr',
    255: 'request_type_any',
    256: 'request_type_uri',
    257: 'request_type_caa',
    32768: 'request_type_ta',
    32769: 'request_type_dlv',
}
        return query_type_map.get(request_type, 'unknown')


class DNSServer:

    def __init__(self):
        """
        Initializes the DNS server, loads the configuration, and sets up the SQLite database.
        """
        self._running = True
        self._lock = threading.RLock()
        self._inbound_packet_buffer_queue = queue.Queue(maxsize=INBOUND_QUEUE_BUFFER_SIZE)
        self._inbound_packet_deduplication_queue = deque(maxlen=INBOUND_REQUESTS_DEDUPLICATE_QUEUE_SIZE)
        self._threads = {}
        self._initialize_config()
        self._load_control_list()

    def _initialize_config(self):
        with self._lock:
            try:
                _server = Config.get_server()
                _dns = Config.get_dns()
                self.INTERFACE = _server.get("interface")
                self.OWN_IP = _server.get("ip")
                self.OWN_MAC = _server.get("mac")
                self.DNS_PORT = _dns.get("port")
                self.BLACKLIST = set()
                self.WHITELIST = set()

            except Exception as err:
                dns_logger.error(f"Error reading config  {str(err)}")

    def _load_control_list(self):
        """Loads control list from a JSON file."""

        with self._lock:

            try:
                with open(DNS_CONTROL_LIST_FULL_PATH, mode="r", encoding="utf-8") as file_handle:
                    _control_list = json.load(file_handle)
                    _blacklist_urls = set(_control_list.get("blacklist", {}).get("urls", []))
                    _blacklist_rules = set(_control_list.get("blacklist", {}).get("rules", []))
                    _blacklist_new = _blacklist_urls | _blacklist_rules
                    _whitelist_new = set(_control_list.get("whitelist", []))
                    if _blacklist_new != self.BLACKLIST or _whitelist_new != self.WHITELIST:
                        self.BLACKLIST = _blacklist_new
                        self.WHITELIST = _whitelist_new
                        dns_logger.debug(f'Loaded blacklist:{len(self.BLACKLIST)} whitelist:{len(self.WHITELIST)}')

            except Exception as err:
                dns_logger.error(
                    f'Error processing control lists file: {str(err)}')

    def _build_notimp_response(self, request_packet: Ether) -> Ether:
        """
        Builds a DNS response with RCODE=4 (Not Implemented).

        Args:
            packet (scapy.Packet): The incoming DNS request packet.
            own_mac (str): The MAC address of the DNS server.
            own_ip (str): The IP address of the DNS server.
            dns_port (int): The port the DNS server is listening on (default: 53).

        Returns:
            scapy.Packet: The DNS response packet.
        """

        return (
            Ether(src=request_packet[Ether].dst, dst=request_packet[Ether].src) /
            IP(src=request_packet[IP].dst, dst=request_packet[IP].src) /
            UDP(sport=request_packet[UDP].dport, dport=request_packet[UDP].sport) /
            DNS(
                id=request_packet[DNS].id,
                qr=1,
                opcode=request_packet[DNS].opcode,
                rcode=4,
                qd=request_packet[DNS].qd
            )
        )

    def _build_nxdomain_response(self, request_packet: Ether) -> Ether:
        """
        Builds a DNS NXDOMAIN (RCODE=3) response to a given DNS query packet.

        Args:
            packet (scapy.Packet): Incoming DNS query packet.

        Returns:
            scapy.Packet: Constructed DNS NXDOMAIN response packet.
        """

        return (
            Ether(src=request_packet[Ether].dst, dst=request_packet[Ether].src) /
            IP(src=request_packet[IP].dst, dst=request_packet[IP].src) /
            UDP(sport=request_packet[UDP].dport, dport=request_packet[UDP].sport) /
            DNS(
                id=request_packet[DNS].id,
                qr=1,
                opcode=request_packet[DNS].opcode,
                rcode=3,
                qd=request_packet[DNS].qd
            )
        )

    def _build_servfail_response(self, request_packet: Ether) -> Ether:
        """
        Builds a DNS SERVFAIL (RCODE=2) response to a given DNS query packet.

        Args:
            packet (scapy.Packet): Incoming DNS query packet.
            own_mac (str): MAC address of the DNS server.
            own_ip (str): IP address of the DNS server.
            dns_port (int): DNS server port (default is 53).

        Returns:
            scapy.Packet: Constructed DNS SERVFAIL response packet.
        """

        return (
            Ether(src=request_packet[Ether].dst, dst=request_packet[Ether].src) /
            IP(src=request_packet[IP].dst, dst=request_packet[IP].src) /
            UDP(sport=request_packet[UDP].dport, dport=request_packet[UDP].sport) /
            DNS(
                id=request_packet[DNS].id,
                qr=1,
                opcode=request_packet[DNS].opcode,
                rcode=2,
                qd=request_packet[DNS].qd
            )
        )

    def _build_noerror_response(self, request_packet: Ether, response: Ether) -> Ether:
        """
        Builds a DNS response to a given DNS query packet, reflecting the provided response details.

        Args:
            packet (scapy.Packet): The incoming DNS query packet.
            response (scapy.Packet): The DNS response containing the actual answer, authority, and additional records.
            own_mac (str): MAC address of the DNS server.
            own_ip (str): IP address of the DNS server.
            dns_port (int): DNS server port (default is 53).

        Returns:
            scapy.Packet: Constructed DNS response packet with details.
        """

        return (
            Ether(src=request_packet[Ether].dst, dst=request_packet[Ether].src) /
            IP(src=request_packet[IP].dst, dst=request_packet[IP].src) /
            UDP(sport=request_packet[UDP].dport, dport=request_packet[UDP].sport) /
            DNS(
                id=request_packet[DNS].id,
                qr=1,
                rd=request_packet[DNS].rd,
                ra=1,
                opcode=request_packet[DNS].opcode,
                rcode=response[DNS].rcode,
                qd=request_packet[DNS].qd,
                an=response[DNS].an or None,    # Answer records
                ns=response[DNS].ns or None,    # Authority records
                ar=response[DNS].ar or None     # Additional records
            )
        )

    def _track_received_query_stats(self, packet: Ether) -> None:
        """
        Tracks statistics for DNS query types and unsupported queries.
        """

        DNSStats.increment(key='request_total')

        if self._is_query_blacklisted(packet):
            DNSStats.increment(key='request_blacklisted')

        if DNSUtilities.is_query_type_not_supported(packet):
            DNSStats.increment(key='request_not_supported')
            

        if DNSUtilities.convert_request_type(packet[DNS].qd.qtype):
            DNSStats.increment(key=DNSUtilities.convert_request_type(packet[DNS].qd.qtype))

    def _track_response_stats(self, packet: Ether) -> None:

        DNSStats.increment(key="response_total")
        if packet[DNS].rcode == 0:
            DNSStats.increment(key="response_noerror")
        if packet[DNS].rcode == 2:
            DNSStats.increment(key="response_servfail")
        if packet[DNS].rcode == 3:
            DNSStats.increment(key="response_nxdomain")
        if packet[DNS].rcode == 4:
            DNSStats.increment(key="response_notimp")

    def _is_query_blacklisted(self, packet: Ether) -> bool:
        decoded_query = packet[DNS].qd.qname.decode('utf-8').rstrip('.').lower()
        for _blacklist_rule_raw in self.BLACKLIST:
            blacklist_rule = f"^{_blacklist_rule_raw.strip().lower().replace('*', '.*')}$"
            if re.search(blacklist_rule, decoded_query):
                return True
        return False

    def _get_dns_response(self, request: Ether) -> DNS | None:

        try:
            cached_response = DNSCache.get_cached_response(request[DNS].qd.qname)
        except Exception as e:
            dns_logger.error(f"Error checking cache for {request[DNS].qd.qname}: {e}")
            cached_response = None

        if cached_response:
            try:
                DNSStats.increment(key='cache_hit')
            except Exception as e:
                dns_logger.error(f"Error incrementing cache_hit stats: {str(e)}")
            return cached_response

        try:
            DNSStats.increment(key='cache_miss')
        except Exception as e:
            dns_logger.error(f"Error incrementing cache_miss stats: {str(e)}")

        try:
            external_response = DNSQueries(dns_servers=DEFAULT_DNS_SERVERS).query_best_from_multiple_servers(request[DNS].qd)
        except Exception as e:
            dns_logger.error(f"Error querying upstream DNS servers for {request[DNS].qd.qname}: {str(e)}")
            external_response = None

        if external_response and external_response.haslayer(DNS) and external_response[DNS].rcode == 0:
            try:
                DNSCache.add_to_cache(request[DNS].qd.qname, external_response[DNS])
            except Exception as e:
                dns_logger.error(f"Error adding response to cache for {request[DNS].qd.qname}: {str(e)}")

            try:
                DNSStats.increment(key='external_noerror')
            except Exception as e:
                dns_logger.error(f"Error incrementing external_noerror stats: {str(e)}")

            return external_response[DNS]

        try:
            DNSStats.increment(key='external_failed')
        except Exception as e:
            dns_logger.error(f"Error incrementing external_failed stats: {str(e)}")

        rcode = None
        if external_response and external_response.haslayer(DNS):
            rcode = external_response[DNS].rcode

        dns_logger.warning(f"Query:{request[DNS].qd.qname} id:{request[DNS].id} qtype:{request[DNS].qd.qtype} failed rcode:{rcode}")

        return None

    def _request_processor(self, request: Ether):
        """
        Handles incoming DNS queries.
        If the query is valid, processes it and sends a response back to the client.
        """

        self._track_received_query_stats(request)

        if self._is_query_blacklisted(request):
            self._send_response(self._build_nxdomain_response(request))
            return

        if DNSUtilities.is_query_type_not_supported(request):
            self._send_response(self._build_notimp_response(request))
            return

        response: DNS | None = self._get_dns_response(request)

        if response and response[DNS].rcode == 0:
            self._send_response(self._build_noerror_response(request, response))
            DNSHistory.add_query(request[DNS].qd.qname)
            return

        self._send_response(self._build_servfail_response(request))
        return

    def _is_packet_processable(self, packet: Ether) -> bool:
        if (
            not packet or
            not packet.haslayer(DNS) or
            not DNSUtilities.is_packet_ipv4(packet) or
            not DNSUtilities.is_dns_request_query(packet) or
            not packet[DNS].qd
        ):
            return False

        if packet[IP].src in DEFAULT_DNS_SERVERS or packet[IP].dst in DEFAULT_DNS_SERVERS:
            return False

        return True

    def _filter_and_enqueue_packets(self, packet: Ether) -> None:
        """Enqueue a sniffed DNS packet for processing"""

        try:

            if not self._is_packet_processable(packet):
                return

            _key = (packet[Ether].src, packet[DNS].id)
            if _key in self._inbound_packet_deduplication_queue:
                return
            self._inbound_packet_deduplication_queue.append(_key)

            self._inbound_packet_buffer_queue.put(packet)

        except queue.Full:
            dns_logger.warning(f"packet queue is full")

        except Exception as e:
            dns_logger.warning(f"Failed to enqueue DNS packet: {e}")

    def _send_response(self, reply: Ether) -> None:
        """
        Sends a raw Ethernet packet through the specified network interface.
        """
        self._track_response_stats(reply)
        scapy.sendp(x=reply, iface=self.INTERFACE, verbose=False)
        return

    @staticmethod
    def _queue_worker_timer_calculator(qsize:int = INBOUND_QUEUE_BUFFER_SIZE) -> tuple:
      
        if qsize > INBOUND_QUEUE_BUFFER_SIZE*0.75:
            dns_logger.warning(f"Queue ^75%")
            _loading = 0.25
            return WORKER_QUEUE_EMPTY_TIMEOUT*_loading, WORKER_QUEUE_GET_TIMEOUT*_loading
        
        if qsize > INBOUND_QUEUE_BUFFER_SIZE*0.5:
            dns_logger.warning(f"Queue ^50%")
            _loading = 0.50
            return WORKER_QUEUE_EMPTY_TIMEOUT*_loading, WORKER_QUEUE_GET_TIMEOUT*_loading
        
        if qsize > INBOUND_QUEUE_BUFFER_SIZE*0.25:
            _loading = 0.75
            return WORKER_QUEUE_EMPTY_TIMEOUT*_loading, WORKER_QUEUE_GET_TIMEOUT*_loading
       
        return WORKER_QUEUE_EMPTY_TIMEOUT, WORKER_QUEUE_GET_TIMEOUT

    def service_queue_worker_processor(self) -> None:
        """
        Continuously processes DNS packets from the queue in a dedicated worker thread.

        This worker:
        - Retrieves DNS packets from the thread-safe queue.
        - Passes each packet to the DNS request handler.
        - Logs activity and handles exceptions gracefully.
        - Sleeps briefly to avoid CPU hogging.
        """

        thread_name = threading.current_thread().name
        empty_sleep_timeout,get_timeout = self.__class__._queue_worker_timer_calculator(self._inbound_packet_buffer_queue.qsize())

        while self._running:
            packet = None

            try:
                packet = self._inbound_packet_buffer_queue.get(timeout=get_timeout)
                self._request_processor(packet)
                self._inbound_packet_buffer_queue.task_done()

            except queue.Empty:
                time.sleep(empty_sleep_timeout)

            except Exception as err:
                dns_logger.error(f"{thread_name} processing DNS packet: {str(err)}")
                self._inbound_packet_buffer_queue.task_done()
                time.sleep(WORKER_ERROR_SLEEP_TIMEOUT)

    def service_traffic_listener(self) -> None:
        """ Start sniffing for DNS packets on the interface"""
        while self._running:
            scapy.sniff(
                iface=self.INTERFACE,
                filter="ip and udp dst port 53",
                prn=self._filter_and_enqueue_packets,
                store=False
            )

    def service_control_lists_loader(self) -> None:
        while self._running:
            with self._lock:
                self._load_control_list()
            time.sleep(BLOCKED_LISTS_LOADING_INTERVAL)

    def start(self):
        """Starts the DNS server, listening for DNS queries, and starts the cleanup thread."""

        self._running = True
        dns_logger.info(f"Starting at IFACE:{self.INTERFACE} MAC:{self.OWN_MAC} IP:{self.OWN_IP} PORT:{self.DNS_PORT}")

        with self._lock:
            Services.delete_dns_db_files()
            DNSCache.init()
            DNSStats.init()
            DNSHistory.init()

        traffic_listener = threading.Thread(target=self.service_traffic_listener, name="traffic_listener", daemon=True)
        traffic_listener.start()
        self._threads["traffic_listener"] = traffic_listener

        control_lists_loader = threading.Thread(target=self.service_control_lists_loader, name="control_lists_loader", daemon=True)
        control_lists_loader.start()
        self._threads["control_lists_loader"] = control_lists_loader

        for _index in range(DNS_WORKERS):
            queue_worker = threading.Thread(target=self.service_queue_worker_processor, name=f"queue_worker_{_index}", daemon=True)
            queue_worker.start()
            self._threads[f"queue_worker_{_index}"] = queue_worker

        dns_stats_persistance_thread = threading.Thread(target=Services.db_persistence, name="dns_stats_persistence", daemon=True)
        dns_stats_persistance_thread.start()
        self._threads["db_persistance"] = dns_stats_persistance_thread



        dns_logger.info("Service started")

    def stop_service(self):

        self._running = False

        for thread_name, thread in self._threads.items():
            if thread.is_alive():
                dns_logger.info(f"Stopping thread:{thread_name}")
                thread.join()

        dns_logger.info("All threads stopped, stopping the DNS server")

    def handle_signal(self, signal, frame):
        """Handles termination signals to stop the server gracefully."""
        dns_logger.info(f"Received {signal} stopping server")
        self.stop_service()
        sys.exit(0)


if __name__ == "__main__":

    while True:
        time.sleep(1)
