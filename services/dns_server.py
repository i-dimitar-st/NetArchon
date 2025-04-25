#!/usr/bin/env python3.12

import sqlite3
import time
import queue
import threading
import json
import random
import sys
import logging
import signal
import ipaddress
import re
import scapy.all as scapy
from collections import deque
from scapy.layers.inet import IP, UDP, Ether
from scapy.layers.dns import DNS, DNSRR
from pathlib import Path
from services import MainLogger

dns_logger = MainLogger.get_logger(service_name='DNS', log_level=logging.DEBUG)

DB_CONN_TIMEOUT = 10
DB_CONN_CHECK_SAME_THREAD = False
DB_CONN_ISOLATION_LEVEL = None
DB_CONN_CACHED_STATEMENTS = 100
DB_JOURNAL_MODE = "WAL"
DB_SYNC_MODE = "NORMAL"
DB_CACHE_SIZE = -4*1024
DB_MMAP_SIZE = 24*1024*1024
DB_AUTO_VACCUM = 'INCREMENTAL'

DEFAULT_CACHE_TTL = 10*60
DEFAULT_NEGATIVE_CACHE_TTL = 3*60
DEFAULT_DNS_PORT = 53
DEFAULT_MAC = '00:00:00:00:00:00'
DEFAULT_IP = '0.0.0.0'
DEFAULT_CIDR = '24'
DEFAULT_INTERFACE = 'eth0'
DEFAULT_DNS_SERVER = '94.140.14.15'
DEFAULT_DNS_SERVER_SECONDARY = '9.9.9.9'
DEFAULT_UNSUPPORTED_DNS_QUERY_TYPES = [12, 28, 65]

DEFAULT_DNS_BUFFER_QUEUE_SIZE = 100
DEFAULT_DNS_BUFFER_QUEUE_SIZE_SPEED_INCREASE = 50
DEFAULT_DNS_REQUESTS_DEDUPLICATE_QUEUE_SIZE = 60

DEFAULT_CACHE_REMOVER_PERIOD = 60 * 60 * 1
DEFAULT_CACHE_LOOKBACK_PERIOD = 60 * 60 * 3
DEFAULT_BLOCKED_LISTS_LOADING_PERIOD = 5 * 60

DEFAULT_PACKET_PER_SEC_HIGH_LIMIT = 25
DEFAULT_DNS_WORKER_SLEEP_TIMEOUT = 0.2
DEFAULT_DNS_WORKER_SLEEP_TIMEOUT_FAST = 0.1
DEFAULT_DNS_WORKER_QUEUE_GET_TIMEOUT = 0.2
DEFAULT_DNS_WORKER_THROTTLE_TIMEOUT = 0.05
DEFAULT_DNS_WORKER_THROTTLE_TIMEOUT_FAST = 0.025

ROOT_PATH = Path(__file__).resolve().parents[1]
DNS_CONFIG_PATH = ROOT_PATH / 'config' / 'dns_config.json'
DNS_CONTROL_LIST = ROOT_PATH / 'config' / 'dns_control_list.json'
DB_PATH = ROOT_PATH / 'db'
DB_DNS_FILENAME = 'dns.sqlite3'
DB_DNS = DB_PATH / DB_DNS_FILENAME


class Utiltities:

    @staticmethod
    def delete_dns_db_files() -> None:
        """Deletes files with given suffixes from the base path."""

        dns_logger.debug(f"Deleting DNS DB files ...")
        for file in DB_PATH.iterdir():
            if file.is_file() and file.name.startswith(DB_DNS_FILENAME):
                try:
                    file.unlink()
                    dns_logger.debug(f"{file} deleted.")
                except FileNotFoundError:
                    dns_logger.error(f"{file} does not exist.")

    @staticmethod
    def generate_subnet_from_ip_and_cidr(ip: str, cidr: str) -> ipaddress.IPv4Network:
        """Extracts all A and AAAA record IPs from DNS answer section."""
        return ipaddress.ip_network(f"{ip}/{cidr}", strict=False)

    @staticmethod
    def get_connection_settings() -> dict:
        return {
            'database': DB_DNS,
            'check_same_thread': DB_CONN_CHECK_SAME_THREAD,
            'timeout': DB_CONN_TIMEOUT,
            'isolation_level': DB_CONN_ISOLATION_LEVEL,
            'cached_statements': DB_CONN_CACHED_STATEMENTS
        }

    @staticmethod
    def create_db():

        DB_PATH.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(DB_DNS) as conn:
            conn.execute(f"PRAGMA journal_mode = {DB_JOURNAL_MODE}")
            conn.execute(f"PRAGMA synchronous = {DB_SYNC_MODE}")
            conn.execute(f"PRAGMA cache_size = {DB_CACHE_SIZE}")
            conn.execute(f"PRAGMA mmap_size = {DB_MMAP_SIZE}")
            conn.execute(f"PRAGMA auto_vacuum = {DB_AUTO_VACCUM}")


class DNSUtilities:

    @staticmethod
    def is_packet_ipv4(packet: Ether) -> bool:
        return bool(packet[IP].proto == 17)

    @staticmethod
    def is_dns_request_query(packet: DNS) -> bool:
        return bool(packet[DNS].opcode == 0)

    @staticmethod
    def is_query_type_not_supported(packet: DNS) -> bool:
        return bool(packet[DNS].qd.qtype in DEFAULT_UNSUPPORTED_DNS_QUERY_TYPES)

    @staticmethod
    def extract_max_ttl_from_answers(answers: DNSRR) -> int:
        """Extracts and returns the maximum TTL from DNSRR records in the answer chain."""

        max_ttl = DEFAULT_CACHE_TTL
        for answer in answers:
            if isinstance(answer, DNSRR):
                max_ttl = max(DEFAULT_CACHE_TTL, answer.ttl)
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


class DNSCacheStorage:
    _lock = threading.RLock()
    _conn = None
    _cursor = None
    _is_initialised = False

    @classmethod
    def init(cls):

        if cls._is_initialised:
            return

        cls._conn = sqlite3.connect(**Utiltities.get_connection_settings())
        cls._cursor = cls._conn.cursor()
        cls._create_tables()
        cls._is_initialised = True

    @classmethod
    def _create_tables(cls):
        with cls._lock:

            cls._cursor.execute("""
                                CREATE TABLE IF NOT EXISTS cache (
                                query TEXT PRIMARY KEY,
                                response BLOB,
                                expiration INTEGER,
                                query_times INTEGER DEFAULT 0)""")

            cls._cursor.execute("""CREATE INDEX IF NOT EXISTS idx_cache_query ON cache(query)""")
            cls._cursor.execute("""CREATE INDEX IF NOT EXISTS idx_cache_expiration ON cache(expiration)""")
            cls._cursor.execute("""
                                CREATE TABLE IF NOT EXISTS negative_cache (
                                query TEXT PRIMARY KEY,
                                expiration INTEGER,
                                query_times INTEGER DEFAULT 0)""")

            cls._cursor.execute("""CREATE INDEX IF NOT EXISTS idx_negative_cache_query ON negative_cache(query)""")
            cls._cursor.execute("""CREATE INDEX IF NOT EXISTS idx_negative_cache_expiration ON negative_cache(expiration)""")
            cls._conn.commit()

    @classmethod
    def add_to_cache(cls, query: bytes, response: DNS):

        if not response[DNS].an:
            dns_logger.warning(f"Answer field missing for query:{query}")
            return

        ttl_max: int = DNSUtilities.extract_max_ttl_from_answers(response[DNS].an)
        expiration = int(time.time() + ttl_max)
        decoded_query = query.decode('utf-8', errors='ignore')
        with cls._lock:
            cls._cursor.execute("""
                INSERT INTO cache (query, response, expiration, query_times)
                VALUES (?, ?, ?, 1)
                ON CONFLICT(query) DO UPDATE SET
                    response = excluded.response,
                    expiration = excluded.expiration,
                    query_times = cache.query_times + 1
            """, (decoded_query, bytes(response), expiration))
            cls._conn.commit()

    @classmethod
    def add_to_negative_cache(cls, query: bytes):
        dns_logger.debug(f"adding to negative cache {query}")

        with cls._lock:
            decoded_query = query.decode('utf-8', errors='ignore')
            expiry = int(time.time() + DEFAULT_NEGATIVE_CACHE_TTL)
            cls._cursor.execute("""
                                INSERT INTO negative_cache (query, expiration, query_times)
                                VALUES (?, ?, 1)
                                ON CONFLICT(query) DO UPDATE SET
                                    expiration = excluded.expiration,
                                    query_times = negative_cache.query_times + 1
                               """, (decoded_query, expiry))
            cls._conn.commit()

    @classmethod
    def get_cached_response(cls, query: bytes) -> tuple[DNS | None, bool]:
        """Fetches the cached response if valid and not expired."""

        with cls._lock:
            decoded_query = query.decode('utf-8', errors='ignore')
            cls._cursor.execute("""
                                SELECT response, expiration
                                FROM cache
                                WHERE query=?
                                """, (decoded_query,))
            result = cls._cursor.fetchone()

            if result:
                response, expiration = result
                if int(time.time()) > expiration:
                    return None, False
                else:
                    return DNS(response), True

            return None, False

    @classmethod
    def is_query_in_negative_cache(cls, query: bytes) -> bool:
        """Checks if a query has been negatively cached (NXDOMAIN response)."""

        with cls._lock:
            decoded_query = query.decode('utf-8', errors='ignore')
            cls._cursor.execute("""
                                SELECT expiration
                                FROM negative_cache
                                WHERE query=?
                                """, (decoded_query,))
            result = cls._cursor.fetchone()

            if result:
                if int(time.time()) > result[0]:
                    return False
                else:
                    return True

        return False

    @classmethod
    def delete_stale_caches(cls):
        while True:
            time.sleep(DEFAULT_CACHE_REMOVER_PERIOD)
            try:
                with cls._lock:

                    lookback = int(time.time() - DEFAULT_CACHE_LOOKBACK_PERIOD)
                    cls._cursor.execute(
                        """
                        DELETE
                        FROM cache
                        WHERE expiration < ?
                        """, (lookback,))
                    cache_deleted = cls._cursor.rowcount

                    cls._cursor.execute(
                        """
                        DELETE
                        FROM negative_cache
                        WHERE expiration < ?
                        """, (lookback,))
                    negative_deleted = cls._cursor.rowcount

                    cls._conn.commit()

                    dns_logger.debug(
                        f"[{threading.current_thread().name}] cache_cleaned:{cache_deleted} negative_cache_cleaned:{negative_deleted}")

            except Exception as e:
                dns_logger.debug(f"[Stale Cache Cleaner ERROR] {e}")

    @classmethod
    def close(cls):
        with cls._lock:
            if cls._conn:
                cls._cursor.close()
                cls._conn.close()
                cls._cursor = None
                cls._conn = None


class DNSHistoryStorage:
    _lock = threading.RLock()
    _conn = None
    _cursor = None

    @classmethod
    def init(cls):
        """Initializes the class-level SQLite connection and cursor."""

        cls._conn = sqlite3.connect(**Utiltities.get_connection_settings())
        cls._cursor = cls._conn.cursor()
        cls._create_table()

    @classmethod
    def _create_table(cls):
        """Creates the history table if it doesn't already exist."""

        with cls._lock:
            cls._cursor.execute("""
                                CREATE TABLE IF NOT EXISTS history (
                                query TEXT NOT NULL PRIMARY KEY,
                                query_times INTEGER NOT NULL DEFAULT 0,
                                active INTEGER NOT NULL DEFAULT 1 )""")
            cls._cursor.execute("""CREATE INDEX IF NOT EXISTS idx_query ON history(query)""")
            cls._conn.commit()

    @classmethod
    def add_query(cls, query: bytes, active: int = 0):
        """Adds a query to the history or increments its counter if it already exists, and updates the active status."""
        decoded_query = query.decode('utf-8', errors='ignore').rstrip('.').lower()
        with cls._lock:
            cls._cursor.execute("""
                                INSERT INTO history (query, active, query_times)
                                VALUES (?, ?, 1)
                                ON CONFLICT (query) DO UPDATE SET
                                    query_times = history.query_times + 1,
                                    active = excluded.active
                                """, (decoded_query, active))
            cls._conn.commit()

    @classmethod
    def close(cls):
        with cls._lock:
            if cls._conn:
                cls._cursor.close()
                cls._conn.close()
                cls._cursor = None
                cls._conn = None


class DNSStatsStorage:
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

        cls._conn = sqlite3.connect(**Utiltities.get_connection_settings())
        cls._cursor = cls._conn.cursor()
        cls._create_table()
        cls._init_table()
        cls._is_initialised = True

    @classmethod
    def _create_table(cls):
        with cls._lock:
            cls._valid_columns = set([
                'id',
                'last_updated',
                'response_noerror',
                'response_nxdomain',
                'response_notimp',
                'response_servfail',
                'response_failure',
                'request_total',
                'request_not_supported',
                'request_blacklisted',
                'request_type_a',
                'request_type_aaaa',
                'request_type_ptr',
                'request_type_mx',
                'request_type_https',
                'request_type_any',
                'cache_hit',
                'cache_negative_hit',
                'cache_miss',
                'external_noerror',
                'external_nxdomain',
                'external_servfail',
                'external_failure'
            ])

            cls._cursor.execute("""
                CREATE TABLE IF NOT EXISTS stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    last_updated TEXT DEFAULT CURRENT_TIMESTAMP,
                    response_noerror INTEGER DEFAULT 0,
                    response_nxdomain INTEGER DEFAULT 0,
                    response_notimp INTEGER DEFAULT 0,
                    response_servfail INTEGER DEFAULT 0,
                    response_failure INTEGER DEFAULT 0,
                    request_total INTEGER DEFAULT 0,
                    request_blacklisted INTEGER DEFAULT 0,
                    request_not_supported INTEGER DEFAULT 0,
                    request_type_a INTEGER DEFAULT 0,
                    request_type_aaaa INTEGER DEFAULT 0,
                    request_type_ptr INTEGER DEFAULT 0,
                    request_type_mx INTEGER DEFAULT 0,
                    request_type_https INTEGER DEFAULT 0,
                    request_type_any INTEGER DEFAULT 0,
                    cache_hit INTEGER DEFAULT 0,
                    cache_negative_hit INTEGER DEFAULT 0,
                    cache_miss INTEGER DEFAULT 0,
                    external_noerror INTEGER DEFAULT 0,
                    external_nxdomain INTEGER DEFAULT 0,
                    external_servfail INTEGER DEFAULT 0,
                    external_failure INTEGER DEFAULT 0
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
        """Validates that the key exists as a column in the `stats` table."""
        return key in cls._valid_columns

    @classmethod
    def increment(cls, key: str, count: int = 1):

        if not cls._is_key_valid(key):
            dns_logger.warning(f"[DNSSTATSDB] Invalid key: {key}")
            return

        with cls._lock:
            cls._cursor.execute(f"""
                                UPDATE stats
                                SET
                                    {key} = {key} + ?,
                                    last_updated = CURRENT_TIMESTAMP
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


class DNSServer:
    """
    A DNS server that processes incoming DNS queries, caches responses, and forwards queries to upstream DNS servers.
    """

    def __init__(self):
        """
        Initializes the DNS server, loads the configuration, and sets up the SQLite database.
        """
        self._running = True
        self.lock = threading.RLock()
        self.conn = None
        self.cursor = None
        self.dns_packet_queue = queue.Queue(maxsize=DEFAULT_DNS_BUFFER_QUEUE_SIZE)
        self._dns_deduplication_queue = deque(maxlen=DEFAULT_DNS_REQUESTS_DEDUPLICATE_QUEUE_SIZE)
        self._packet_hit_rate = deque(maxlen=DEFAULT_DNS_REQUESTS_DEDUPLICATE_QUEUE_SIZE)
        self.threads = {}
        self._initialize_config()
        self._load_control_list()

    def _initialize_config(self):
        """Loads configuration from a JSON file."""
        with self.lock:
            try:
                with open(DNS_CONFIG_PATH, "r") as file_handle:
                    _config = json.load(file_handle)
                    self.INTERFACE = _config.get("server.interface", DEFAULT_INTERFACE)
                    self.OWN_IP = _config.get("server.ip", DEFAULT_IP)
                    self.OWN_MAC = _config.get("server.mac", DEFAULT_MAC)
                    self.OWN_CIDR = _config.get("server.subnet", DEFAULT_CIDR)
                    self.DNS_PORT = _config.get("server.port.dns", DEFAULT_DNS_PORT)
                    self.UPSTREAM_DNS = _config.get("upstream.ip", DEFAULT_DNS_SERVER)
                    self.CACHE_TTL = _config.get("dns.cache.ttl", DEFAULT_CACHE_TTL)
                    self.NEGATIVE_TTL = _config.get("dns.ncache.ttl", DEFAULT_NEGATIVE_CACHE_TTL)

            except Exception as err:
                dns_logger.error(f'Error processing config file: {str(err)}')

    def _load_control_list(self):
        """Loads control list from a JSON file."""
        with self.lock:
            try:
                with open(DNS_CONTROL_LIST, "r") as file_handle:
                    _control_list = json.load(file_handle)
                    self.WHITELIST = _control_list.get("whitelist", [])
                    self.BLACKLIST = _control_list.get("blacklist", [])

            except Exception as err:
                dns_logger.error(f'Error processing control lists file: {str(err)}')

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
                qr=1,                          # Response
                opcode=request_packet[DNS].opcode,     # Same as query opcode
                rcode=3,                       # NXDOMAIN (Non-Existent Domain)
                qd=request_packet[DNS].qd
            )
        )

    def _build_dns_servfail_response(self, request_packet: Ether) -> Ether:
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
                rcode=2,  # SERVFAIL
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
                id=request_packet[DNS].id,             # Request ID
                qr=1,                          # This is a response
                rd=request_packet[DNS].rd,             # Recursion Desired
                ra=1,                          # Recursion Available (optional)
                opcode=request_packet[DNS].opcode,     # Mirror client's opcode
                rcode=response[DNS].rcode,     # Response code from the actual response
                qd=request_packet[DNS].qd,             # Echo back the question part
                an=response[DNS].an or None,    # Answer records
                ns=response[DNS].ns or None,    # Authority records
                ar=response[DNS].ar or None     # Additional records
            )
        )

    def _query_external_dns_server(self, packet: Ether) -> IP | None:
        """
        Forwards the DNS query to an external DNS server and returns the response if valid.
        Handles different DNS response scenarios and error logging.
        """
        try:
            response = scapy.sr1(
                IP(dst=self.UPSTREAM_DNS, src=self.OWN_IP) /
                UDP(sport=DNSUtilities.generate_random_port(), dport=53) /
                DNS(id=packet[DNS].id, rd=1, qd=packet[DNS].qd, aa=0),
                verbose=0, retry=0, timeout=5, iface=self.INTERFACE
            )

            if response:
                rcode = response[DNS].rcode

                if rcode in [0, 2, 3, 4, 5]:
                    return response

            dns_logger.warning(f"{self.UPSTREAM_DNS} failed to respond qname:{packet[DNS].qd.qname}")
            return None

        except Exception as err:
            dns_logger.error(f"{self.UPSTREAM_DNS} timedout {str(err)}")
            return None

    def _is_query_blacklisted(self, query: bytes) -> bool:
        decoded_query = query.decode('utf-8').rstrip('.').lower()
        for blacklist_rule in self.BLACKLIST:
            if re.search(blacklist_rule, decoded_query):
                return True
        return False

    def _process_query(self, packet: Ether) -> DNS | None:
        """
        Processes an incoming DNS query:
        - Checks if a response is cached.
        - If no cache hit, forwards the query to an upstream DNS server.
        - Caches only successful responses before returning.
        """

        query_name = packet[DNS].qd.qname

        cached_response, cached_response_is_valid = DNSCacheStorage.get_cached_response(query_name)
        if cached_response and cached_response_is_valid:
            DNSStatsStorage.increment(key='cache_hit')
            return cached_response

        if DNSCacheStorage.is_query_in_negative_cache(query_name):
            DNSStatsStorage.increment(key='cache_negative_hit')
            return None

        DNSStatsStorage.increment(key='cache_miss')

        external_response = self._query_external_dns_server(packet)

        if external_response:
            rcode = external_response[DNS].rcode

            if rcode == 0 and external_response[DNS].an:
                DNSCacheStorage.add_to_cache(query_name, external_response[DNS])
                DNSStatsStorage.increment(key='external_noerror')
                return external_response[DNS]

            elif rcode == 2:  # 2 = SERVFAIL
                DNSCacheStorage.add_to_negative_cache(query_name)
                DNSStatsStorage.increment(key='external_servfail')
                dns_logger.warning(f"[DNSQUERY] {query_name} SERVFAIL")
                return None

            elif rcode in [3, 4, 5]:  # 3 = NXDOMAIN, 4 = NOTIMP, 5 = REFUSED
                DNSCacheStorage.add_to_negative_cache(query_name)
                DNSStatsStorage.increment(key='external_nxdomain')
                dns_logger.warning(f"[DNSQUERY] {query_name} rcode:{rcode}")
                return external_response[DNS]

        DNSCacheStorage.add_to_negative_cache(query_name)
        DNSStatsStorage.increment(key='external_failure')
        dns_logger.warning(f"[DNSQUERY] {query_name} timeout")
        return None

    def _send_packet(self, reply: Ether) -> None:
        """
        Sends a raw Ethernet packet through the specified network interface.

        Args:
            reply (Ether): The Scapy Ethernet packet to be sent.

        Returns:
            None
        """
        self._track_response_stats(reply)
        scapy.sendp(x=reply, iface=self.INTERFACE, verbose=False)

        return

    def _track_query_stats(self, packet: Ether) -> None:
        """
        Tracks statistics for DNS query types and unsupported queries.

        Args:
            qtype (int): The DNS query type (e.g., 1 for A, 28 for AAAA).

        Returns:
            None
        """
        DNSStatsStorage.increment(key='request_total')

        query_type_map = {
            1: 'request_type_a',
            12: 'request_type_ptr',
            15: 'request_type_mx',
            28: 'request_type_aaaa',
            65: 'request_type_https',
            255: 'request_type_any',
        }

        qtype = packet[DNS].qd.qtype

        if self._is_query_blacklisted(packet[DNS].qd.qname):
            DNSStatsStorage.increment(key='request_blacklisted')

        if qtype in DEFAULT_UNSUPPORTED_DNS_QUERY_TYPES:
            DNSStatsStorage.increment(key='request_not_supported')

        if qtype in query_type_map:
            DNSStatsStorage.increment(key=query_type_map[qtype])

    def _track_response_stats(self, packet: Ether) -> None:

        rcode = packet[DNS].rcode
        if rcode == 0:
            DNSStatsStorage.increment(key='response_noerror')
        if rcode == 2:
            DNSStatsStorage.increment(key='response_servfail')
        if rcode == 3:
            DNSStatsStorage.increment(key='response_nxdomain')
        if rcode == 4:
            DNSStatsStorage.increment(key='response_notimp')

    def _handle_dns_request(self, packet: Ether):
        """
        Handles incoming DNS queries.
        If the query is valid, processes it and sends a response back to the client.
        """

        self._track_query_stats(packet)
        is_query_active = 0

        if DNSUtilities.is_query_type_not_supported(packet):
            reply = self._build_notimp_response(packet)
            self._send_packet(reply)
            return

        if self._is_query_blacklisted(packet[DNS].qd.qname):
            reply = self._build_nxdomain_response(packet)
            self._send_packet(reply)
            return

        response: DNS | None = self._process_query(packet)
        reply = None

        if not response:
            reply = self._build_dns_servfail_response(packet)
        elif response[DNS].rcode == 0:
            is_query_active = 1
            reply = self._build_noerror_response(packet, response)
        elif response[DNS].rcode == 3:
            reply = self._build_nxdomain_response(packet)
        elif response[DNS].rcode == 4:
            reply = self._build_notimp_response(packet)

        DNSHistoryStorage.add_query(packet[DNS].qd.qname, is_query_active)

        if reply:
            self._send_packet(reply)
        else:
            dns_logger.debug(f"DNS response was not matched rcode:{response[DNS].rcode}")

    def service_worker_processor(self) -> None:
        """
        Continuously processes DNS packets from the queue in a dedicated worker thread.

        This worker:
        - Retrieves DNS packets from the thread-safe queue.
        - Passes each packet to the DNS request handler.
        - Logs activity and handles exceptions gracefully.
        - Sleeps briefly to avoid CPU hogging.
        """

        thread_name = threading.current_thread().name
        dns_logger.debug(f"{thread_name} started")

        while self._running:

            increase_speed = bool(self.dns_packet_queue.qsize() > DEFAULT_DNS_BUFFER_QUEUE_SIZE_SPEED_INCREASE)
            if increase_speed:
                dns_logger.debug(f"Queue is getting full increasing processing speed")
            try:
                packet = self.dns_packet_queue.get(timeout=DEFAULT_DNS_WORKER_QUEUE_GET_TIMEOUT)
                self._handle_dns_request(packet)
                self.dns_packet_queue.task_done()

                # print(f"{thread_name} Processed DNS_id:{packet[DNS].id}")
                time.sleep(DEFAULT_DNS_WORKER_THROTTLE_TIMEOUT_FAST if increase_speed else DEFAULT_DNS_WORKER_THROTTLE_TIMEOUT)

            except queue.Empty:
                time.sleep(DEFAULT_DNS_WORKER_SLEEP_TIMEOUT_FAST if increase_speed else DEFAULT_DNS_WORKER_SLEEP_TIMEOUT)

            except Exception as err:
                dns_logger.error(f"{thread_name} processing DNS packet:{str(err)}")
                time.sleep(DEFAULT_DNS_WORKER_SLEEP_TIMEOUT)

    def _is_incoming_packet_congestable(self, packet: Ether) -> bool:
        if (
            not packet or
            not packet.haslayer(DNS) or
            not DNSUtilities.is_packet_ipv4(packet) or
            not DNSUtilities.is_dns_request_query(packet)
        ):
            return False

        subnet = Utiltities.generate_subnet_from_ip_and_cidr(self.OWN_IP, self.OWN_CIDR)

        if (
            ipaddress.ip_address(packet[IP].src) not in subnet or
            ipaddress.ip_address(packet[IP].dst) not in subnet or
            packet[IP].src == self.OWN_IP
        ):
            return False

        return True

    def _enqueue_dns_packet(self, packet: Ether) -> None:
        """Enqueue a sniffed DNS packet for processing"""

        try:
            if not self._is_incoming_packet_congestable(packet):
                return

            self._packet_hit_rate.appendleft(packet.time)

            if self.dns_packet_queue.full():
                raise queue.Full("DNS packet queue is full")

            key = (
                packet[IP].src,
                packet[DNS].id,
                packet[DNS].qd.qtype,
                str(packet[DNS].qd.qname)
            )

            if key in self._dns_deduplication_queue:
                return

            self._dns_deduplication_queue.appendleft(key)
            self.dns_packet_queue.put(packet)

            average_per_sec = 0
            if len(self._packet_hit_rate) > 1:
                time_delta = abs(self._packet_hit_rate[-1] - self._packet_hit_rate[0])
                average_per_sec = len(self._packet_hit_rate) / time_delta

            if average_per_sec > DEFAULT_PACKET_PER_SEC_HIGH_LIMIT:
                dns_logger.warning(f"Average packet per sec > {average_per_sec}")

            # print(f"received {round(average_per_min, 2)} id:{packet[DNS].id} src:{packet[IP].src} dst:{packet[IP].dst} queue:{self.dns_packet_queue.qsize()}")

        except queue.Full:
            dns_logger.warning(f"packet queue is full")

        except Exception as e:
            dns_logger.warning(f"Failed to enqueue DNS packet: {e}")

    def service_traffic_listener(self) -> None:
        """ Start sniffing for DNS packets on the interface"""
        while self._running:
            scapy.sniff(
                iface=self.INTERFACE,
                filter="ip and udp dst port 53",
                prn=self._enqueue_dns_packet,
                store=False
            )

    def service_block_lists_loader(self) -> None:
        while self._running:
            with self.lock:
                self._load_control_list()
            time.sleep(DEFAULT_BLOCKED_LISTS_LOADING_PERIOD)

    def start(self):
        """Starts the DNS server, listening for DNS queries, and starts the cleanup thread."""

        self._running = True
        dns_logger.info(f"Starting at IFACE:{self.INTERFACE} MAC:{self.OWN_MAC} IP:{self.OWN_IP} PORT:{self.DNS_PORT}")

        Utiltities.delete_dns_db_files()
        Utiltities.create_db()
        DNSHistoryStorage.init()
        DNSStatsStorage.init()
        DNSCacheStorage.init()

        dns_service_listener = threading.Thread(target=self.service_traffic_listener, name="listener", daemon=True)
        dns_service_listener.start()
        self.threads["listener"] = dns_service_listener

        control_lists_loader = threading.Thread(target=self.service_block_lists_loader, name="control_lists_loader", daemon=True)
        control_lists_loader.start()
        self.threads["control_lists_loader"] = dns_service_listener

        for i in range(5):
            queue_worker = threading.Thread(target=self.service_worker_processor, name=f"queue_worker_{i}", daemon=True)
            queue_worker.start()
            self.threads[f"queue_worker_{i}"] = queue_worker

        dns_stale_cache_remover = threading.Thread(target=DNSCacheStorage.delete_stale_caches,
                                                   name="stale_cache_remover", daemon=True)
        dns_stale_cache_remover.start()
        self.threads[f"stale_cache_remover"] = dns_stale_cache_remover

        dns_logger.info("Service started")

    def stop_server(self):
        """Sets running to False to stop the DNS server gracefully."""
        self._running = False

        for thread_name, thread in self.threads.items():
            if thread.is_alive():
                dns_logger.info(f"Stopping thread: {thread_name}")
                thread.join()

        dns_logger.info("All threads stopped, stopping the DNS server")

    def handle_signal(self, signal, frame):
        """Handles termination signals to stop the server gracefully."""
        dns_logger.info(f"Received {signal} stopping server")
        self.stop_server()
        sys.exit(0)


if __name__ == "__main__":

    # dns_server = DNSServer()
    # dns_server.start()

    while True:
        time.sleep(1)
