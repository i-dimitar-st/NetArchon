#!/usr/bin/env python3.12

import sqlite3
import time
import queue
import threading
import json
import random
import sys
import signal
import ipaddress
import re
import random
import threading
from concurrent.futures import ThreadPoolExecutor, Future
import scapy.all as scapy
from typing import Optional
from collections import deque
from scapy.layers.inet import IP, UDP, Ether
from scapy.layers.dns import DNS, DNSRR
from pathlib import Path
from services import MainLogger

dns_logger = MainLogger.get_logger(service_name="DNS", log_level="debug")

DEFAULT_DNS_PORT = 53
ROOT_PATH = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT_PATH / 'config'
DNS_CONFIG_FULLPATH = CONFIG_PATH / 'config.json'
DNS_CONTROL_LIST_FULL_PATH = CONFIG_PATH / 'dns_control_list.json'
DNS_DB_PATH = ROOT_PATH / 'db'
DNS_DB_FILENAME = 'dns.sqlite3'
DNS_DB_FULLPATH = DNS_DB_PATH / DNS_DB_FILENAME

DB_CONN_TIMEOUT = 10
DB_CONN_CHECK_SAME_THREAD = False
DB_CONN_ISOLATION_LEVEL = None
DB_CONN_CACHED_STATEMENTS = 100

DB_JOURNAL_MODE = "WAL"
DB_SYNC_MODE = "NORMAL"
DB_CACHE_SIZE = -8192   # 8KB
DB_MMAP_SIZE = 25165824  # 24MB
DB_AUTO_VACCUM = 'INCREMENTAL'

DEFAULT_MAC = '00:00:00:00:00:00'
DEFAULT_IP = '0.0.0.0'
DEFAULT_CIDR = '24'
DEFAULT_INTERFACE = 'eth0'
DEFAULT_DNS_SERVER = '94.140.14.15'
DEFAULT_DNS_SERVERS = ["1.1.1.3", "9.9.9.9", "185.228.168.9"]
DEFAULT_DNS_TIMEOUT = 5

DEFAULT_CACHE_TTL = 10*60
NEGATIVE_DEFAULT_CACHE_TTL = 10*60
CACHE_EXPIRY_GRACE = 30*60
UNSUPPORTED_QUERY_TYPES = [12, 28, 65]
BLOCKED_LISTS_LOADING_PERIOD = 5 * 60
DB_MAX_HISTORY_SIZE = 1000

INBOUND_QUEUE_BUFFER_SIZE = 100
INBOUND_QUEUE_BUFFER_LIMIT = 50
INBOUND_REQUESTS_DEDUPLICATE_QUEUE_SIZE = 50
DEDUPLICATION_TIME_BUFFER_SEC = 60
INBOUND_PACKET_HIGH_LIMIT = 100

WORKER_QUEUE_GET_TIMEOUT = 0.4
WORKER_QUEUE_EMPTY_SLEEP_TIMEOUT = 0.1
WORKER_ERROR_SLEEP_TIMEOUT = 0.1


class Utilities:

    @staticmethod
    def delete_dns_db_files() -> None:
        """Deletes files with given suffixes from the base path."""

        dns_logger.debug(f"Deleting DNS DB files ...")
        for file in DNS_DB_PATH.iterdir():
            if file.is_file() and file.name.startswith(DNS_DB_FILENAME):
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
            'database': DNS_DB_FULLPATH,
            'check_same_thread': DB_CONN_CHECK_SAME_THREAD,
            'timeout': DB_CONN_TIMEOUT,
            'isolation_level': DB_CONN_ISOLATION_LEVEL,
            'cached_statements': DB_CONN_CACHED_STATEMENTS
        }

    @staticmethod
    def create_db():
        DNS_DB_PATH.mkdir(parents=True, exist_ok=True)
        sqlite3.connect(DNS_DB_FULLPATH).close()

    @staticmethod
    def enrich_connection(connection: sqlite3.Connection):
        connection.execute(f"PRAGMA journal_mode = {DB_JOURNAL_MODE}")
        connection.execute(f"PRAGMA synchronous = {DB_SYNC_MODE}")
        connection.execute(f"PRAGMA cache_size = {DB_CACHE_SIZE}")
        connection.execute(f"PRAGMA mmap_size = {DB_MMAP_SIZE}")
        connection.execute(f"PRAGMA auto_vacuum = {DB_AUTO_VACCUM}")
        return connection


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
    def convert_request_type(request_type: int = 1):
        query_type_map = {
            1: 'request_type_a',
            2: 'request_type_ns',
            5: 'request_type_cname',
            6: 'request_type_soa',
            12: 'request_type_ptr',
            15: 'request_type_mx',
            16: 'request_type_txt',
            28: 'request_type_aaaa',
            33: 'request_type_srv',
            65: 'request_type_https',
            255: 'request_type_any'
        }
        return query_type_map.get(request_type, None)


class DNSCacheStorage:

    _lock = threading.RLock()
    _conn = None
    _cursor = None
    _running = False

    @classmethod
    def init(cls):

        if cls._running:
            return

        cls._running = True
        cls._conn = Utilities.enrich_connection(sqlite3.connect(**Utilities.get_connection_settings()))
        cls._cursor = cls._conn.cursor()
        cls._create_tables()
        cls._create_triggers()

    @classmethod
    def _create_tables(cls):

        if not cls._running:
            return
        
        with cls._lock:
            cls._cursor.execute("""
                                CREATE TABLE IF NOT EXISTS cache (
                                query BLOB PRIMARY KEY,
                                response BLOB NOT NULL,
                                created INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),
                                modified INTEGER,
                                expiration INTEGER NOT NULL,
                                update_counter INTEGER DEFAULT 0)""")

            cls._cursor.execute("CREATE INDEX IF NOT EXISTS idx_cache_query ON cache(query)")
            cls._cursor.execute("CREATE INDEX IF NOT EXISTS idx_cache_created ON cache(created)")
            cls._cursor.execute("CREATE INDEX IF NOT EXISTS idx_cache_expiration ON cache(expiration)")
            cls._cursor.execute("""
                                CREATE TABLE IF NOT EXISTS negative_cache (
                                query BLOB PRIMARY KEY,
                                created INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),
                                modified INTEGER,
                                expiration INTEGER NOT NULL,
                                update_counter INTEGER DEFAULT 0)""")

            cls._cursor.execute("CREATE INDEX IF NOT EXISTS idx_negative_cache_query ON negative_cache(query)")
            cls._cursor.execute("CREATE INDEX IF NOT EXISTS idx_negative_cache_created ON negative_cache(created)")
            cls._cursor.execute("CREATE INDEX IF NOT EXISTS idx_negative_cache_expiration ON negative_cache(expiration)")
            cls._conn.commit()

    @classmethod
    def _create_triggers(cls):
        
        if not cls._running:
            return
        
        with cls._lock:

            cls._cursor.execute(f"""
                CREATE TRIGGER IF NOT EXISTS delete_expired_cache
                BEFORE INSERT ON cache
                BEGIN
                    DELETE FROM cache
                    WHERE expiration < CAST(strftime('%s','now') AS INT) - {CACHE_EXPIRY_GRACE};
                END;""")

            cls._cursor.execute(f"""
                CREATE TRIGGER IF NOT EXISTS delete_expired_negative_cache
                BEFORE INSERT ON negative_cache
                BEGIN
                    DELETE FROM negative_cache
                    WHERE expiration < CAST(strftime('%s','now') AS INT) - {CACHE_EXPIRY_GRACE};
                END;""")

            cls._conn.commit()

    @classmethod
    def add_to_cache(cls, query: bytes, response: DNS):

        if not cls._running:
            return

        if not query:
            dns_logger.warning(f"Cannot add to cache, no query")
            return

        if not response[DNS].an:
            dns_logger.warning(f"Cannot add to cache no DNS Answer")
            return

        with cls._lock:
            try:
                ttl_max:int = DEFAULT_CACHE_TTL \
                                if DNSUtilities.extract_max_ttl_from_answers(response) < DEFAULT_CACHE_TTL \
                                else DNSUtilities.extract_max_ttl_from_answers(response) 
                cls._cursor.execute(f"""
                                    INSERT INTO cache (query,response,expiration)
                                    VALUES (?,?,?)
                                    ON CONFLICT(query)
                                    DO UPDATE SET
                                            response = excluded.response,
                                            expiration = excluded.expiration,
                                            modified = CAST(strftime('%s', 'now') AS INTEGER),
                                            update_counter = cache.update_counter + 1
                                    """, (query, bytes(response), ttl_max+int(time.time())))
                cls._conn.commit()
            except Exception as err:
                dns_logger.error(f"Error inserting into cache {query}")

    @classmethod
    def add_to_negative_cache(cls, query: bytes):

        if not cls._running:
            return

        with cls._lock:
            try:

                cls._cursor.execute("""
                                    INSERT INTO negative_cache (query,expiration)
                                    VALUES (?,?)
                                    ON CONFLICT(query)
                                    DO UPDATE SET
                                        expiration = excluded.expiration,
                                        modified = CAST(strftime('%s', 'now') AS INTEGER),
                                        update_counter = negative_cache.update_counter + 1
                                """, (query, int(time.time()+NEGATIVE_DEFAULT_CACHE_TTL)))
                cls._conn.commit()
            except Exception as err:
                dns_logger.error(f"error adding to negative cache {query}")

    @classmethod
    def get_cached_response(cls, query: bytes) -> tuple[DNS | None, bool]:
        """Fetches the cached response if valid and not expired."""

        if not cls._running:
            return
        with cls._lock:
            try:
                cls._cursor.execute("""
                                    SELECT response
                                    FROM cache
                                    WHERE query = ?
                                    AND expiration > CAST(strftime('%s', 'now') AS INTEGER)
                                    """, (query,))
                result = cls._cursor.fetchone()
                if result:
                    return DNS(result[0])
                return None
            except Exception as err:
                dns_logger.error(f"error getting cached response {query},{str(err)}")
                return None

    @classmethod
    def is_query_in_negative_cache(cls, query: bytes) -> bool:
        """Checks if a query has been negatively cached (NXDOMAIN response)."""

        if not cls._running:
            return
        with cls._lock:
            try:
                cls._cursor.execute("""
                                    SELECT expiration
                                    FROM negative_cache
                                    WHERE query=?
                                    AND expiration > CAST(strftime('%s', 'now') AS INTEGER)
                                    """, (query,))
                result = cls._cursor.fetchone()
                if result:
                    return True
                return False
            except Exception as err:
                dns_logger.error(f"error querying negative cache {query} {str(err)}")
                return False

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
    _running = False

    @classmethod
    def init(cls):
        """Initializes the class-level SQLite connection and cursor."""

        if cls._running:
            return

        cls._conn = Utilities.enrich_connection(
            sqlite3.connect(**Utilities.get_connection_settings()))
        cls._cursor = cls._conn.cursor()
        cls._create_table()
        cls._running = True

    @classmethod
    def _create_table(cls):
        """Creates the history table if it doesn't already exist."""

        if cls._running:
            return

        with cls._lock:
            cls._cursor.execute("""
                                CREATE TABLE IF NOT EXISTS history (
                                    query TEXT NOT NULL PRIMARY KEY,
                                    query_counter INTEGER NOT NULL DEFAULT 0,
                                    active INTEGER NOT NULL DEFAULT 1,
                                    created INTEGER NOT NULL)
                                """)
            cls._cursor.execute(f"""
                                CREATE TRIGGER limit_table
                                BEFORE INSERT ON history
                                FOR EACH ROW
                                WHEN (SELECT COUNT(*) FROM history) >= {DB_MAX_HISTORY_SIZE}
                                BEGIN
                                    DELETE FROM history
                                    WHERE created = (SELECT created FROM history ORDER BY created ASC LIMIT 1);
                                END""")
            cls._cursor.execute("CREATE INDEX IF NOT EXISTS idx_query ON history(query)")
            cls._cursor.execute("CREATE INDEX IF NOT EXISTS idx_created ON history(created)")
            cls._cursor.execute("CREATE INDEX IF NOT EXISTS idx_query_counter ON history(query_counter)")
            cls._conn.commit()

    @classmethod
    def add_query(cls, query: bytes, active: int = 1):
        """Adds a query to the history or increments its counter if it already exists, and updates the active status."""

        if not cls._running:
            return

        with cls._lock:
            decoded_query = query.decode('utf-8').rstrip('.').lower()
            cls._cursor.execute("""
                                INSERT INTO history (query,active,query_counter,created)
                                VALUES (?,?,1,?)
                                ON CONFLICT (query) DO UPDATE SET
                                    query_counter = history.query_counter + 1,
                                    active = excluded.active,
                                    created = excluded.created
                                """,(decoded_query, active, int(time.time())))
            cls._conn.commit()

    @classmethod
    def close(cls):
        with cls._lock:
            if cls._conn:
                cls._conn.close()
                cls._conn = None
            if cls._cursor:
                cls._cursor.close()
                cls._cursor = None
            cls._running = False


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

        cls._conn = Utilities.enrich_connection(
            sqlite3.connect(**Utilities.get_connection_settings()))
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
                    start_time TEXT DEFAULT CURRENT_TIMESTAMP,
                    last_updated TEXT DEFAULT CURRENT_TIMESTAMP,
                    request_total INTEGER DEFAULT 0,
                    request_total_valid INTEGER DEFAULT 0,
                    request_blacklisted INTEGER DEFAULT 0,
                    request_not_supported INTEGER DEFAULT 0,
                    request_type_a INTEGER DEFAULT 0,
                    request_type_aaaa INTEGER DEFAULT 0,
                    request_type_ptr INTEGER DEFAULT 0,
                    request_type_mx INTEGER DEFAULT 0,
                    request_type_https INTEGER DEFAULT 0,
                    request_type_cname INTEGER DEFAULT 0,
                    request_type_ns INTEGER DEFAULT 0,
                    request_type_soa INTEGER DEFAULT 0,
                    request_type_txt INTEGER DEFAULT 0,
                    request_type_srv INTEGER DEFAULT 0,
                    request_type_any INTEGER DEFAULT 0,
                    response_total INTEGER DEFAULT 0,
                    response_noerror INTEGER DEFAULT 0,
                    response_nxdomain INTEGER DEFAULT 0,
                    response_notimp INTEGER DEFAULT 0,
                    response_servfail INTEGER DEFAULT 0,
                    response_failure INTEGER DEFAULT 0,
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
            cls._cursor.execute(
                "DELETE FROM sqlite_sequence WHERE name='stats'")
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

        with cls._lock:
            if not cls._is_key_valid(key):
                dns_logger.warning(f"Invalid key: {key}")
                return
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

    def __init__(self):
        """
        Initializes the DNS server, loads the configuration, and sets up the SQLite database.
        """
        self._running = True
        self._lock = threading.RLock()
        self._inbound_packet_buffer_queue = queue.Queue(maxsize=INBOUND_QUEUE_BUFFER_SIZE)
        self._inbound_packet_deduplication_queue = deque(maxlen=INBOUND_REQUESTS_DEDUPLICATE_QUEUE_SIZE)
        self._inbound_packet_timestamps = deque(maxlen=INBOUND_REQUESTS_DEDUPLICATE_QUEUE_SIZE)
        self._threads = {}
        self._initialize_config()
        self._load_control_list()

    def _initialize_config(self):
        """Loads configuration from a JSON file."""
        with self._lock:
            try:
                with open(DNS_CONFIG_FULLPATH, "r") as file_handle:
                    _config = json.load(file_handle)
                    _server = _config.get("server", {})
                    _dns_settings = _config.get("dns", {})
                    self.INTERFACE = _server.get("interface", DEFAULT_INTERFACE)
                    self.OWN_IP = _server.get("ip", DEFAULT_IP)
                    self.OWN_MAC = _server.get("mac", DEFAULT_MAC)
                    self.OWN_CIDR = _server.get("subnet_mask", DEFAULT_CIDR)
                    self.DNS_PORT = _dns_settings.get("port", DEFAULT_DNS_PORT)
                    self.UPSTREAM_DNS = _dns_settings.get("server", DEFAULT_DNS_SERVER)
                    self.DEFAULT_CACHE_TTL = _dns_settings.get("ttl_cache", DEFAULT_CACHE_TTL)
                    self.NEGATIVE_TTL = _dns_settings.get("ttl_cache", NEGATIVE_DEFAULT_CACHE_TTL)
                    self.BLACKLIST = set()
                    self.WHITELIST = set()

            except Exception as err:
                dns_logger.error(f'Error processing config file: {str(err)}')

    def _load_control_list(self):
        """Loads control list from a JSON file."""

        with self._lock:

            try:
                with open(DNS_CONTROL_LIST_FULL_PATH, mode="r", encoding="utf-8") as file_handle:
                    _control_list = json.load(file_handle)
                    _blacklist_urls = set(_control_list.get(
                        "blacklist", {}).get("urls", []))
                    _blacklist_rules = set(_control_list.get(
                        "blacklist", {}).get("rules", []))
                    _blacklist_new = _blacklist_urls | _blacklist_rules
                    _whitelist_new = set(_control_list.get("whitelist", []))
                    if _blacklist_new != self.BLACKLIST or _whitelist_new != self.WHITELIST:
                        self.BLACKLIST = _blacklist_new
                        self.WHITELIST = _whitelist_new
                        dns_logger.debug(
                            f'Loaded blacklist:{len(self.BLACKLIST)} whitelist:{len(self.WHITELIST)}')

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
                qr=1,                          # Response
                opcode=request_packet[DNS].opcode,     # Same as query opcode
                rcode=3,                       # NXDOMAIN (Non-Existent Domain)
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
                # Response code from the actual response
                rcode=response[DNS].rcode,
                # Echo back the question part
                qd=request_packet[DNS].qd,
                an=response[DNS].an or None,    # Answer records
                ns=response[DNS].ns or None,    # Authority records
                ar=response[DNS].ar or None     # Additional records
            )
        )

    def _send_packet(self, reply: Ether) -> None:
        """
        Sends a raw Ethernet packet through the specified network interface.
        """
        self._track_response_stats(reply)
        scapy.sendp(x=reply, iface=self.INTERFACE, verbose=False)
        return

    def _track_received_query_stats(self, packet: Ether) -> None:
        """
        Tracks statistics for DNS query types and unsupported queries.
        """

        DNSStatsStorage.increment(key='request_total_valid')

        if self._is_query_blacklisted(packet):
            DNSStatsStorage.increment(key='request_blacklisted')

        if DNSUtilities.is_query_type_not_supported(packet):
            DNSStatsStorage.increment(key='request_not_supported')

        if DNSUtilities.convert_request_type(packet[DNS].qd.qtype):
            DNSStatsStorage.increment(key=DNSUtilities.convert_request_type(packet[DNS].qd.qtype))

    def _track_response_stats(self, packet: Ether) -> None:

        DNSStatsStorage.increment(key='response_total')
        if packet[DNS].rcode == 0:
            DNSStatsStorage.increment(key='response_noerror')
        if packet[DNS].rcode == 2:
            DNSStatsStorage.increment(key='response_servfail')
        if packet[DNS].rcode == 3:
            DNSStatsStorage.increment(key='response_nxdomain')
        if packet[DNS].rcode == 4:
            DNSStatsStorage.increment(key='response_notimp')

    def _is_query_blacklisted(self, packet: Ether) -> bool:
        decoded_query = packet[DNS].qd.qname.decode('utf-8').rstrip('.').lower()
        for _blacklist_rule_raw in self.BLACKLIST:
            blacklist_rule = f"^{_blacklist_rule_raw.strip().lower().replace('*', '.*')}$"
            if re.search(blacklist_rule, decoded_query):
                return True
        return False

    def _query_individual_dns_server(self, server_ip: str, packet: Ether) -> IP | None:

        try:
            response = scapy.sr1(
                IP(dst=server_ip, src=self.OWN_IP) /
                UDP(sport=DNSUtilities.generate_random_port(), dport=self.DNS_PORT) /
                DNS(id=packet[DNS].id, rd=1, qd=packet[DNS].qd, aa=0),
                verbose=0, retry=0, timeout=DEFAULT_DNS_TIMEOUT, iface=self.INTERFACE
            )

            if not response:
                dns_logger.warning(f"{server_ip} no response {packet[DNS].qd.qname}")
                return None
            
            if response[DNS].rcode != 0:
                dns_logger.warning(f"{server_ip} responded, bad response (rcode={response[DNS].rcode}) {packet[DNS].qd.qname}")
                return None
            
            if not response[DNS].an or response[DNS].ancount < 1:
                dns_logger.warning(f"{server_ip} responded, no answer {packet[DNS].qd.qname}")
                return None
            
            if response[DNS].rcode == 0:
                return response

            dns_logger.warning(f"weird we shouldn't get this")
            return None

        except Exception as e:
            dns_logger.error(f"Error querying {server_ip}: {str(e)}")

        return None

    def _query_multiple_dns_servers(self, packet: Ether) -> Optional[DNSRR]:

        _results = {}
        with ThreadPoolExecutor(max_workers=len(DEFAULT_DNS_SERVERS)) as executor:
            _futures: dict[str, Future] = {
                _ip: executor.submit(self._query_individual_dns_server, _ip, packet)
                for _ip in DEFAULT_DNS_SERVERS
            }
            for _ip, _future in _futures.items():
                _results[_ip] = _future.result()

        _best_response_ttl = 0
        _best_response = None

        for _server_ip, _server_response in _results.items():
            if not _server_response:
                continue

            # We have to iterate through DNSRR like this
            for _index in range(_server_response[DNS].ancount):
                if _server_response[DNS].an[_index].ttl and _server_response[DNS].an[_index].ttl > _best_response_ttl:
                    _best_response_ttl = _server_response[DNS].an[_index].ttl
                    _best_response = _server_response

        if not _best_response:
            dns_logger.warning(f"Weird all external DNS servers failed for {packet[DNS].qd.qname}")
            return None

        return _best_response

    def _process_request(self, packet: Ether) -> DNS | None:
        """
        Processes an incoming DNS query:
        - Checks if a response is cached.
        - If no cache hit, forwards the query to an upstream DNS server.
        - Caches only successful responses before returning.
        """

        query_name = packet[DNS].qd.qname

        cached_response = DNSCacheStorage.get_cached_response(query_name)
        if cached_response:
            DNSStatsStorage.increment(key='cache_hit')
            return cached_response

        if DNSCacheStorage.is_query_in_negative_cache(query_name):
            DNSStatsStorage.increment(key='cache_negative_hit')
            return None

        DNSStatsStorage.increment(key='cache_miss')

        external_response = self._query_multiple_dns_servers(packet)
        if external_response:

            if external_response[DNS].rcode == 0 and external_response[DNS].an:
                DNSCacheStorage.add_to_cache(query_name, external_response[DNS])
                DNSStatsStorage.increment(key='external_noerror')
                return external_response[DNS]

        DNSCacheStorage.add_to_negative_cache(query_name)
        DNSStatsStorage.increment(key='external_failure')
        dns_logger.warning(f"{query_name} failed")
        return None

    def _handle_dns_request(self, packet: Ether):
        """
        Handles incoming DNS queries.
        If the query is valid, processes it and sends a response back to the client.
        """

        self._track_received_query_stats(packet)

        if self._is_query_blacklisted(packet):
            self._send_packet(self._build_nxdomain_response(packet))
            return

        if DNSUtilities.is_query_type_not_supported(packet):
            self._send_packet(self._build_notimp_response(packet))
            return

        response: DNS | None = self._process_request(packet)
        if response is not None:
            rcode = response[DNS].rcode
            match rcode:
                case 0:
                    self._send_packet(
                        self._build_noerror_response(packet, response))
                    DNSHistoryStorage.add_query(packet[DNS].qd.qname)
                case 3:
                    self._send_packet(self._build_nxdomain_response(packet))
                case 4:
                    self._send_packet(self._build_notimp_response(packet))
                case 5:
                    self._send_packet(self._build_servfail_response(packet))
                case default:
                    dns_logger.error(
                        f"Unexpected DNS response code: {rcode} for query: {packet[DNS].qd.qname}")
                    self._send_packet(self._build_servfail_response(packet))
            return

        dns_logger.error(f"{packet[DNS].qd.qname} failed")
        self._send_packet(self._build_servfail_response(packet))

    def _validate_inbound_packet(self, packet: Ether) -> bool:
        if (
            not packet or
            not packet.haslayer(DNS) or
            not DNSUtilities.is_packet_ipv4(packet) or
            not DNSUtilities.is_dns_request_query(packet)
        ):
            return False

        subnet = Utilities.generate_subnet_from_ip_and_cidr(
            self.OWN_IP, self.OWN_CIDR)

        if ipaddress.ip_address(packet[IP].src) not in subnet or ipaddress.ip_address(packet[IP].dst) not in subnet:
            return False

        if self.OWN_IP == packet[IP].src:
            return False

        return True

    def _preprocessor(self, packet: Ether) -> None:
        """Enqueue a sniffed DNS packet for processing"""

        try:

            DNSStatsStorage.increment(key='request_total')
            self._inbound_packet_timestamps.appendleft(packet.time)
            if not self._validate_inbound_packet(packet):
                return

            if self._inbound_packet_buffer_queue.qsize() > INBOUND_REQUESTS_DEDUPLICATE_QUEUE_SIZE/2:
                dns_logger.warning(f"Queue half full")
            if self._inbound_packet_buffer_queue.full():
                raise queue.Full("DNS packet queue is full")

            _time = packet.time // DEDUPLICATION_TIME_BUFFER_SEC
            key = (packet[IP].src, packet[DNS].id, packet[DNS].qd, _time)
            if key in self._inbound_packet_deduplication_queue:
                return

            self._inbound_packet_deduplication_queue.appendleft(key)
            self._inbound_packet_buffer_queue.put(packet)

        except queue.Full:
            dns_logger.warning(f"packet queue is full")

        except Exception as e:
            dns_logger.warning(f"Failed to enqueue DNS packet: {e}")

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

        while self._running:

            try:

                packet = self._inbound_packet_buffer_queue.get(
                    timeout=WORKER_QUEUE_GET_TIMEOUT)
                self._handle_dns_request(packet)
                self._inbound_packet_buffer_queue.task_done()

            except queue.Empty:
                time.sleep(WORKER_QUEUE_EMPTY_SLEEP_TIMEOUT)

            except Exception as err:
                dns_logger.error(
                    f"{thread_name} processing DNS packet:{str(err)}")
                self._inbound_packet_buffer_queue.task_done()
                time.sleep(WORKER_ERROR_SLEEP_TIMEOUT)

    def service_traffic_listener(self) -> None:
        """ Start sniffing for DNS packets on the interface"""
        while self._running:
            scapy.sniff(
                iface=self.INTERFACE,
                filter="ip and udp dst port 53",
                prn=self._preprocessor,
                store=False
            )

    def service_control_lists_loader(self) -> None:
        while self._running:
            with self._lock:
                self._load_control_list()
            time.sleep(BLOCKED_LISTS_LOADING_PERIOD)

    def start(self):
        """Starts the DNS server, listening for DNS queries, and starts the cleanup thread."""

        self._running = True
        dns_logger.info(f"Starting at IFACE:{self.INTERFACE} MAC:{self.OWN_MAC} IP:{self.OWN_IP} PORT:{self.DNS_PORT}")

        Utilities.delete_dns_db_files()
        Utilities.create_db()

        DNSHistoryStorage.init()
        DNSStatsStorage.init()
        DNSCacheStorage.init()

        traffic_listener = threading.Thread(target=self.service_traffic_listener,name="traffic_listener",daemon=True)
        traffic_listener.start()
        self._threads["traffic_listener"] = traffic_listener
#
        control_lists_loader = threading.Thread(target=self.service_control_lists_loader,name="control_lists_loader",daemon=True)
        control_lists_loader.start()
        self._threads["control_lists_loader"] = control_lists_loader

        for _index in range(10):
            queue_worker = threading.Thread(target=self.service_queue_worker_processor,name=f"queue_worker_{_index}",daemon=True)
            queue_worker.start()
            self._threads[f"queue_worker_{_index}"] = queue_worker

        # stale_history_remover = threading.Thread(target=DNSHistoryStorage.service_delete_stale_history_entries,
        #                                          name="stale_history_remover", daemon=True)
        # stale_history_remover.start()
        # self._threads[f"stale_history_remover"] = stale_history_remover

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
