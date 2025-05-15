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
from scapy.all import Ether
from concurrent.futures import ThreadPoolExecutor
import scapy.all as scapy
from collections import deque
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from pathlib import Path
from services.service_logger import MainLogger
from services.dns.dns_utilities import DNSQuery, DNSQueries, extract_min_and_max_ttl
from services.config import Config


dns_logger = MainLogger.get_logger(service_name="DNS", log_level="debug")

ROOT_PATH = Config.get_paths().get("root")
CONFIG_PATH = Config.get_paths().get("config")
DNS_CONTROL_LIST_FULL_PATH = CONFIG_PATH / 'dns_control_list.json'
DNS_DB_PATH = Config.get_paths().get("db")
DNS_DB_FILENAME = 'dns.sqlite3'
DNS_DB_FULLPATH = DNS_DB_PATH / DNS_DB_FILENAME

DB_CONN_TIMEOUT = 30
DB_CONN_CHECK_SAME_THREAD = False
DB_CONN_ISOLATION_LEVEL = None
DB_CONN_CACHED_STATEMENTS = 1000

DB_JOURNAL_MODE = "WAL"
DB_SYNC_MODE = "NORMAL"
DB_CACHE_SIZE = -8192   # 8KB
DB_MMAP_SIZE = 25165824  # 24MB
DB_AUTO_VACCUM = 'INCREMENTAL'

DEFAULT_DNS_SERVER = '94.140.14.15'
DEFAULT_DNS_SERVERS = ["1.1.1.1", "9.9.9.9", "8.8.8.8"]
DEFAULT_DNS_TIMEOUT = 2.5
DEFAULT_DNS_RETRY = 0

DEFAULT_CACHE_TTL = 4*60
NEGATIVE_DEFAULT_CACHE_TTL = 10

UNSUPPORTED_QUERY_TYPES = [12, 28, 65]
BLOCKED_LISTS_LOADING_PERIOD = 5 * 60
DB_MAX_HISTORY_SIZE = 1000

DNS_WORKERS = 50
INBOUND_QUEUE_BUFFER_SIZE = 100
INBOUND_QUEUE_BUFFER_LIMIT = 50
INBOUND_REQUESTS_DEDUPLICATE_QUEUE_SIZE = 50
INBOUND_PACKET_HIGH_LIMIT = 100

WORKER_QUEUE_GET_TIMEOUT = 0.5
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
                                ttl INTEGER DEFAULT 0,
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
                    WHERE expiration < CAST(strftime('%s','now') AS INT);
                END;""")

            cls._cursor.execute(f"""
                CREATE TRIGGER IF NOT EXISTS delete_expired_negative_cache
                BEFORE INSERT ON negative_cache
                BEGIN
                    DELETE FROM negative_cache
                    WHERE expiration < CAST(strftime('%s','now') AS INT);
                END;""")

            cls._conn.commit()

    @classmethod
    def add_to_cache(cls, query: bytes, response: DNS):

        if not cls._running:
            return

        if not query:
            dns_logger.warning(f"Cannot add to cache, no query")
            return

        with cls._lock:
            try:
                min_ttl, max_ttl = extract_min_and_max_ttl(response[DNS].an)
                cls._cursor.execute(f"""
                                    INSERT INTO cache (query,response,expiration,ttl)
                                    VALUES (?,?,?,?)
                                    ON CONFLICT(query)
                                    DO UPDATE SET
                                            response = excluded.response,
                                            expiration = excluded.expiration,
                                            modified = CAST(strftime('%s', 'now') AS INTEGER),
                                            ttl = excluded.ttl,
                                            update_counter = cache.update_counter + 1
                                    """, (query, bytes(response), min_ttl+int(time.time()), min_ttl))
                cls._conn.commit()
            except Exception as err:
                dns_logger.error(f"Error inserting into cache {query}")

    @classmethod
    def add_to_negative_cache(cls, query: bytes):

        if not cls._running:
            return

        with cls._lock:
            try:
                current_time = int(time.time())
                expiration = current_time+NEGATIVE_DEFAULT_CACHE_TTL
                cls._cursor.execute("""
                    INSERT INTO negative_cache (query, expiration, modified, update_counter)
                    VALUES (?, ?, ?, 1)
                    ON CONFLICT(query) DO UPDATE SET
                        update_counter = update_counter + 1,
                        modified = excluded.modified,
                        expiration = excluded.modified + (negative_cache.update_counter * ?)
                """, (query, expiration, current_time, NEGATIVE_DEFAULT_CACHE_TTL))
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
                                """, (decoded_query, active, int(time.time())))
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
                self.OWN_CIDR = _server.get("cidr")
                self.DNS_PORT = _dns.get("port")
                self.UPSTREAM_DNS = _dns.get("server")
                self.UPSTREAM_DNS_SERVER = _dns.get("server")
                self.DEFAULT_CACHE_TTL = _dns.get("ttl_cache")
                self.NEGATIVE_TTL = _dns.get("ttl_cache")
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

        DNSStatsStorage.increment(key='request_total')

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

    def _query_individual_dns_server(self, server_ip: str, request: Ether) -> IP | None:
        """
        Possible rcodes:
            - 0 NOERROR
            - 1 FORMERR
            - 2 SERVFAIL
            - 3 NXDOMAIN
            - 4 NOTIMP
            - 5 REFUSED
        """
        try:
            response = scapy.sr1(
                IP(dst=server_ip, src=self.OWN_IP) /
                UDP(sport=DNSUtilities.generate_random_port(), dport=self.DNS_PORT) /
                DNS(id=request[DNS].id, rd=1, qd=request[DNS].qd, aa=0),
                verbose=0,
                retry=DEFAULT_DNS_RETRY,
                timeout=DEFAULT_DNS_TIMEOUT,
                iface=self.INTERFACE
            )

            if response and response.haslayer(DNS) and response[DNS].qd:
                return response

            dns_logger.warning(f"{server_ip} no response")

        except Exception as e:
            dns_logger.error(f"Error querying {server_ip}: {str(e)}")

        return None

    def _query_multiple_dns_servers(self, packet: Ether) -> Ether | None:

        _results = {}
        with ThreadPoolExecutor(max_workers=len(DEFAULT_DNS_SERVERS)) as executor:
            _futures = {}

            for _ip in DEFAULT_DNS_SERVERS:
                _futures[_ip] = executor.submit(self._query_individual_dns_server, _ip, packet)

            for _ip, _future in _futures.items():
                _results[_ip] = _future.result()

        fallback_response = None

        for response in _results.values():

            if not response or response[DNS].rcode != 0:
                continue

            if response[DNS].ancount > 0:
                return response

            if response[DNS].ancount == 0:
                fallback_response = response
                continue

        return fallback_response

    def _get_dns_response(self, request: Ether) -> DNS | None:
        """
        Processes an incoming DNS query:
        - Checks if a response is cached.
        - If no cache hit, forwards the query to an upstream DNS server.
        - Caches only successful responses before returning.
        """

        cached_response = DNSCacheStorage.get_cached_response(request[DNS].qd.qname)
        if cached_response:
            DNSStatsStorage.increment(key='cache_hit')
            return cached_response

        if DNSCacheStorage.is_query_in_negative_cache(request[DNS].qd.qname):
            DNSStatsStorage.increment(key='cache_negative_hit')
            return None

        DNSStatsStorage.increment(key='cache_miss')

        external_response = DNSQueries(dns_servers=DEFAULT_DNS_SERVERS).query_best_from_multiple_servers(request[DNS].qd)
        # external_response = self._query_multiple_dns_servers(request)
        if external_response and external_response.haslayer(DNS) and external_response[DNS].rcode == 0:
            DNSCacheStorage.add_to_cache(request[DNS].qd.qname, external_response[DNS])
            DNSStatsStorage.increment(key='external_noerror')
            return external_response[DNS]

        # DNSCacheStorage.add_to_negative_cache(query_name)
        DNSStatsStorage.increment(key='external_failure')
        dns_logger.warning(f"{request[DNS].qd.qname} {request[DNS].id} {request[DNS].qd.qtype} failed")
        return None

    def _handle_dns_request(self, request: Ether):
        """
        Handles incoming DNS queries.
        If the query is valid, processes it and sends a response back to the client.
        """

        self._track_received_query_stats(request)

        if self._is_query_blacklisted(request):
            self._send_packet(self._build_nxdomain_response(request))
            return

        if DNSUtilities.is_query_type_not_supported(request):
            self._send_packet(self._build_notimp_response(request))
            return

        response: DNS | None = self._get_dns_response(request)

        if response and response[DNS].rcode == 0:
            self._send_packet(self._build_noerror_response(request, response))
            DNSHistoryStorage.add_query(request[DNS].qd.qname)
            return

        self._send_packet(self._build_servfail_response(request))
        return

    def _is_processable_inbound_packet(self, packet: Ether) -> bool:
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

        # if packet[IP].src == packet[IP].dst:
        #     return False

        return True

    def _preprocessor(self, packet: Ether) -> None:
        """Enqueue a sniffed DNS packet for processing"""

        try:

            if not self._is_processable_inbound_packet(packet):
                return

            _key = (packet[Ether].src, packet[DNS].id)
            if _key in self._inbound_packet_deduplication_queue:
                return
            self._inbound_packet_deduplication_queue.append(_key)

            if self._inbound_packet_buffer_queue.qsize() > INBOUND_REQUESTS_DEDUPLICATE_QUEUE_SIZE*0.5:
                dns_logger.warning(f"Queue 50%")
            if self._inbound_packet_buffer_queue.qsize() > INBOUND_REQUESTS_DEDUPLICATE_QUEUE_SIZE*0.75:
                dns_logger.warning(f"Queue 75%")
            if self._inbound_packet_buffer_queue.qsize() > INBOUND_REQUESTS_DEDUPLICATE_QUEUE_SIZE*0.90:
                dns_logger.warning(f"Queue 90%")

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
            packet = None

            try:
                packet = self._inbound_packet_buffer_queue.get(timeout=WORKER_QUEUE_GET_TIMEOUT)
                self._handle_dns_request(packet)
                self._inbound_packet_buffer_queue.task_done()

            except queue.Empty:
                time.sleep(WORKER_QUEUE_EMPTY_SLEEP_TIMEOUT)

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
