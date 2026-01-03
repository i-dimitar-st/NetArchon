"""GUI and System Utilities Module.

Provides functions and classes for:
- Retrieving system, CPU, memory, disk, and network statistics
- Managing DHCP and DNS service statistics
- Reading and writing whitelist and blacklist rules
- Handling system logs
- Flask utility functions (auth extraction, cache control)
- Network connectivity checks

This module uses:
- psutil for system metrics
- sqlite3 for database access
- scapy and custom DHCP/DNS services for network info
- threading locks for safe concurrent access
"""


from datetime import datetime, timezone
from json import dump, load
from os import getloadavg
from pathlib import Path
from platform import machine, node, processor, release, system
from socket import AF_INET, AF_PACKET, SOCK_STREAM, socket
from sqlite3 import Cursor, Row, connect
from threading import RLock
from time import ctime, time

from flask import Request, Response
from psutil import (
    Process as PsutilProcess,
)
from psutil import (
    boot_time,
    cpu_count,
    cpu_freq,
    disk_partitions,
    disk_usage,
    net_if_addrs,
    net_io_counters,
    sensors_temperatures,
    swap_memory,
    virtual_memory,
)
from psutil import (
    cpu_percent as sys_cpu_percent,
)
from psutil._common import shwtemp, snetio

from src.config.config import config
from src.services.dhcp.dhcp import DHCPServer
from src.services.dhcp.metrics import dhcp_metrics
from src.services.dns.dns import DNSServer
from src.services.dns.metrics import (
    dns_metrics,
    dns_metrics_external,
    dns_per_server_metrics,
    received_metrics,
)
from src.services.gui.metrics import api_metrics, http_response_metrics
from src.services.http_proxy.metrics import http_proxy_metrics
from src.services.logger.logger import MainLogger
from src.utils.dns_utils import DNSUtils

PATHS = config.get("paths")
ROOT_PATH = Path(PATHS.get("root"))
DB_PATH = ROOT_PATH / PATHS.get("database")
LOGS_PATH = ROOT_PATH / PATHS.get("logs")

DB = config.get("database")
DHCP_DB = DB.get("dhcp")
DNS_DB = DB.get("dns")

DHCP_LEASES_DB = DB_PATH / DHCP_DB.get("leases").get("path")
DHCP_STATS_DB = DB_PATH / DHCP_DB.get("stats").get("path")

DNS_HISTORY_DB = DB_PATH / DNS_DB.get("history").get("path")
DNS_STATS_DB = DB_PATH / DNS_DB.get("stats").get("path")

DNS = config.get("dns")
BLACKLIST = ROOT_PATH / DNS.get("blacklists_config").get("path")
WHITELIST = ROOT_PATH / DNS.get("whitelists_config").get("path")

LOGGING = config.get("logging")
LOG_FILE_PATH = ROOT_PATH / LOGGING.get("handlers").get("file").get("filename")

GUI = config.get("gui")
PING_HOST = str(GUI.get("ping_host"))
PING_TIMEOUT = float(GUI.get("ping_timeout_sec"))
PING_PORT = int(GUI.get("ping_port"))
DB_TIMEOUT = float(GUI.get("db_read_timeout_sec"))

NET_INTERFACE = config.get("network").get("interface")


logger = MainLogger.get_logger(service_name="GUI", log_level="debug")
_lock = RLock()


def generate_dashboard_cards() -> dict:
    """Generate dashboard statistics for system, services, and network.

    Returns:
    dict: A dictionary containing system, services, and network statistics.

    """
    sys_stats = generate_system_stats()
    cpu_temps = [
        sensor.get("value")
        for label, sensors in sys_stats.get("temperature", {}).items()
        if "core" in label.lower()
        for sensor in sensors.values()
    ]
    system_stats = {
        "system_time": sys_stats.get("system", {}).get("datetime"),
        "uptime": sys_stats.get("system", {}).get("uptime", {}),
        "cpu_temp": {"value": max(cpu_temps), "unit": "°C"},
        "cpu_usage": sys_stats.get("cpu", {}).get("overall", {}),
        "mem_usage": sys_stats.get("memory", {}).get("used", {}),
    }
    return {
        "system": system_stats,
        "services": get_service_stats(),
        "network": generate_network_stats(),
    }


def generate_system_stats() -> dict:
    """Generate comprehensive system statistics including CPU, memory, disk."""
    process = PsutilProcess()
    stats = {
        "system": {},
        "cpu": {},
        "temperature": {},
        "memory": {},
        "swap": {},
        "disks": {},
        "process": {},
        "network": {},
    }
    stats["system"] = {
        "datetime": {"value": ctime(), "unit": "time"},
        "uptime": {
            "value": round((time() - boot_time()) / 86400, 2),
            "unit": "day",
        },
        "os_name": {"value": system(), "unit": "os"},
        "os_version": {"value": release(), "unit": "version"},
        "architecture": {"value": machine(), "unit": "arch"},
        "processor": {"value": processor(), "unit": "cpu"},
        "hostname": {"value": node(), "unit": "name"},
    }

    stats["cpu"]["overall"] = {
        "value": round(sys_cpu_percent(interval=0.5), 1),
        "unit": "%",
    }
    stats["cpu"]["cores"] = {
        "value": cpu_count(logical=True),
        "unit": "cores",
    }
    stats["cpu"]["per_core"] = {
        f"core_{_core_i}": {"value": round(_cpu_perc, 1), "unit": "%"}
        for _core_i, _cpu_perc in enumerate(sys_cpu_percent(interval=0.5, percpu=True))
    }
    stats["cpu"]["frequency_per_core"] = {
        f"core_{_core_index}": {"value": int(_core_frequency.current), "unit": "MHz"}
        for _core_index, _core_frequency in enumerate(cpu_freq(percpu=True))
    }
    stats["cpu"]["load_avg"] = {
        f"core_{_core_index}": {"value": round(_load_average, 2), "unit": "proc"}
        for _core_index, _load_average in enumerate(getloadavg())
    }

    stats["temperature"] = {}
    stats["memory"] = {}
    stats["swap"] = {}
    stats["disks"] = {}
    stats["network"] = {}
    stats["process"] = {}

    # CPU temperatures
    temps: dict[str, list[shwtemp]] = sensors_temperatures(fahrenheit=False)
    for label, sensors in temps.items():
        stats["temperature"][label] = {}
        for i, sensor in enumerate(sensors):
            key = sensor.label if sensor.label else f"core_{i}"
            stats["temperature"][label][key] = {
                "value": int(sensor.current),
                "unit": "°C",
            }

    # Memory
    mem = virtual_memory()
    stats["memory"] = {
        "total": {
            "value": mem.total // (1024 * 1024),
            "unit": "MB",
        },
        "available": {
            "value": mem.available // (1024 * 1024),
            "unit": "MB",
        },
        "used": {"value": mem.percent, "unit": "%"},
    }

    # Swap
    swap = swap_memory()
    stats["swap"] = {
        "total": {
            "value": swap.total // (1024 * 1024),
            "unit": "MB",
        },
        "used": {
            "value": swap.used // (1024 * 1024),
            "unit": "MB",
        },
        "free": {
            "value": swap.free // (1024 * 1024),
            "unit": "MB",
        },
        "percent": {"value": round(swap.percent, 1), "unit": "%"},
    }

    # Disks per mount point
    for part in disk_partitions(all=False):
        if "ext" not in part.fstype:
            continue  # Only external / data disks
        try:
            usage = disk_usage(part.mountpoint)
            stats["disks"][part.mountpoint] = {
                "total": {
                    "value": round(usage.total // (1024 * 1024 * 1024), 2),
                    "unit": "GB",
                },
                "used": {
                    "value": round(usage.used // (1024 * 1024 * 1024), 2),
                    "unit": "GB",
                },
                "free": {
                    "value": round(usage.free // (1024 * 1024 * 1024), 2),
                    "unit": "GB",
                },
                "percent": {
                    "value": round(usage.percent, 1),
                    "unit": "%",
                },
            }
        except PermissionError:
            continue

    # Network interfaces
    nets = net_io_counters(pernic=True)
    for iface, counters in nets.items():
        if iface.startswith("vet"):
            continue
        stats["network"][iface] = {
            "data_sent": {
                "value": counters.bytes_sent // (1024 * 1024),
                "unit": "MB",
            },
            "data_recv": {
                "value": counters.bytes_recv // (1024 * 1024),
                "unit": "MB",
            },
            "packets_sent": {
                "value": counters.packets_sent,
                "unit": "count",
            },
            "packets_recv": {
                "value": counters.packets_recv,
                "unit": "count",
            },
            "errors_sent": {
                "value": counters.errout,
                "unit": "count",
            },
            "errors_recv": {
                "value": counters.errin,
                "unit": "count",
            },
        }

    # Current process stats
    with process.oneshot():
        now = time()
        mem_info = process.memory_info()
        cpu_perc = process.cpu_percent(interval=0.1)
        stats["process"] = {
            "pid": {"value": process.pid, "unit": "id"},
            "name": {"value": process.name()},
            "status": {"value": process.status()},
            "started": {
                "value": datetime.fromtimestamp(process.create_time()).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "unit": "time",
            },
            "uptime": {
                "value": round(now - process.create_time(), 2),
                "unit": "sec",
            },
            "cpu": {"value": round(cpu_perc, 2), "unit": "%"},
            "memory_rss": {
                "value": mem_info.rss // (1024 * 1024),
                "unit": "MB",
            },
            "memory_vms": {
                "value": mem_info.vms // (1024 * 1024),
                "unit": "MB",
            },
        }

    return stats


def generate_network_stats() -> dict:
    """Retrieve network statistics for the configured network interface."""
    _stats: snetio | None = net_io_counters(pernic=True).get(NET_INTERFACE.get("name"))
    if _stats:
        return {
            "status": {
                "value": "online" if _is_online() else "offline",
                "unit": "state",
            },
            "interface": {
                "value": NET_INTERFACE.get("name"),
                "unit": "name",
            },
            "ip": {
                "value": NET_INTERFACE.get("ip"),
                "unit": "addr",
            },
            "gateway": {
                "value": NET_INTERFACE.get("gateway"),
                "unit": "addr",
            },
            "packets": {
                "value": _stats.packets_recv + _stats.packets_sent,
                "unit": "qty",
            },
            "errors": {
                "value": _stats.errin + _stats.errout,
                "unit": "qty",
            },
            "drops": {
                "value": _stats.dropin + _stats.dropout,
                "unit": "qty",
            },
            "received": {
                "value": int(_stats.bytes_recv / (1024 * 1024)),
                "unit": "MB",
            },
            "sent": {
                "value": int(_stats.bytes_sent / (1024 * 1024)),
                "unit": "MB",
            },
        }

    return {}


def get_network_interfaces()-> list[dict]:
    """Retrieve network interface information.

    Returns:
        list: A list of dictionaries representing network interfaces.

    """
    network_interfaces = []

    for interface, _addresses in net_if_addrs().items():
        _interface_data = {
            "name": interface,
            "type": None,
            "ip_address": None,
            "netmask": None,
            "broadcast": None,
            "mac_address": None,
        }

        for _address in _addresses:
            _type = _address.family
            _addr = _address.address
            netmask = _address.netmask
            broadcast = _address.broadcast

            if _type == AF_INET:
                _interface_data["type"] = "IPv4"
                _interface_data["ip_address"] = _addr
                _interface_data["netmask"] = netmask
                _interface_data["broadcast"] = broadcast
            elif _type == AF_PACKET:
                _interface_data["mac_address"] = _addr

        network_interfaces.append(_interface_data)

    return network_interfaces


def get_dhcp_leases() -> list:
    """Retrieve DHCP leases from the DHCP leases database.

    Returns:
        list: A list of dictionaries representing DHCP lease records.

    """
    return _get_items_from_db(
        db_path=DHCP_LEASES_DB,
        query="SELECT * FROM leases"
    )


def get_dns_history() -> list[dict]:
    """Retrieve DNS query history from the DNS history database.

    Returns:
    list: A list of dictionaries representing DNS query history records.

    """
    return _get_items_from_db(
        db_path=DNS_HISTORY_DB,
        query="SELECT * FROM history"
    )


def _get_item_from_db(db_path: str, query: str, timeout: float = DB_TIMEOUT) -> dict:
    """Fetch a single row from a SQLite database and return as a dictionary.

    Args:
        db_path (str): Path to the SQLite database.
        query (str): SQL query to execute.
        timeout (int): Connection timeout in seconds.

    Returns:
        dict: Row data with column names as keys, or empty dict if none.

    """
    try:
        with connect(db_path, timeout=timeout) as conn:
            conn.row_factory = Row
            cursor: Cursor = conn.cursor()
            row = cursor.execute(query).fetchone()
            if row:
                return dict(row)
    except Exception as e:
        logger.error(f"Failed to read {db_path} - {e}")
    return {}


def _get_items_from_db(
        db_path: str,
        query: str,
        timeout: float = DB_TIMEOUT
    ) -> list[dict]:
    """Fetch all rows from a SQLite database and return as a list of dictionaries.

    Args:
        db_path (str): Path to the SQLite database.
        query (str): SQL query to execute.
        timeout (float): Connection timeout in seconds.

    Returns:
        list[dict]: List of rows as dictionaries with column names as keys.

    """
    try:
        with connect(db_path, timeout=timeout) as _conn:
            _conn.row_factory = Row
            _cursor: Cursor = _conn.cursor()
            _result = _cursor.execute(query).fetchall()
            return [dict(_each) for _each in _result]
    except Exception as e:
        logger.error(f"Failed to read {db_path} - {e}")
        return []


def get_dns_statistics() -> dict:
    """Retrieve DNS statistics from the DNS stats database.

    Returns:
        dict: A dictionary containing DNS statistics.

    """
    return _get_item_from_db(
        db_path=DNS_STATS_DB,
        query="SELECT * FROM stats"
    )


def get_dhcp_statistics() -> dict:
    """Retrieve DHCP statistics from the DHCP stats database.

    Returns:
        dict: A dictionary containing DHCP statistics.

    """
    return _get_item_from_db(
        db_path=DHCP_STATS_DB,
        query="SELECT * FROM stats"
    )


def get_control_list() -> list[str]:
    """Retrieve all blacklist rules from the blacklist file.

    Returns:
        list: A sorted list of all blacklist rules.

    """
    try:
        blacklist_rules = []
        with open(BLACKLIST, mode="r", encoding="utf-8") as file_handle:
            _blacklists = load(file_handle).get("payload")
        for _key, _value in _blacklists.items():
            blacklist_rules.extend(_value)
        return sorted(blacklist_rules)
    except Exception as e:
        logger.error(f"Error: Failed to read {BLACKLIST} - {e}")
    return []


def get_blacklist() -> list[str]:
    """Retrieve the blacklist URLs from the blacklist file.

    Returns:
        list: A list of blacklisted URLs in lowercase.

    """
    try:
        with open(BLACKLIST, mode="r", encoding="utf-8") as file_handle:
            urls = load(file_handle).get("payload", {}).get("urls", [])
            return list(set(url.lower() for url in urls))
    except Exception as e:
        logger.error("Failed to load blackist: %s", e)
        return list()


def get_whitelist() -> list[str]:
    """Retrieve the whitelist URLs from the whitelist file.

    Returns:
        list: A list of whitelisted URLs in lowercase.

    """
    try:
        with open(WHITELIST, mode="r", encoding="utf-8") as file_handle:
            urls = load(file_handle).get("payload", {}).get("urls", [])
            return list(set(url.lower() for url in urls))
    except Exception as e:
        logger.error("Failed to load whitelist: %s", e)
        return list()


def get_system_logs() -> list:
    """Retrieve system log entries from the log file.

    Returns:
        list: A list of log entries, each represented as a dictionary with keys
              'timestamp', 'level', 'service', and 'message'.

    """
    try:
        with open(LOG_FILE_PATH, mode="r", encoding="utf-8") as file_handle:
            log_entries = []
            for line in file_handle:
                if not line:
                    continue
                line_array: list[str] = line.strip().split("|")
                if len(line_array) != 4:
                    continue
                log_entries.append(
                    {
                        "timestamp": line_array[0].strip(),
                        "level": line_array[1].strip(),
                        "service": line_array[2].strip(),
                        "message": line_array[3].strip(),
                    }
                )
            return log_entries
    except Exception as e:
        logger.error(f"Failed to read {LOG_FILE_PATH} - {e}")
        return []


def clear_system_logs() -> bool:
    """Clear the system log file.

    Returns:
        bool: True if logs were cleared successfully, False otherwise.

    """
    try:
        with open(LOG_FILE_PATH, mode="w", encoding="utf-8") as file_handle:
            file_handle.truncate(0)
        logger.info("Cleared system logs.")
        return True
    except Exception as err:
        logger.error(f"Failed to clear logs: {str(err)}.")
        return False


def add_to_whitelist(url: str) -> bool:
    """Add a URL or rule to the whitelist.

    Args:
        url (str): The URL or rule to add to the whitelist.
        Returns:    bool: True if added successfully, False otherwise.

    """
    if not url or not DNSUtils.is_valid_domain(url.replace("*", "a")):
        return False

    try:
        with _lock:
            with open(WHITELIST, mode="r", encoding="utf-8") as file_handle:
                _whitelists = load(file_handle)

            payload = _whitelists.get("payload", {})
            urls = payload.get("urls", [])

            if url in urls:
                return True
            urls.append(url)
            payload["urls"] = urls

            _whitelists["payload"] = payload
            _whitelists["timestamp"] = datetime.now(timezone.utc).isoformat()

            with open(WHITELIST, mode="w", encoding="utf-8") as file_handle:
                dump(_whitelists, file_handle, indent=2)

        return True
    except Exception as e:
        logger.error(f"Failed to add URL '{url}' to blacklist: {e}")
        return False


def delete_from_whitelist(url: str) -> bool:
    """Delete a URL or rule from the whitelist."""
    if not url or not DNSUtils.is_valid_domain(url.replace("*", "a")):
        return False

    try:
        with _lock:
            with open(WHITELIST, mode="r", encoding="utf-8") as file_handle:
                _whitelist = load(file_handle)

            payload = _whitelist.get("payload", {})
            url_list = payload.get("urls", [])

            if url not in url_list:
                return True

            payload["urls"] = [url_rule for url_rule in url_list if url_rule != url]

            _whitelist["timestamp"] = datetime.now(timezone.utc).isoformat()
            _whitelist["payload"] = payload

            with open(WHITELIST, mode="w", encoding="utf-8") as file_handle:
                dump(_whitelist, file_handle, indent=2)

        return True
    except Exception as e:
        logger.error(f"Failed to delete URL '{url}' from blacklist: {e}")
        return False


def add_to_blacklist(url: str) -> bool:
    """Add a URL or rule to the blacklist."""
    if not url:
        return False

    if not DNSUtils.is_valid_domain(url.replace("*", "a")):
        return False

    try:
        with _lock:
            with open(BLACKLIST, mode="r", encoding="utf-8") as file_handle:
                _blacklists = load(file_handle)

            payload = _blacklists.get("payload", {})
            rules_list = payload.get("rules", [])
            url_list = payload.get("urls", [])

            if "*" in url:
                if url in rules_list:
                    return True
                rules_list.append(url)
                payload["rules"] = rules_list
            else:
                if url in url_list:
                    return True
                url_list.append(url)
                payload["urls"] = url_list

            _blacklists["payload"] = payload
            _blacklists["timestamp"] = datetime.now(timezone.utc).isoformat()

            with open(BLACKLIST, mode="w", encoding="utf-8") as file_handle:
                dump(_blacklists, file_handle, indent=2)

        return True
    except Exception as e:
        logger.error(f"Failed to add URL '{url}' to blacklist: {e}")
        return False


def delete_from_blacklist(url: str) -> bool:
    """Delete a URL or rule from the blacklist."""
    if not url or not DNSUtils.is_valid_domain(url.replace("*", "a")):
        return False

    try:
        with _lock:
            with open(BLACKLIST, mode="r", encoding="utf-8") as file_handle:
                _blacklists = load(file_handle)

            payload = _blacklists.get("payload", {})
            rules_list = payload.get("rules", [])
            url_list = payload.get("urls", [])

            if "*" in url:
                if url not in rules_list:
                    return True
                payload["rules"] = [rule for rule in rules_list if rule != url]
            else:
                if url not in url_list:
                    return True

                payload["urls"] = [url_rule for url_rule in url_list if url_rule != url]

            _blacklists["timestamp"] = datetime.now(timezone.utc).isoformat()
            _blacklists["payload"] = payload

            with open(BLACKLIST, mode="w", encoding="utf-8") as file_handle:
                dump(_blacklists, file_handle, indent=2)

        return True
    except Exception as e:
        logger.error(f"Failed to delete URL '{url}' from blacklist: {e}")
        return False


def get_service_stats() -> dict:
    """Retrieve statistics for DHCP and DNS services."""
    _dns_stats: dict = get_dns_statistics()
    _leases = get_dhcp_leases()
    _dhcp_stats = {
        "leases": len(_leases),
        "static": sum(1 for lease in _leases if lease.get("type") == "static"),
        "dynamic": sum(1 for lease in _leases if lease.get("type") == "dynamic"),
        "manual": sum(1 for lease in _leases if lease.get("type") == "manual"),
    }
    _dns_cache_hit_rate = int(
        100
        * _dns_stats.get("request_cache_hit", 0)
        / (
            _dns_stats.get("request_cache_hit", 0)
            + _dns_stats.get("request_cache_miss", 0)
        )
        if _dns_stats.get("request_cache_miss", 0) > 0
        else 0
    )

    return {
        "dhcp_status": {
            "value": ("running" if DHCPServer.running else "stopped"),
            "unit": "state",
        },
        "dhcp_leases_total": {
            "value": _dhcp_stats["leases"],
            "unit": "qty",
        },
        "dns_status": {
            "value": ("running" if DNSServer.running else "stopped"),
            "unit": "state",
        },
        "dns_cache_hit_rate": {
            "value": _dns_cache_hit_rate,
            "unit": "%",
        },
    }


def get_metrics() -> list[dict]:
    """Retrieve metrics from various services."""
    _server_metrics = []
    for server, metrics in dns_per_server_metrics.items():
        _server_metrics.append(
            {
                "label": str(server),
                "metrics": metrics.get_stats(),
                "qty": metrics.get_count(),
                "unit":"sec"
            }
        )
    dns_received_results = received_metrics.get_results()
    return [
        {
            "label": "api",
            "metrics": api_metrics.get_stats(),
            "qty": api_metrics.get_count(),
            "unit":"sec"
        },
        {
            "label": "gui",
            "metrics": http_response_metrics.get_stats(),
            "qty": http_response_metrics.get_count(),
            "unit":"sec"
        },
        {
            "label":"http_proxy",
            "metrics": http_proxy_metrics.get_stats(),
            "qty":http_proxy_metrics.get_count(),
            "unit":"sec"
        },
        {
            "label": "dhcp",
            "metrics": dhcp_metrics.get_stats(),
            "qty": dhcp_metrics.get_count(),
            "unit":"sec"
        },
        {
            "label": "dns",
            "metrics": dns_metrics.get_stats(),
            "qty": dns_metrics.get_count(),
            "unit":"sec"
        },
        {
            "label":"dns_received",
            "metrics":dns_received_results,
            "qty":len(dns_received_results.keys()),
            "unit":"qty"
         },
        {
            "label": "external",
            "metrics": dns_metrics_external.get_stats(),
            "qty": dns_metrics_external.get_count(),
            "unit":"sec"
        },
        *_server_metrics,
    ]


def extract_auth_bearer(request: Request) -> str | None:
    """Extract the bearer token from the Authorization header.

    Args:
        request: Incoming Flask request object.

    Returns:
        The token string if the header is a valid "Bearer <token>" format,
        otherwise None.

    """
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        return header[7:].strip()
    return None


def set_cache_control(
    response: Response, max_age: int, public: bool = True
) -> Response:
    """Apply Cache-Control headers to a Flask response.

    Args:
        response (Response): Flask Response object
        max_age (int): Cache duration in seconds
        public (str): Whether the response is public cacheable
    Returns: The modified response

    """
    visibility = "public" if public else "private"
    response.headers["Cache-Control"] = f"{visibility},max-age={max_age}"
    return response


def _is_online(
    host: str = PING_HOST,
    port: int = PING_PORT,
    timeout: float = PING_TIMEOUT,
) -> bool:
    """Check if a host is reachable on a given TCP port.
    Attempts to establish a TCP connection to the specified host and port
    within the given timeout.

    Args:
        host(str): Hostname or IP address to check. Defaults to PING_HOST.
        port(int): TCP port to connect to. Defaults to PING_PORT.
        timeout (float): Connection timeout in seconds. Defaults to PING_TIMEOUT.

    Returns:
        bool: True if the host is reachable, False otherwise.

    """
    try:
        with socket(AF_INET, SOCK_STREAM) as _socket:
            _socket.settimeout(timeout)
            _socket.connect((host, port))
        return True
    except Exception:
        return False
