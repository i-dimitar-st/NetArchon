from datetime import datetime, timezone
from json import dump, load
from os import getloadavg
from pathlib import Path
from platform import machine, node, processor, release, system
from socket import AF_INET, AF_PACKET, SOCK_STREAM, socket
from sqlite3 import Cursor, connect
from threading import RLock
from time import ctime, time
from typing import Any

from psutil import (
    Process as PsutilProcess,
    boot_time,
    cpu_count,
    cpu_freq,
    cpu_percent as sys_cpu_percent,
    disk_partitions,
    disk_usage,
    net_if_addrs,
    net_io_counters,
    sensors_temperatures,
    swap_memory,
    virtual_memory,
)
from psutil._common import shwtemp, snetio

from app.config.config import config
from app.services.dhcp.metrics import dhcp_metrics
from app.services.dhcp.server import DHCPServer
from app.services.dns.dns import DNSServer
from app.services.dns.metrics import (
    dns_metrics,
    dns_metrics_external,
    dns_per_server_metrics,
)
from app.services.gui.metrics import api_metrics, http_response_metrics
from app.services.logger.logger import MainLogger
from app.utils.dns_utils import DNSUtils

PATHS = config.get("paths")
ROOT_PATH = Path(PATHS.get("root"))
DB_PATH = ROOT_PATH / PATHS.get("database")

DNS_HISTORY_DB = DB_PATH / "dns_history.sqlite3"
DNS_STATS_DB = DB_PATH / "dns_stats.sqlite3"
DHCP_LEASES_DB = DB_PATH / "dhcp_leases.sqlite3"
DHCP_STATS_DB = DB_PATH / "dhcp_stats.sqlite3"
BLACKLIST = ROOT_PATH / "config" / "blacklists.json"
WHITELIST = ROOT_PATH / "config" / "whitelists.json"
LOG_FILE_PATH = ROOT_PATH / "logs" / "main.log"

GUI = config.get("gui")
PING_HOST = str(GUI.get("ping_host"))
PING_TIMEOUT = float(GUI.get("ping_timeout_sec"))
PING_PORT = int(GUI.get("ping_port"))

NET_INTERFACE = config.get("network").get("interface")
DB_TIMEOUT = float(GUI.get("db_read_timeout_sec"))


logger = MainLogger.get_logger(service_name="GUI", log_level="debug")
_lock = RLock()


def generate_dashboard_cards() -> dict:
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
    stats["cpu"]["cores"] = {"value": cpu_count(logical=True), "unit": "cores"}
    stats["cpu"]["per_core"] = {
        f"core_{i}": {"value": round(u, 1), "unit": "%"}
        for i, u in enumerate(sys_cpu_percent(interval=0.5, percpu=True))
    }
    stats["cpu"]["frequency_per_core"] = {
        f"core_{i}": {"value": int(f.current), "unit": "MHz"}
        for i, f in enumerate(cpu_freq(percpu=True))
    }
    stats["cpu"]["load_avg"] = {
        f"core_{i}": {"value": round(l, 2), "unit": "proc"} for i, l in enumerate(getloadavg())
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
        "total": {"value": mem.total // (1024 * 1024), "unit": "MB"},
        "available": {"value": mem.available // (1024 * 1024), "unit": "MB"},
        "used": {"value": mem.percent, "unit": "%"},
    }

    # Swap
    swap = swap_memory()
    stats["swap"] = {
        "total": {"value": swap.total // (1024 * 1024), "unit": "MB"},
        "used": {"value": swap.used // (1024 * 1024), "unit": "MB"},
        "free": {"value": swap.free // (1024 * 1024), "unit": "MB"},
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
                "percent": {"value": round(usage.percent, 1), "unit": "%"},
            }
        except PermissionError:
            continue

    # Network interfaces
    nets = net_io_counters(pernic=True)
    for iface, counters in nets.items():
        if iface.startswith("vet"):
            continue
        stats["network"][iface] = {
            "data_sent": {"value": counters.bytes_sent // (1024 * 1024), "unit": "MB"},
            "data_recv": {"value": counters.bytes_recv // (1024 * 1024), "unit": "MB"},
            "packets_sent": {"value": counters.packets_sent, "unit": "count"},
            "packets_recv": {"value": counters.packets_recv, "unit": "count"},
            "errors_sent": {"value": counters.errout, "unit": "count"},
            "errors_recv": {"value": counters.errin, "unit": "count"},
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
                "value": datetime.fromtimestamp(process.create_time()).strftime("%Y-%m-%d %H:%M:%S")
            },
            "uptime": {"value": round(now - process.create_time(), 2), "unit": "sec"},
            "cpu": {"value": round(cpu_perc, 2), "unit": "%"},
            "memory_rss": {"value": mem_info.rss // (1024 * 1024), "unit": "MB"},
            "memory_vms": {"value": mem_info.vms // (1024 * 1024), "unit": "MB"},
        }

    return stats


def generate_network_stats() -> dict:
    _stats: snetio | None = net_io_counters(pernic=True).get(NET_INTERFACE.get("name"))
    if _stats:
        return {
            "status": {
                "value": "online" if _is_online() else "offline",
                "unit": "state",
            },
            "interface": {"value": NET_INTERFACE.get("name"), "unit": "name"},
            "ip": {"value": NET_INTERFACE.get("ip"), "unit": "addr"},
            "gateway": {"value": NET_INTERFACE.get("gateway"), "unit": "addr"},
            "packets": {
                "value": _stats.packets_recv + _stats.packets_sent,
                "unit": "qty",
            },
            "errors": {"value": _stats.errin + _stats.errout, "unit": "qty"},
            "drops": {"value": _stats.dropin + _stats.dropout, "unit": "qty"},
            "received": {"value": int(_stats.bytes_recv / (1024 * 1024)), "unit": "MB"},
            "sent": {"value": int(_stats.bytes_sent / (1024 * 1024)), "unit": "MB"},
        }

    return {}


def get_network_interfaces():

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

    try:
        with connect(DHCP_LEASES_DB) as _conn:

            _cursor: Cursor = _conn.cursor()
            columns_raw: list[Any] = _cursor.execute("PRAGMA table_info(leases)").fetchall()

            _columns: list[str] = [column[1] for column in columns_raw]
            _leases: list[tuple] = _cursor.execute("SELECT * FROM leases").fetchall()

            result = []
            for _lease in _leases:
                result.append(dict(zip(_columns, _lease)))

            return result

    except Exception as e:
        logger.error(f"Error: Failed to read {DHCP_LEASES_DB} - {e}")
        return []


def get_dns_history() -> list[dict]:

    try:
        with connect(DNS_HISTORY_DB, timeout=DB_TIMEOUT) as _conn:

            _cursor: Cursor = _conn.cursor().execute("PRAGMA table_info(history)")
            _columns: list[str] = [_column[1] for _column in _cursor.fetchall()]

            _history_records: list[tuple] = _cursor.execute("SELECT * FROM history").fetchall()

            dns_records = []
            for history_record in _history_records:
                dns_records.append(dict(zip(_columns, history_record)))

            return dns_records

    except Exception as e:
        logger.error(f"Error: Failed to read {DNS_HISTORY_DB} - {e}")
        return []


def get_dns_statistics() -> dict:
    try:
        with connect(DNS_STATS_DB, timeout=DB_TIMEOUT) as _conn:

            _cursor: Cursor = _conn.cursor().execute("PRAGMA table_info(stats)")
            _columns: list[str] = [_column[1] for _column in _cursor.fetchall()]
            _row: tuple | None = _cursor.execute("SELECT * FROM stats").fetchone()
            if _row and _columns:
                if len(_columns) != len(_row):
                    logger.warning(f"Column count ({len(_columns)}) != Row length ({len(_row)})")
                return dict(zip(_columns, _row))

    except Exception as e:
        logger.error(f"Failed to read {DNS_STATS_DB} - {e}")

    return {}


def get_dhcp_statistics() -> dict:
    try:
        with connect(DHCP_STATS_DB) as _conn:

            _cursor: Cursor = _conn.cursor().execute("PRAGMA table_info(stats)")
            columns: list[str] = [_column[1] for _column in _cursor.fetchall()]

            _cursor.execute("SELECT * FROM stats")
            row: tuple | None = _cursor.fetchone()

            if row and columns:
                if len(columns) != len(row):
                    logger.warning("[get_dns_statistics] Invalid db clumns")
                return dict(zip(columns, row))

    except Exception as e:
        logger.error(f"[get_dns_statistics]  Failed to read {DHCP_STATS_DB} - {e}")

    return {}


def get_control_list() -> list[str]:
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
    try:
        with open(BLACKLIST, mode="r", encoding="utf-8") as file_handle:
            urls = load(file_handle).get("payload", {}).get("urls", [])
            return list(set(url.lower() for url in urls))
    except Exception as e:
        logger.error("Failed to load blackist: %s", e)
        return list()


def get_whitelist() -> list[str]:
    try:
        with open(WHITELIST, mode="r", encoding="utf-8") as file_handle:
            urls = load(file_handle).get("payload", {}).get("urls", [])
            return list(set(url.lower() for url in urls))
    except Exception as e:
        logger.error("Failed to load whitelist: %s", e)
        return list()


def get_system_logs() -> list:
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
    try:
        with open(LOG_FILE_PATH, mode="w", encoding="utf-8") as file_handle:
            file_handle.truncate(0)
        logger.info(f"Cleared system logs.")
        return True
    except Exception as err:
        logger.error(f"Failed to clear logs: {str(err)}.")
        return False


def add_to_whitelist(url: str) -> bool:

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
    _dns_stats: dict = get_dns_statistics()
    _leases = get_dhcp_leases()
    _dhcp_stats = {
        "leases": len(_leases),
        "static": sum(1 for lease in _leases if lease.get("type") == "static"),
        "dynamic": sum(1 for lease in _leases if lease.get("type") == "dynamic"),
        "manual": sum(1 for lease in _leases if lease.get("type") == "manual"),
    }
    _dns_blacklist_hit_rate = int(
        100 * _dns_stats.get("request_blacklisted", 0) / _dns_stats.get("request_valid", 0)
        if _dns_stats.get("request_valid", 0) > 0
        else 0
    )
    _dns_external_hit_rate = int(
        100 * _dns_stats.get("request_external", 0) / _dns_stats.get("response_total", 0)
        if _dns_stats.get("response_total", 0) > 0
        else 0
    )
    _dns_cache_hit_rate = int(
        100
        * _dns_stats.get("request_cache_hit", 0)
        / (_dns_stats.get("request_cache_hit", 0) + _dns_stats.get("request_cache_miss", 0))
        if _dns_stats.get("request_cache_miss", 0) > 0
        else 0
    )

    return {
        "dhcp_status": {
            "value": "running" if DHCPServer.running else "stopped",
            "unit": "state",
        },
        "dhcp_started": {
            "value": datetime.fromtimestamp(DHCPServer.timestamp).strftime("%Y-%m-%d %H:%M:%S"),
            "unit": "time",
        },
        "dhcp_leases_total": {"value": _dhcp_stats["leases"], "unit": "qty"},
        "dhcp_leases_static": {"value": _dhcp_stats["static"], "unit": "qty"},
        "dhcp_leases_dynamic": {"value": _dhcp_stats["dynamic"], "unit": "qty"},
        "dhcp_leases_manual": {"value": _dhcp_stats["manual"], "unit": "qty"},
        "dns_status": {
            "value": "running" if DNSServer.running else "stopped",
            "unit": "state",
        },
        "dns_started": {
            "value": datetime.fromtimestamp(DNSServer.timestamp).strftime("%Y-%m-%d %H:%M:%S"),
            "unit": "time",
        },
        "dns_cache_hit_rate": {
            "value": _dns_cache_hit_rate,
            "unit": "%",
        },
        "dns_blacklist_hit_rate": {
            "value": _dns_blacklist_hit_rate,
            "unit": "%",
        },
        "dns_external_hit_rate": {
            "value": _dns_external_hit_rate,
            "unit": "%",
        },
    }


def get_metrics() -> list[dict]:
    _server_metrics = []
    for server, metrics in dns_per_server_metrics.items():
        _server_metrics.append(
            {"label": str(server), "metrics": metrics.get_stats(), "qty": metrics.get_count()}
        )
    return [
        {"label": "api", "metrics": api_metrics.get_stats(), "qty": api_metrics.get_count()},
        {
            "label": "http",
            "metrics": http_response_metrics.get_stats(),
            "qty": http_response_metrics.get_count(),
        },
        {"label": "dhcp", "metrics": dhcp_metrics.get_stats(), "qty": dhcp_metrics.get_count()},
        {"label": "dns", "metrics": dns_metrics.get_stats(), "qty": dns_metrics.get_count()},
        {
            "label": "external",
            "metrics": dns_metrics_external.get_stats(),
            "qty": dns_metrics_external.get_count(),
        },
        *_server_metrics,
    ]


def _is_online(host: str = PING_HOST, port: int = PING_PORT, timeout: float = PING_TIMEOUT) -> bool:
    """
    Check if a host is reachable on a given TCP port.
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
