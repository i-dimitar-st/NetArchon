from datetime import datetime, timezone
from hashlib import sha256
from json import dump, load
from logging import WARNING, getLogger
from os import getloadavg
from pathlib import Path
from platform import machine, node, processor, release, system, version
from socket import AF_INET, AF_PACKET
from sqlite3 import Cursor, connect
from threading import Event, RLock, Thread
from time import ctime, time
from typing import Any

from asgiref.wsgi import WsgiToAsgi
from flask import Flask, abort, jsonify, render_template, request
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
from uvicorn import run as runUvicorn

from app.config.config import config
from app.services.dns.metrics import dns_metrics
from app.services.logger.logger import MainLogger
from app.utils.dns_utils import DNSUtils

APP_CONFIG = config.get("app")
PORT = APP_CONFIG.get("port")
HOST = APP_CONFIG.get("host")
BEARER_TOKEN = APP_CONFIG.get("bearer_token")
BEARER_TOKEN_HASH = sha256(BEARER_TOKEN.encode()).hexdigest()


PATHS = config.get("paths")
ROOT_PATH = Path(PATHS.get("root"))
DB_PATH = ROOT_PATH / PATHS.get("database")

CERTIFICATES = config.get("certificates")
CERT_PATH = ROOT_PATH / PATHS.get("certificates")
PEM_PATH = CERT_PATH / CERTIFICATES.get("cert")
KEY_PATH = CERT_PATH / CERTIFICATES.get("key")

DNS_HISTORY_DB = DB_PATH / "dns_history.sqlite3"
DNS_STATS_DB = DB_PATH / "dns_stats.sqlite3"
DHCP_LEASES_DB = DB_PATH / "dhcp_leases.sqlite3"
DHCP_STATS_DB = DB_PATH / "dhcp_stats.sqlite3"
DNS_CONTROL_LIST = ROOT_PATH / "config" / "blacklists.json"
LOG_FILE_PATH = ROOT_PATH / "logs" / "main.log"

DB_TIMEOUT = 10

DHCP_STATISTICS = {}
LEASES = []

logger = MainLogger.get_logger(service_name="GUI", log_level="debug")
_lock = RLock()


def generate_system_stats() -> dict:
    process = PsutilProcess()
    stats = {
        "system": {
            "datetime": {"value": ctime()},
            "uptime": {"value": int(time() - boot_time()), "unit": "sec"},
            "os_name": {"value": system()},
            "os_version": {"value": version()},
            "os_release": {"value": release()},
            "architecture": {"value": machine()},
            "processor": {"value": processor()},
            "hostname": {"value": node()},
        },
        "cpu": {
            "usage": {"value": sys_cpu_percent(interval=0.5), "unit": "%"},
            "usage_per_core": {
                "value": sys_cpu_percent(interval=0.5, percpu=True),
                "unit": "%",
            },
            "frequency_per_core": {
                "value": [int(freq.current) for freq in cpu_freq(percpu=True)],
                "unit": "MHz",
            },
            "cores": {"value": cpu_count(logical=True), "unit": "cores"},
            "load_1min": {"value": round(getloadavg()[0], 2)},
            "load_5min": {"value": round(getloadavg()[1], 2)},
            "load_15min": {"value": round(getloadavg()[2], 2)},
        },
        "temperature": {},
        "memory": {},
        "swap": {},
        "disks": {},
        "process": {},
        "network": {},
    }

    # CPU Temp
    temp_info = sensors_temperatures(fahrenheit=False)
    for label, sensors in temp_info.items():
        for sensor in sensors:
            stats["temperature"][f"{label}_{sensor.label}"] = {
                "value": int(sensor.current),
                "unit": "°C",
            }

    # Memory
    memory = virtual_memory()
    stats["memory"] = {
        "total": {"value": int(memory.total / 1024 / 1024), "unit": "MB"},
        "available": {"value": int(memory.available / 1024 / 1024), "unit": "MB"},
        "percent_used": {"value": int(memory.percent), "unit": "%"},
    }

    # Swap
    swap = swap_memory()
    stats["swap"] = {
        "total": {"value": int(swap.total / 1024 / 1024), "unit": "MB"},
        "used": {"value": int(swap.used / 1024 / 1024), "unit": "MB"},
        "percent_used": {"value": int(swap.percent), "unit": "%"},
    }

    # Disks
    for part in disk_partitions(all=False):
        try:
            usage = disk_usage(part.mountpoint)
            if "ext" in part.fstype:
                stats["disks"][f"disk_{part.mountpoint}_total"] = {
                    "value": int(usage.total / 1024 / 1024),
                    "unit": "MB",
                }
                stats["disks"][f"disk_{part.mountpoint}_used"] = {
                    "value": int(usage.used / 1024 / 1024),
                    "unit": "MB",
                }
        except PermissionError:
            continue

    # Network: Stats from all network interfaces (Flat structure)
    network = net_io_counters(pernic=True)
    for iface, counters in network.items():
        stats["network"][f"{iface}_sent"] = {
            "value": int(counters.bytes_sent / 1024 / 1024),
            "unit": "MB",
        }
        stats["network"][f"{iface}_recv"] = {
            "value": int(counters.bytes_recv / 1024 / 1024),
            "unit": "MB",
        }
        stats["network"][f"{iface}_packets_sent"] = {"value": counters.packets_sent}
        stats["network"][f"{iface}_packets_recv"] = {"value": counters.packets_recv}
        stats["network"][f"{iface}_errors_sent"] = {"value": counters.errout}
        stats["network"][f"{iface}_errors_recv"] = {"value": counters.errin}

    # Current Process Stats
    with process.oneshot():
        now: float = time()
        create_time: float = process.create_time()
        uptime: float = round(now - create_time, 2)
        mem_info = process.memory_info()
        cpu_percent: float = process.cpu_percent(interval=0.1)  # Short sample

        stats["process"] = {
            "pid": {"value": process.pid},
            "name": {"value": process.name()},
            "status": {"value": process.status()},
            "uptime": {"value": uptime, "unit": "sec"},
            "cpu": {"value": round(cpu_percent, 2), "unit": "%"},
            "memory_rss": {"value": int(mem_info.rss / 1024 / 1024), "unit": "MB"},
            "memory_vms": {"value": int(mem_info.vms / 1024 / 1024), "unit": "MB"},
        }

    return stats


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
            columns_raw: list[Any] = _cursor.execute(
                "PRAGMA table_info(leases)"
            ).fetchall()

            _columns: list[str] = [column[1] for column in columns_raw]
            _leases: list[tuple] = _cursor.execute("SELECT * FROM leases").fetchall()

            result = []
            for _lease in _leases:
                result.append(dict(zip(_columns, _lease)))  # type: ignore

            return result

    except Exception as e:
        logger.error(f"Error: Failed to read {DHCP_LEASES_DB} - {e}")
        return []


def get_dns_history() -> list:

    try:
        with connect(DNS_HISTORY_DB, timeout=DB_TIMEOUT) as _conn:

            _cursor: Cursor = _conn.cursor().execute("PRAGMA table_info(history)")
            _columns: list[str] = [_column[1] for _column in _cursor.fetchall()]

            _history_records: list[tuple] = _cursor.execute(
                "SELECT * FROM history"
            ).fetchall()

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
                    logger.warning(
                        f"Column count ({len(_columns)}) != Row length ({len(_row)})"
                    )
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


def get_control_list() -> list:
    try:
        blacklist_rules = []
        with open(DNS_CONTROL_LIST, mode="r", encoding="utf-8") as file_handle:
            _blacklists = load(file_handle).get("payload")
        for _key, _value in _blacklists.items():
            blacklist_rules.extend(_value)
        return sorted(blacklist_rules)
    except Exception as e:
        logger.error(f"Error: Failed to read {DNS_CONTROL_LIST} - {e}")
    return []


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


def add_to_blacklist(url: str) -> bool:

    if not url:
        return False

    if not DNSUtils.is_valid_domain(url.replace("*", "a")):
        return False

    try:
        with _lock:
            with open(DNS_CONTROL_LIST, mode="r", encoding="utf-8") as file_handle:
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

            with open(DNS_CONTROL_LIST, mode="w", encoding="utf-8") as file_handle:
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
            with open(DNS_CONTROL_LIST, mode="r", encoding="utf-8") as file_handle:
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

            with open(DNS_CONTROL_LIST, mode="w", encoding="utf-8") as file_handle:
                dump(_blacklists, file_handle, indent=2)

        return True
    except Exception as e:
        logger.error(f"Failed to delete URL '{url}' from blacklist: {e}")
        return False


class App:
    _worker: Thread | None = None
    _app: Flask | None = None
    _stop_app = Event()

    @classmethod
    def init(cls, host: str = HOST, port: int = PORT):
        cls._host: str = host
        cls._port: int = port

    @classmethod
    def start(cls):
        if cls._worker and cls._worker.is_alive():
            raise RuntimeError("Flask App already running")
        cls._worker = Thread(target=cls._work, daemon=True)
        cls._worker.start()
        logger.info(f"Starting Flask App at {cls._host}:{cls._port}.")

    @classmethod
    def stop(cls):
        logger.info("Shutting Flask App")
        cls._stop_app.set()

    @classmethod
    def _work(cls):
        cls._app = Flask(__name__)
        cls._app_wsgi: WsgiToAsgi = WsgiToAsgi(cls._app)

        cls._bootstrap_loggers()
        cls._define_routes()

        runUvicorn(
            cls._app_wsgi,
            host=cls._host,
            port=cls._port,
            ssl_certfile=PEM_PATH,
            ssl_keyfile=KEY_PATH,
            log_level="warning",
        )

    @classmethod
    def _bootstrap_loggers(cls):
        # Flask logger
        if cls._app:
            cls._app.logger.handlers.clear()
            cls._app.logger.propagate = True
            for _handler in logger.handlers:
                cls._app.logger.addHandler(_handler)
            cls._app.logger.setLevel(WARNING)

        # Uvicorn loggers
        if cls._app_wsgi:
            for _name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
                _uv_logger = getLogger(_name)
                _uv_logger.handlers.clear()
                _uv_logger.propagate = True
                for _handler in logger.handlers:
                    _uv_logger.addHandler(_handler)
                _uv_logger.setLevel(WARNING)

    @classmethod
    def _define_routes(cls):

        if cls._app:

            @cls._app.route("/")
            def index():
                return render_template(
                    "index.html",
                    system_stats=generate_system_stats(),
                    active_leases=len(get_dhcp_leases()),
                )

            @cls._app.route("/info")
            def info():
                return render_template(
                    "info.html",
                    system_statistics=generate_system_stats(),
                    network_interfaces=get_network_interfaces(),
                )

            @cls._app.route("/dhcp")
            def dhcp():
                return render_template(
                    "dhcp.html",
                    dhcp_statistics=get_dhcp_statistics(),
                    dhcp_leases=get_dhcp_leases(),
                )

            @cls._app.route("/dns")
            def dns():
                print(dns_metrics.get_stats())
                return render_template(
                    "dns.html",
                    dns_history=get_dns_history(),
                    dns_statistics=get_dns_statistics(),
                )

            @cls._app.route("/config", methods=["GET", "POST"])
            def get_config():
                if request.method == "POST":
                    _auth: str = request.headers.get("Authorization", "")
                    if (
                        not _auth.startswith("Bearer ")
                        or _auth[7:].strip() != BEARER_TOKEN_HASH
                    ):
                        abort(401, description="Unauthorized")

                    if not request.is_json:
                        abort(415, description="Expected application/json")

                    data: Any | None = request.get_json(silent=True)
                    if not data:
                        abort(400, description="Invalid or empty JSON")

                    category = data.get("category")
                    action = data.get("type")
                    payload = data.get("payload")

                    if category == "blacklist":
                        if action == "add" and add_to_blacklist(payload):
                            logger.info("%s added to blacklists.", payload)
                            return jsonify(status="received"), 200
                        if action == "delete" and delete_from_blacklist(payload):
                            logger.info("%s deleted from blacklists.", payload)
                            return jsonify(status="received"), 200
                        abort(400, description=f"Failed to {action} from {category}")

                    abort(400, description="Invalid action or category")

                return render_template(
                    "config.html",
                    config={
                        "network": config.get("network").get("lan", {}),
                        "dns": config.get("dns"),
                        "dhcp": config.get("dhcp"),
                    },
                    dns_control_list=get_control_list(),
                    bearer_token_hash=BEARER_TOKEN_HASH,
                )

            @cls._app.route("/logs")
            def logs():
                return render_template("logs.html", system_logs=get_system_logs())

            @cls._app.errorhandler(404)
            def not_found(error):
                return render_template("404.html"), 404
