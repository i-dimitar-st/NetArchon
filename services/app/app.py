import os
import time
import platform
import json
import multiprocessing
import socket
from copy import deepcopy
import sqlite3
import psutil
from pathlib import Path
from flask import Flask, render_template
from services.logger.logger import MainLogger
from services.config.config import config

ROOT_PATH = Path("/projects/gitlab/netarchon")
DNS_HISTORY_DB = ROOT_PATH / "db" / "dns_history.sqlite3"
DNS_STATS_DB = ROOT_PATH / "db" / "dns_stats.sqlite3"
DHCP_LEASES_DB = ROOT_PATH / "db" / "dhcp_leases.sqlite3"
DHCP_STATS_DB = ROOT_PATH / "db" / "dhcp_stats.sqlite3"
DNS_CONTROL_LIST = ROOT_PATH / "config" / "dns_control_list.json"
LOG_FILE_PATH = ROOT_PATH / "logs" / "main.log"

DB_TIMEOUT = 10

DHCP_STATISTICS = {}
LEASES = []


app_logger = MainLogger.get_logger(service_name="GUI", log_level="debug")


def _generate_system_stats() -> dict:
    process = psutil.Process()
    stats = {
        "system": {
            "datetime": {"value": time.ctime()},
            "uptime": {"value": int(time.time() - psutil.boot_time()), "unit": "sec"},
            "os_name": {"value": platform.system()},
            "os_version": {"value": platform.version()},
            "os_release": {"value": platform.release()},
            "architecture": {"value": platform.machine()},
            "processor": {"value": platform.processor()},
            "hostname": {"value": platform.node()},
        },
        "cpu": {
            "usage": {"value": psutil.cpu_percent(interval=0.5), "unit": "%"},
            "usage_per_core": {
                "value": psutil.cpu_percent(interval=0.5, percpu=True),
                "unit": "%",
            },
            "frequency_per_core": {
                "value": [int(freq.current) for freq in psutil.cpu_freq(percpu=True)],
                "unit": "MHz",
            },
            "cores": {"value": psutil.cpu_count(logical=True), "unit": "cores"},
            "load_1min": {"value": round(os.getloadavg()[0], 2)},
            "load_5min": {"value": round(os.getloadavg()[1], 2)},
            "load_15min": {"value": round(os.getloadavg()[2], 2)},
        },
        "temperature": {},
        "memory": {},
        "swap": {},
        "disks": {},
        "process": {},
        "network": {},
    }

    # CPU Temp
    temp_info = psutil.sensors_temperatures(fahrenheit=False)
    for label, sensors in temp_info.items():
        for sensor in sensors:
            stats["temperature"][f"{label}_{sensor.label}"] = {
                "value": int(sensor.current),
                "unit": "°C",
            }

    # Memory
    memory = psutil.virtual_memory()
    stats["memory"] = {
        "total": {"value": int(memory.total / 1024 / 1024), "unit": "MB"},
        "available": {"value": int(memory.available / 1024 / 1024), "unit": "MB"},
        "percent_used": {"value": int(memory.percent), "unit": "%"},
    }

    # Swap
    swap = psutil.swap_memory()
    stats["swap"] = {
        "total": {"value": int(swap.total / 1024 / 1024), "unit": "MB"},
        "used": {"value": int(swap.used / 1024 / 1024), "unit": "MB"},
        "percent_used": {"value": int(swap.percent), "unit": "%"},
    }

    # Disks
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
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
    network = psutil.net_io_counters(pernic=True)
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
        now = time.time()
        create_time = process.create_time()
        uptime = round(now - create_time, 2)
        mem_info = process.memory_info()
        cpu_percent = process.cpu_percent(interval=0.1)  # Short sample

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


def _get_network_interfaces():

    network_interfaces = []

    for interface, _addresses in psutil.net_if_addrs().items():
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

            if _type == socket.AF_INET:
                _interface_data["type"] = "IPv4"
                _interface_data["ip_address"] = _addr
                _interface_data["netmask"] = netmask
                _interface_data["broadcast"] = broadcast
            elif _type == socket.AF_PACKET:
                _interface_data["mac_address"] = _addr

        network_interfaces.append(_interface_data)

    return network_interfaces


def _get_dhcp_leases() -> list:

    try:
        with sqlite3.connect(DHCP_LEASES_DB) as _conn:

            _cursor = _conn.cursor()
            columns_raw = _cursor.execute("PRAGMA table_info(leases)").fetchall()

            _columns: list[str] = [column[1] for column in columns_raw]
            _leases: list[tuple] = _cursor.execute("SELECT * FROM leases").fetchall()

            result = []
            for _lease in _leases:
                result.append(dict(zip(_columns, _lease)))

            return result

    except Exception as e:
        app_logger.exception(f"Error: Failed to read {DHCP_LEASES_DB} - {e}")
        return []


def _get_dns_history() -> list:

    try:
        with sqlite3.connect(DNS_HISTORY_DB, timeout=DB_TIMEOUT) as _conn:

            _cursor = _conn.cursor().execute("PRAGMA table_info(history)")
            _columns: list[str] = [_column[1] for _column in _cursor.fetchall()]

            _history_records: list[tuple] = _cursor.execute(
                "SELECT * FROM history"
            ).fetchall()

            dns_records = []
            for history_record in _history_records:
                dns_records.append(dict(zip(_columns, history_record)))

            return dns_records

    except Exception as e:
        app_logger.error(f"Error: Failed to read {DNS_HISTORY_DB} - {e}")
        return []


def _get_dns_statistics() -> dict:
    try:
        with sqlite3.connect(DNS_STATS_DB, timeout=DB_TIMEOUT) as _conn:

            _cursor = _conn.cursor().execute("PRAGMA table_info(stats)")
            _columns: list[str] = [_column[1] for _column in _cursor.fetchall()]
            _row: tuple | None = _cursor.execute("SELECT * FROM stats").fetchone()
            if _row and _columns:
                if len(_columns) != len(_row):
                    app_logger.warning(f"Column count ({len(_columns)}) != Row length ({len(_row)})")
                return dict(zip(_columns, _row))

    except Exception as e:
        app_logger.error(f"Failed to read {DNS_STATS_DB} - {e}")

    return {}


def _get_dhcp_statistics() -> dict:
    try:
        with sqlite3.connect(DHCP_STATS_DB) as _conn:

            _cursor = _conn.cursor().execute("PRAGMA table_info(stats)")
            columns: list[str] = [_column[1] for _column in _cursor.fetchall()]

            _cursor.execute("SELECT * FROM stats")
            row: tuple | None = _cursor.fetchone()

            if row and columns:
                if len(columns) != len(row):
                    app_logger.warning(f"[get_dns_statistics] Column count ({len(columns)}) != Row length ({len(row)})")
                return dict(zip(columns, row))

    except Exception as e:
        app_logger.error(f"[get_dns_statistics]  Failed to read {DHCP_STATS_DB} - {e}")

    return {}


def _get_control_list() -> list:

    try:
        with open(DNS_CONTROL_LIST, encoding="utf-8", mode="r") as file_handle:
            _config = json.load(file_handle)
            blacklist_rules = []
            for _key, _value in _config.get("blacklist").items():
                blacklist_rules.extend(_value)
            return sorted(blacklist_rules)
    except Exception as e:
        app_logger.error(f"Error: Failed to read {DNS_CONTROL_LIST} - {e}")

    return []


def _get_system_logs() -> list:

    try:
        with open(LOG_FILE_PATH, mode="r", encoding="utf-8") as file_handle:
            log_entries = []
            for line in file_handle:
                if not line:
                    continue
                line_array = line.strip().split("|")
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
        app_logger.error(f"Failed to read {LOG_FILE_PATH} - {e}")
        return []


class App:
    _worker: multiprocessing.Process | None = None
    _app: Flask | None = None
    _logger = app_logger

    @classmethod
    def _init(cls, ssl_context: tuple, host: str = "0.0.0.0", port: int = 8080):
        cls._ssl_context = ssl_context
        cls._host = host
        cls._port = port

    @classmethod
    def start(cls, ssl_context: tuple, host: str = "0.0.0.0", port: int = 8080):
        if cls._worker and cls._worker.is_alive():
            raise RuntimeError("Flask App already running")
        cls._init(ssl_context=ssl_context, host=host, port=port)
        cls._logger.info(f"Starting Flask App at {cls._host}:{cls._port}.")
        cls._worker = multiprocessing.Process(target=cls._work)
        cls._worker.start()

    @classmethod
    def stop(cls):
        cls._logger.info("Shutting Flask App")
        if cls._worker and cls._worker.is_alive():
            cls._worker.terminate()
            cls._worker.join(timeout=1)
            if cls._worker.is_alive():
                cls._logger.warning("Flask app process did not stop; killing forcefully.")
                cls._worker.kill()
                cls._worker.join(timeout=1)
            cls._logger.info("App stopped.")
            cls._app = None

    @classmethod
    def _work(cls):
        cls._app = Flask(__name__)
        cls._define_routes()
        cls._app.run(host=cls._host,
                     port=cls._port,
                     ssl_context=cls._ssl_context)

    @classmethod
    def _define_routes(cls):

        if cls._app:
            @cls._app.route("/")
            def index():
                return render_template("index.html",
                                       system_stats=_generate_system_stats(),
                                       active_leases=len(_get_dhcp_leases()))

            @cls._app.route("/info")
            def info():
                return render_template("info.html",
                                       system_statistics=_generate_system_stats(),
                                       network_interfaces=_get_network_interfaces())

            @cls._app.route("/dhcp")
            def dhcp():
                return render_template("dhcp.html",
                                       dhcp_statistics=_get_dhcp_statistics(),
                                       dhcp_leases=_get_dhcp_leases())

            @cls._app.route("/dns")
            def dns():
                return render_template("dns.html",
                                       dns_history=_get_dns_history(),
                                       dns_statistics=_get_dns_statistics())

            @cls._app.route("/config", methods=["GET"])
            def get_config():
                _config = {"network": config.get("network", "lan"),
                           "dns": config.get("dns"),
                           "dhcp": config.get("dhcp")}
                return render_template("config.html",
                                       config=deepcopy(_config),
                                       dns_control_list=_get_control_list())

            @cls._app.route("/logs")
            def logs():
                return render_template("logs.html", system_logs=_get_system_logs())

            @cls._app.errorhandler(404)
            def not_found(error):
                return render_template("404.html"), 404
