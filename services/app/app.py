import sys
import platform
import logging
import threading
import json
import sqlite3
import time
import os
import copy
from datetime import datetime, timezone
from pathlib import Path
from flask import Flask, render_template, request, jsonify
from services.service_logger import MainLogger
# from services.rabbitmq_service import RabbitMqConsumer

# fmt: off
sys.path.append('/projects/gitlab/netarchon/venv/lib/python3.12/site-packages')
import psutil # type: ignore
import pika # type: ignore
# fmt: on

app_logger = MainLogger.get_logger(service_name="GUI", log_level=logging.DEBUG)
app_logger.info('Started APP')

ROOT_PATH = Path(__file__).resolve().parents[2]
DNS_DB_PATH = ROOT_PATH / "db" / "dns.sqlite3"
DHCP_CONFIG_PATH = ROOT_PATH / "config" / "dhcp_config.json"
DNS_CONFIG_PATH = ROOT_PATH / "config" / "dns_config.json"
DNS_CONTROL_LIST = ROOT_PATH / "config" / "dns_control_list.json"
LOG_FILE_PATH = ROOT_PATH / "logs" / "main.log"
ACTIVE_NETWORK_INTERFACE = 'enp2s0'
DHCP_STATISTICS = {}
LEASES = []


def generate_system_stats() -> dict:
    process = psutil.Process()
    stats = {
        'system': {
            'datetime': {'value': time.ctime()},
            'uptime': {'value': int(time.time() - psutil.boot_time()), 'unit': 'sec'},
            'os_name': {'value': platform.system()},
            'os_version': {'value': platform.version()},
            'os_release': {'value': platform.release()},
            'architecture': {'value': platform.machine()},
            'processor': {'value': platform.processor()},
            'hostname': {'value': platform.node()},
            'python_version': {'value': sys.version},
            'python_executable': {'value': sys.executable},
        },
        'cpu': {
            'usage': {'value': psutil.cpu_percent(interval=0.5), 'unit': '%'},
            'usage_per_core': {'value': psutil.cpu_percent(interval=0.5, percpu=True), 'unit': '%'},
            'frequency_per_core': {'value': [int(freq.current) for freq in psutil.cpu_freq(percpu=True)], 'unit': 'MHz'},
            'cores': {'value': psutil.cpu_count(logical=True), 'unit': 'cores'},
            'load_1min': {'value': round(os.getloadavg()[0], 2)},
            'load_5min': {'value': round(os.getloadavg()[1], 2)},
            'load_15min': {'value': round(os.getloadavg()[2], 2)},
        },
        'temperature': {},
        'memory': {},
        'swap': {},
        'disks': {},
        'process': {},
        'network': {},
    }

    # CPU Temp
    temp_info = psutil.sensors_temperatures(fahrenheit=False)
    for label, sensors in temp_info.items():
        for sensor in sensors:
            stats['temperature'][f'{label}_{sensor.label}'] = {'value': int(sensor.current), 'unit': '°C'}

    # Memory
    memory = psutil.virtual_memory()
    stats['memory'] = {
        'total': {'value': int(memory.total / 1024 / 1024), 'unit': 'MB'},
        'available': {'value': int(memory.available / 1024 / 1024), 'unit': 'MB'},
        'percent_used': {'value': int(memory.percent), 'unit': '%'},
    }

    # Swap
    swap = psutil.swap_memory()
    stats['swap'] = {
        'total': {'value': int(swap.total / 1024 / 1024), 'unit': 'MB'},
        'used': {'value': int(swap.used / 1024 / 1024), 'unit': 'MB'},
        'percent_used': {'value': int(swap.percent), 'unit': '%'},
    }

    # Disks
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
            if "ext" in part.fstype:
                stats['disks'][f'disk_{part.mountpoint}_total'] = {'value': int(usage.total / 1024 / 1024), 'unit': 'MB'}
                stats['disks'][f'disk_{part.mountpoint}_used'] = {'value': int(usage.used / 1024 / 1024), 'unit': 'MB'}
        except PermissionError:
            continue

    # Network: Stats from all network interfaces (Flat structure)
    network = psutil.net_io_counters(pernic=True)
    for iface, counters in network.items():
        stats['network'][f'{iface}_sent'] = {'value': int(counters.bytes_sent / 1024 / 1024), 'unit': 'MB'}
        stats['network'][f'{iface}_recv'] = {'value': int(counters.bytes_recv / 1024 / 1024), 'unit': 'MB'}
        stats['network'][f'{iface}_packets_sent'] = {'value': counters.packets_sent}
        stats['network'][f'{iface}_packets_recv'] = {'value': counters.packets_recv}
        stats['network'][f'{iface}_errors_sent'] = {'value': counters.errout}
        stats['network'][f'{iface}_errors_recv'] = {'value': counters.errin}

    # Current Process Stats
    with process.oneshot():
        mem_info = process.memory_info()
        cpu_times = process.cpu_times()
        ctx_switches = process.num_ctx_switches()
        io_counters = process.io_counters()
        open_files = process.open_files()
        stats['process'] = {
            'pid': {'value': process.pid},
            'name': {'value': process.name()},
            'status': {'value': process.status()},
            'memory_rss': {'value': int(mem_info.rss / 1024 / 1024), 'unit': 'MB'},
            'memory_vms': {'value': int(mem_info.vms / 1024 / 1024), 'unit': 'MB'},
            'cpu_time_user': {'value': round(cpu_times.user, 2), 'unit': 'sec'},
            'cpu_time_system': {'value': round(cpu_times.system, 2), 'unit': 'sec'},
            'threads': {'value': process.num_threads()},
            'context_switches_voluntary': {'value': ctx_switches.voluntary},
            'context_switches_involuntary': {'value': ctx_switches.involuntary},
            'io_read_bytes': {'value': int(io_counters.read_bytes / 1024), 'unit': 'KB'},
            'io_write_bytes': {'value': int(io_counters.write_bytes / 1024), 'unit': 'KB'},
            'open_files_count': {'value': len(open_files)},
        }

    return stats


def get_network_interfaces():
    network_interfaces = []

    for interface, addresses in psutil.net_if_addrs().items():
        interface_data = {
            "name": interface,
            "type": None,
            "ip_address": None,
            "netmask": None,
            "broadcast": None,
            "mac_address": None
        }

        for address in addresses:
            addr_type = address.family
            addr = address.address
            netmask = address.netmask
            broadcast = address.broadcast

            if addr_type == 2:
                interface_data["type"] = "IPv4"
                interface_data["ip_address"] = addr
                interface_data["netmask"] = netmask
                interface_data["broadcast"] = broadcast
            elif addr_type == 17:
                interface_data["mac_address"] = addr

        network_interfaces.append(interface_data)

    return network_interfaces


def get_dhcp_system_config() -> dict:

    try:
        with open(DHCP_CONFIG_PATH, encoding="utf-8", mode="r") as file_handle:
            return json.load(file_handle)
    except Exception as e:
        app_logger.error(f"Error: Failed to read {DHCP_CONFIG_PATH} - {e}")
        return None


def get_dns_system_config() -> dict:

    try:
        with open(DNS_CONFIG_PATH, encoding="utf-8", mode="r") as file_handle:
            return json.load(file_handle)
    except Exception as e:
        app_logger.error(f"Error: Failed to read {DNS_CONFIG_PATH} - {e}")
        return None


def get_dns_history() -> list:

    try:
        with sqlite3.connect(DNS_DB_PATH) as conn:

            cursor = conn.cursor()

            cursor.execute("PRAGMA table_info(history)")
            columns: list[str] = [column[1] for column in cursor.fetchall()]

            cursor.execute("SELECT * FROM history")
            history_records: list[tuple] = cursor.fetchall()

            dns_records = []
            for history_record in history_records:
                dns_records.append(dict(zip(columns, history_record)))

            return dns_records

    except Exception as e:
        app_logger.error(f"Error: Failed to read {DNS_DB_PATH} - {e}")
        return []


def get_dns_statistics() -> dict:
    try:
        with sqlite3.connect(DNS_DB_PATH) as conn:

            cursor = conn.cursor()

            cursor.execute("PRAGMA table_info(stats)")
            columns: list[str] = [column[1] for column in cursor.fetchall()]

            cursor.execute("SELECT * FROM stats")
            row: tuple | None = cursor.fetchone()

            if row and columns:
                if len(columns) != len(row):
                    app_logger.warning(f"[get_dns_statistics] Column count ({len(columns)}) != Row length ({len(row)})")
                return dict(zip(columns, row))
            else:
                return {}

    except Exception as e:
        app_logger.error(f"[get_dns_statistics]  Failed to read {DNS_DB_PATH} - {e}")
        return {}


def get_control_list() -> dict:

    try:
        with open(DNS_CONTROL_LIST, encoding="utf-8", mode="r") as file_handle:
            return json.load(file_handle)
    except Exception as e:
        app_logger.error(f"Error: Failed to read {DNS_CONTROL_LIST} - {e}")
        return None


def get_system_logs() -> list:

    try:
        with open(LOG_FILE_PATH, "r") as file_handle:
            log_entries = []
            log_lines = file_handle.readlines()
            for line in log_lines:
                if not line:
                    continue
                line_array = line.strip().split("|")
                log_entries.append({
                    "timestamp": line_array[0].strip(),
                    "level": line_array[1].strip(),
                    "service": line_array[2].strip(),
                    "message": line_array[3].strip()
                })
            return log_entries
    except Exception as e:
        app_logger.error(f"Failed to read {LOG_FILE_PATH} - {e}")
        return []


def queue_processor_dhcp(message: bytes) -> None:
    _message_dict = json.loads(message.decode('utf-8'))
    message_type = _message_dict.get("type", None)
    message_payload = _message_dict.get("payload", None)
    if message_payload and message_type == 'statistics':
        update_dhcp_statistics(message_payload)
    if message_payload and message_type == 'dhcp-leases':
        update_dhcp_leases(message_payload)


def queue_processor_dns(message: bytes) -> None:
    _message_dict = json.loads(message.decode('utf-8'))
    message_type = _message_dict.get("type", None)
    message_payload = _message_dict.get("payload", None)
    if message_payload and message_type == 'history':
        update_dns_history(message_payload)


def update_dns_history(payload: list = []):
    pass


def update_dhcp_statistics(payload: dict = {}):
    if not payload:
        return
    DHCP_STATISTICS.update(payload)


def update_dhcp_leases(_leases: list = None):
    if _leases is None:
        _leases = []

    for _lease in _leases:
        mac_address = _lease[0]

        existing_lease = next((lease for lease in LEASES if lease[0] == mac_address), None)

        if existing_lease:
            LEASES[LEASES.index(existing_lease)] = _lease
        else:
            LEASES.append(_lease)


class RabbitMqConsumer:
    def __init__(self, host: str = '127.0.0.1', port: int = 5672, encoding: str = 'utf-8', message_queue_name: str = "dhcp_server", consumer_tag: str = 'default_consumer', processor_function: callable = None):
        """Initializes the RabbitMqConsumer with one message queue and consumer tag"""
        self.host = host
        self.port = port
        self.encoding = encoding
        self.stop_event = threading.Event()
        self.message_queue_name = message_queue_name
        self.consumer_tag = consumer_tag
        self.connection = None
        self.channel = None
        self._processor_function = processor_function

    def _get_connection_parameters(self):
        """Return default connection params."""
        return pika.ConnectionParameters(
            host=self.host,                             # RabbitMQ server address (hostname or IP)
            port=self.port,                             # Port number for RabbitMQ (default: 5672)
            virtual_host='/',                           # Virtual host on the RabbitMQ server (default: '/')
            credentials=pika.PlainCredentials('guest', 'guest'),  # Credentials (username and password), default is 'guest'/'guest'
            heartbeat=600,                              # Ensures the connection stays alive (default: 600 seconds)
            ssl_options=None,                           # SSL/TLS options (None means no SSL/TLS connection)
            connection_attempts=3,                      # Number of connection attempts before giving up (default: 3)
            retry_delay=5,                              # Delay (in seconds) between retry attempts (default: 5 seconds)
            blocked_connection_timeout=None,            # Timeout in seconds for blocked connections (None means no timeout)
            client_properties=None,                     # Custom client properties (None means no custom properties)
            frame_max=131072,                           # Maximum size of frames that can be sent (None means no limit)
            locale='en_US',                             # Locale setting for the connection (None means the default locale)
            socket_timeout=None,                        # Socket timeout in seconds (None means no timeout)
        )

    def _get_queue_parameters(self):
        return {'queue': self.message_queue_name,
                'durable': True}

    def listen_message(self):
        """Starts listening for requests on RabbitMQ."""
        app_logger.info(f"Starting RabbitMQ listener for message queue: {self.message_queue_name}...")

        try:
            self.connection = pika.BlockingConnection(self._get_connection_parameters())
            self.channel = self.connection.channel()

            self.channel.queue_declare(**self._get_queue_parameters())
            self.channel.basic_consume(queue=self.message_queue_name,
                                       on_message_callback=self.process_message,
                                       consumer_tag=self.consumer_tag)

            while not self.stop_event.is_set():
                self.connection.process_data_events(time_limit=0.2)
                time.sleep(0.2)

            app_logger.info("RabbitMQ listener stopped gracefully.")

        except Exception as e:
            app_logger.error(f"Error starting RabbitMQ listener:{e}")
        finally:
            # Ensure to close the connection when stop event is set
            if self.connection:
                self.connection.close()

    def process_message(self, channel, method, properties, body):
        """Handles requests from RabbitMQ and stores in-memory."""
        try:
            # message = json.loads(body.decode(self.encoding))
            channel.basic_ack(delivery_tag=method.delivery_tag)
            self._processor_function(body)

        except Exception as e:
            app_logger.error(f"Error processing request: {e}")
            channel.basic_nack(delivery_tag=method.delivery_tag)

    def start(self):
        """Starts both RabbitMQ listeners in separate threads."""
        rabbitmq_thread = threading.Thread(target=self.listen_message,
                                           name="rabbitmq-listener",
                                           daemon=True)
        rabbitmq_thread.start()
        app_logger.info(f"RabbitMQ listeners {self.consumer_tag} thread started.")

    def stop(self):
        """Stops both RabbitMQ listeners gracefully."""
        app_logger.debug("Stopping RabbitMQ listeners...")
        self.stop_event.set()  # Set the stop event to signal the threads to stop
        app_logger.debug("Stop event set. Listeners will stop after processing the current message.")

        # Close connection on stop event
        if self.connection and not self.connection.is_closed:
            self.connection.close()
            app_logger.info("RabbitMQ connection closed.")


def run_rabbitmq_consumer():
    """Starts the RabbitMQ Consumer."""
    app_logger.info("Starting RabbidMQ Consumer")
    rabbitmq_dhcp_service = RabbitMqConsumer(message_queue_name="dhcp_server", consumer_tag='app_gui',
                                             processor_function=queue_processor_dhcp)
    rabbitmq_dhcp_service.start()
    rabbitmq_dns_service = RabbitMqConsumer(message_queue_name="dns_server", consumer_tag='app_gui', processor_function=queue_processor_dns)
    rabbitmq_dns_service.start()


rabbit_mq_thread = threading.Thread(target=run_rabbitmq_consumer, daemon=True)
rabbit_mq_thread.start()

app = Flask(__name__)
app.logger = app_logger


@app.route('/')
def index():
    return render_template(
        'index.html',
        system_stats=generate_system_stats(),
        active_leases=len(LEASES))


@app.route('/info')
def info_and_statistics():
    return render_template(
        'info.html',
        system_statistics=generate_system_stats(),
        network_interfaces=get_network_interfaces()
    )


@app.route('/dhcp')
def dhcp():
    return render_template(
        'dhcp.html',
        dhcp_statistics=copy.deepcopy(DHCP_STATISTICS),
        dhcp_leases=copy.deepcopy(LEASES))


@app.route('/dns')
def dns():
    return render_template(
        'dns.html',
        dns_history=get_dns_history(),
        dns_statistics=get_dns_statistics()
    )


@app.route('/config', methods=['GET'])
def config():
    return render_template(
        'config.html',
        dhcp_config=get_dhcp_system_config(),
        dns_config=get_dns_system_config(),
        dns_control_list=get_control_list()
    )


@app.route('/logs')
def logs():
    return render_template(
        'logs.html',
        system_logs=get_system_logs()
    )


@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404


if __name__ == '__main__':
    print("Error: This script should be run as a module, not directly.")
    # sys.exit(1)  # Exit with an error code (1) indicating incorrect execution
    # app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
