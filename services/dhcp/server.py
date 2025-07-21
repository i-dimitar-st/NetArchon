from collections import deque
from logging import Logger
from queue import Empty, Full, Queue
from threading import RLock, Thread, current_thread

from scapy.packet import Packet
from scapy.sendrecv import sniff

from config.config import config
from services.dhcp.client_discovery import ClientDiscoveryService
from services.dhcp.db_dhcp_leases import DHCPStorage
from services.dhcp.db_dhcp_stats import DHCPStats
from services.dhcp.db_persistence import DbPersistanceService
from services.dhcp.message_handler import DHCPMessageHandler
from services.dhcp.models import DHCPMessage, DHCPResponseFactory
from services.dhcp.reservation_cache import LeaseReservationCache
from services.logger.logger import MainLogger

DHCP_CONFIG = config.get("dhcp")
INTERFACE = DHCP_CONFIG.get("interface")
PORT = DHCP_CONFIG.get("port")
SERVER_IP = DHCP_CONFIG.get("ip")
SERVER_MAC = DHCP_CONFIG.get("mac")
BROADCAST_IP = DHCP_CONFIG.get("broadcast_ip")
BROADCAST_MAC = DHCP_CONFIG.get("broadcast_mac")
SUBNET_MASK = DHCP_CONFIG.get("subnet")
ROUTER = DHCP_CONFIG.get("router_ip")
NAME_SERVER = DHCP_CONFIG.get("ntp_server")

LEASE_TIME = int(DHCP_CONFIG.get("lease_time_seconds"))
REBINDING_TIME_RATIO = float(DHCP_CONFIG.get("rebinding_time_ratio"))
REBINDING_TIME = int(LEASE_TIME * REBINDING_TIME_RATIO)
RENEWAL_TIME_RATIO = float(DHCP_CONFIG.get("renewal_time_ratio"))
RENEWAL_TIME = int(LEASE_TIME * RENEWAL_TIME_RATIO)

MTU = int(DHCP_CONFIG.get("mtu"))

RECEIVED_QUEUE_SIZE = int(DHCP_CONFIG.get("rcvd_queue_size"))
INBOUND_REQ_DEQUE_SIZE = int(DHCP_CONFIG.get("deque_size"))
BOOTP_FLAG_BROADCAST = 0x8000

WORKERS = DHCP_CONFIG.get("workers")
TIMEOUTS = DHCP_CONFIG.get("timeouts")
WORKER_GET_TIMEOUT = float(TIMEOUTS.get("worker_get"))
WORKER_SLEEP_TIMEOUT = float(TIMEOUTS.get("worker_sleep"))
WORKER_JOIN_TIMEOUT = float(TIMEOUTS.get("worker_join"))


dhcp_logger: Logger = MainLogger.get_logger(service_name="DHCP", log_level="debug")


class DHCPServer:

    _lock = RLock()
    _initialised = False
    _running = False
    _workers = {}

    @classmethod
    def init(
        cls,
        received_queue_size=RECEIVED_QUEUE_SIZE,
        inbound_requests_deque_size=INBOUND_REQ_DEQUE_SIZE,
    ) -> None:

        if cls._initialised:
            raise RuntimeError("Already Init")

        cls._received_queue = Queue(maxsize=received_queue_size)
        cls._dedup_queue = deque(maxlen=inbound_requests_deque_size)

        DHCPResponseFactory.init(
            server_ip=SERVER_IP,
            server_mac=SERVER_MAC,
            port=PORT,
            broadcast_mac=BROADCAST_MAC,
            broadcast_ip=BROADCAST_IP,
            flags=BOOTP_FLAG_BROADCAST,
            router=ROUTER,
            subnet_mask=SUBNET_MASK,
            name_server=NAME_SERVER,
            lease_time=LEASE_TIME,
            renewal_time=RENEWAL_TIME,
            rebinding_time=REBINDING_TIME,
            mtu=MTU,
        )
        DHCPStorage.init(logger=dhcp_logger)
        DHCPStats.init(logger=dhcp_logger)
        DHCPMessageHandler.init(logger=dhcp_logger)
        LeaseReservationCache.init()
        ClientDiscoveryService.init(logger=dhcp_logger)
        DbPersistanceService.init(logger=dhcp_logger)

        cls._initialised = True

    @classmethod
    def start(cls):
        """Start all necessary threads"""

        if not cls._initialised:
            raise RuntimeError("Not init.")
        if cls._running:
            raise RuntimeError("Server already running.")
        cls._running = True

        with cls._lock:

            ClientDiscoveryService.start()
            DbPersistanceService.start()

            _traffic_listener = Thread(
                target=cls._traffic_listener, name="dhcp-traffic-listener", daemon=True
            )
            _traffic_listener.start()
            cls._workers["dhcp-traffic_listener"] = _traffic_listener

            for _index in range(WORKERS):
                _worker = Thread(
                    target=cls._processor, name=f"dhcp-worker-{_index}", daemon=True
                )
                _worker.start()
                cls._workers[f"dhcp-worker-{_index}"] = _worker
            dhcp_logger.info("Started %s", cls.__name__)

    @classmethod
    def stop(cls, worker_join_timeout=WORKER_JOIN_TIMEOUT):

        if not cls._running:
            raise RuntimeError("Server not running.")

        with cls._lock:
            cls._running = False
            DbPersistanceService.stop()
            ClientDiscoveryService.stop()
            for _name, thread in cls._workers.items():
                if thread.is_alive():
                    thread.join(timeout=worker_join_timeout)
            cls._workers.clear()
            dhcp_logger.info("Stopped %s.", cls.__name__)

    @classmethod
    def restart(cls, worker_join_timeout=WORKER_JOIN_TIMEOUT):
        """Stop and then start the DHCP server cleanly."""
        if not cls._initialised:
            raise RuntimeError("Server not initialized.")
        if not cls._running:
            cls.start()
            return
        cls.stop(worker_join_timeout=worker_join_timeout)
        cls.start()

    @classmethod
    def _traffic_listener(cls, interface=INTERFACE, port=PORT):
        """Start sniffing for DHCP packets on the interface"""
        sniff(
            iface=interface,
            filter=f"ip and udp and port {port}",
            prn=cls._listen,
            stop_filter=lambda _: not cls._running,
            count=0,
            timeout=None,
            store=False,
            session=None,
        )

    @classmethod
    def _listen(cls, packet: Packet):
        """Callback for sniffed DHCP packets; enqueues into processing queue."""
        try:
            cls._received_queue.put_nowait(packet)
        except Full:
            dhcp_logger.warning("Queue full.")
        except Exception as err:
            dhcp_logger.exception("Couldn't enqueue DHCP packet: %s.", err)

    @classmethod
    def _processor(
        cls,
        worker_get_timeout=WORKER_GET_TIMEOUT,
        server_mac=SERVER_MAC,
        server_ip=SERVER_IP,
    ):
        """Main processor function multi threaded."""

        while cls._running:
            dhcp_message = None
            try:
                dhcp_message = DHCPMessage(
                    cls._received_queue.get(timeout=worker_get_timeout)
                )

                if (
                    dhcp_message.mac.lower() == server_mac.lower() or
                    dhcp_message.src_ip.lower() == server_ip.lower()
                ):
                    continue

                with cls._lock:
                    if dhcp_message.dedup_key in cls._dedup_queue:
                        continue
                    cls._dedup_queue.append(dhcp_message.dedup_key)

                DHCPMessageHandler.handle_message(dhcp_message)

            except Empty:
                continue
            except Exception as err:
                dhcp_logger.error("%s processing %s.", current_thread().name, err)
            finally:
                if dhcp_message:
                    cls._received_queue.task_done()
