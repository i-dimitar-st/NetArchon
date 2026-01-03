import logging
import socket
import socketserver
import threading
import time
from typing import Generator
from unittest.mock import MagicMock, patch

import dnslib
import pytest

from src.models.models import DNSReqMsg
from src.services.dns.resolver_service import ResolverService

_MOCK_LOGGER = False

# =============================
# Mock & Patch Dependencies
# =============================
@pytest.fixture(autouse=True)
def patch_resolver_dependencies(monkeypatch) -> None:

    class _Metric:
        def add_sample(self, *args, **kwargs) -> None:
            pass

    monkeypatch.setattr(
        "src.services.dns.resolver_service.dns_metrics", _Metric()
    )
    monkeypatch.setattr(
        "src.services.dns.resolver_service.dns_metrics_external", _Metric()
    )
    monkeypatch.setattr(
        "src.services.dns.resolver_service.received_metrics", _Metric()
    )
    monkeypatch.setattr(
        "src.services.dns.resolver_service.dns_per_server_metrics", {}
    )

    class _MockDnsStatsDb:
        @classmethod
        def increment(cls, *args, **kwargs) -> None:
            pass

    monkeypatch.setattr(
        "src.services.dns.resolver_service.DnsStatsDb", _MockDnsStatsDb
    )

    class _MockDnsQueryHistoryDb:
        @classmethod
        def add_query(cls, *args, **kwargs) -> None:
            pass

    monkeypatch.setattr(
        "src.services.dns.resolver_service.DnsQueryHistoryDb", _MockDnsQueryHistoryDb
    )


# =============================
# Fixtures
# =============================


@pytest.fixture(scope="session", autouse=True)
def logger() -> logging.Logger:
    """Global logger fixture shared across all tests."""
    if not _MOCK_LOGGER:
        return MagicMock()
    else:
        log = logging.getLogger("test_logger")
        log.setLevel(logging.DEBUG)
        if not log.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
            )
            handler.setFormatter(formatter)
            log.addHandler(handler)
        return log


@pytest.fixture(scope="module")
def test_hostname() -> str:
    return "127.0.0.1"


@pytest.fixture(scope="module")
def test_dns_port() -> int:
    return 35353


@pytest.fixture
def base_lag() -> float:
    return 0.003


@pytest.fixture
def dns_servers() -> list[str]:
    return ["127.0.0.1", "127.0.0.2", "127.0.0.3"]


# =============================
# Mock DNS Server
# =============================

class MockDNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        request = dnslib.DNSRecord.parse(data)

        reply = request.reply()
        reply.add_answer(
            dnslib.RR(
                str(request.q.qname),
                dnslib.QTYPE.A,
                rdata=dnslib.A("127.0.0.1"),
                ttl=60,
            )
        )
        delay = getattr(self.server, "delay", 0)
        if delay:
            time.sleep(delay)

        sock.sendto(reply.pack(), self.client_address)


class MockDNSServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    daemon_threads = True

    def __init__(self, server_address, handler_cls, delay=0.0):
        super().__init__(server_address, handler_cls)
        self.delay = delay


def start_mock_dns_server(ip: str, port: int, delay: float) -> MockDNSServer:
    server = MockDNSServer((ip, port), MockDNSHandler, delay=delay)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture
def mock_dns_servers(dns_servers, test_dns_port, base_lag) -> Generator[None, None, None]:
    servers = [start_mock_dns_server(ip, test_dns_port, base_lag) for ip in dns_servers]
    yield
    for server in servers:
        server.shutdown()
        server.server_close()



# ==========
# Unit Tests
# ==========


def test_resolver_lifecycle(logger):
    import queue
    import time

    from src.libs.libs import MRUCache

    _TEST_HOSTNAME = "127.0.0.1"
    _TEST_PORT = 53535
    _MAX_WORKERS = 2

    with patch.object(ResolverService, "_send_reply", return_value=None):

        ResolverService.init(logger, _TEST_HOSTNAME, _TEST_PORT, max_workers=_MAX_WORKERS)
        assert isinstance(ResolverService._dns_received_dedup_cache, MRUCache)
        assert isinstance(ResolverService._dns_cache, object)
        assert isinstance(ResolverService._dns_request_queue, queue.Queue)

        ResolverService.start()
        time.sleep(1)
        assert ResolverService._dns_received_worker.is_alive()
        for worker in ResolverService._dns_processor_worker:
            assert worker.is_alive()
        assert ResolverService._dns_cache_purge_worker.is_alive()

        # Check socket
        sock = ResolverService._dns_socket
        assert sock is not None
        assert sock.fileno() != -1
        assert sock.getsockname() == (_TEST_HOSTNAME, _TEST_PORT)
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        test_sock.sendto(b"test", (_TEST_HOSTNAME, _TEST_PORT))
        data, addr = sock.recvfrom(1500)
        assert data == b"test"

        test_sock.close()

        ResolverService.stop()
        assert not ResolverService._dns_received_worker.is_alive()
        assert not ResolverService._dns_cache_purge_worker.is_alive()
        for worker in ResolverService._dns_processor_worker:
            assert not worker.is_alive()

        assert ResolverService._dns_socket is None


def test_deduplication(logger):

    _TEST_HOSTNAME = "127.0.0.1"
    _TEST_PORT = 53535
    _MAX_WORKERS = 2

    with patch.object(ResolverService, "_work_listen_traffic", return_value=None), \
         patch.object(ResolverService, "_work_purge_cache", return_value=None), \
         patch.object(ResolverService, "_work_process_dns_packet", return_value=None), \
         patch.object(ResolverService, "_send_reply", return_value=None):

        ResolverService.init(logger, _TEST_HOSTNAME, _TEST_PORT,max_workers=_MAX_WORKERS)
        ResolverService.start()

        _request = dnslib.DNSRecord.question("google.com")
        _dns_req = DNSReqMsg(_request.pack(), (_TEST_HOSTNAME, _TEST_PORT))

        _request_additional = dnslib.DNSRecord.question("google-test.com")
        _dns_req_additional = DNSReqMsg(_request_additional.pack(), (_TEST_HOSTNAME, _TEST_PORT))

        ResolverService._dns_received_dedup_cache.add(_dns_req.dedup_key)
        assert ResolverService._dns_received_dedup_cache.is_present(_dns_req.dedup_key)
        assert ResolverService._dns_received_dedup_cache.size() == 1

        ResolverService._dns_received_dedup_cache.add(_dns_req.dedup_key)
        assert ResolverService._dns_received_dedup_cache.size() == 1

        ResolverService._dns_received_dedup_cache.add(_dns_req_additional.dedup_key)
        assert ResolverService._dns_received_dedup_cache.is_present(_dns_req_additional.dedup_key)
        assert ResolverService._dns_received_dedup_cache.size() == 2

        ResolverService._dns_received_dedup_cache.clear()
        assert ResolverService._dns_received_dedup_cache.size() == 0

        ResolverService.stop()


def test_handle_blacklisted(logger):

    _TEST_HOSTNAME = "127.0.0.1"
    _TEST_PORT = 53535
    _MAX_WORKERS = 2


    def _is_blacklisted_mock(domain: str) -> bool:
        return "ads" in domain

    with patch.object(ResolverService, "_work_listen_traffic", return_value=None), \
         patch.object(ResolverService, "_work_process_dns_packet", return_value=None), \
         patch.object(ResolverService, "_work_purge_cache", return_value=None), \
         patch.object(ResolverService, "_send_reply", return_value=None), \
         patch("src.services.dns.blacklist_service.BlacklistService.is_blacklisted", side_effect=_is_blacklisted_mock), \
         patch("src.services.dns.db.DnsStatsDb.increment") as mock_increment:

        ResolverService.init(logger, _TEST_HOSTNAME, _TEST_PORT,max_workers=_MAX_WORKERS)
        ResolverService.start()

        _blocked: dnslib.DNSRecord = dnslib.DNSRecord.question("ads-example.com")
        _allowed = dnslib.DNSRecord.question("example.com")

        assert ResolverService._handle_blacklist(DNSReqMsg(_blocked.pack(), (_TEST_HOSTNAME, _TEST_PORT))) is True
        assert ResolverService._handle_blacklist(DNSReqMsg(_allowed.pack(), (_TEST_HOSTNAME, _TEST_PORT))) is False

        ResolverService.stop()


def test_handle_cache_hit(logger):

    _TEST_HOSTNAME = "127.0.0.1"
    _TEST_PORT = 53535
    _MAX_WORKERS = 2

    with patch.object(ResolverService, "_work_listen_traffic", return_value=None), \
         patch.object(ResolverService, "_work_purge_cache", return_value=None), \
         patch.object(ResolverService, "_work_process_dns_packet", return_value=None), \
         patch.object(ResolverService, "_send_reply", return_value=None), \
         patch("src.services.dns.db.DnsStatsDb.increment") as mock_increment:

        ResolverService.init(logger, _TEST_HOSTNAME, _TEST_PORT,max_workers=_MAX_WORKERS)
        ResolverService.start()

        _request = dnslib.DNSRecord.question("example.com")
        _dns_req = DNSReqMsg(_request.pack(), (test_hostname, test_dns_port))

        assert not ResolverService._handle_cache_hit(_dns_req)
        ResolverService._dns_cache[_dns_req.cache_key] = (_request, 60, time.time())
        assert ResolverService._handle_cache_hit(_dns_req)

        ResolverService.stop()


def test_handle_server_fail(logger):

    _TEST_HOSTNAME = "127.0.0.1"
    _TEST_PORT = 53535

    with patch.object(ResolverService, "_work_listen_traffic", return_value=None), \
         patch.object(ResolverService, "_work_purge_cache", return_value=None), \
         patch.object(ResolverService, "_work_process_dns_packet", return_value=None), \
         patch.object(ResolverService, "_send_reply", return_value=None), \
         patch("src.services.dns.db.DnsStatsDb.increment") as mock_increment:

        ResolverService.init(logger, _TEST_HOSTNAME, _TEST_PORT)
        ResolverService.start()

        _request = dnslib.DNSRecord.question(qname="nonexistent.com",qtype="A")
        _dns_req = DNSReqMsg(_request.pack(), (_TEST_HOSTNAME, _TEST_PORT))

        assert ResolverService._handle_server_fail(_dns_req)
        ResolverService.stop()


def test_handle_external(logger):

    def _query_mock(ok=True):
            if not ok:
                return None, None
            mock_response = dnslib.DNSRecord.question("example.com").reply()
            mock_response.add_answer(dnslib.RR("example.com", dnslib.QTYPE.A, rdata=dnslib.A("1.2.3.4"), ttl=60))
            return mock_response.pack(), _TEST_HOSTNAME

    _TEST_HOSTNAME = "127.0.0.1"
    _TEST_PORT = 53535

    with patch.object(ResolverService, "_work_listen_traffic", return_value=None), \
         patch.object(ResolverService, "_work_purge_cache", return_value=None), \
         patch.object(ResolverService, "_work_process_dns_packet", return_value=None), \
         patch.object(ResolverService, "_send_reply", return_value=None),\
         patch("src.services.dns.metrics.dns_metrics_external.add_sample") as mock_external_metrics, \
         patch("src.services.dns.metrics.dns_per_server_metrics", new_callable=dict) as mock_per_server_metrics, \
         patch("src.services.dns.external_resolver.ExternalResolverService.resolve", side_effect=lambda _req: _query_mock(True)), \
         patch("src.services.dns.db.DnsStatsDb.increment") as mock_increment:

        ResolverService.init(logger, host=_TEST_HOSTNAME, port=_TEST_PORT)
        ResolverService.start()

        request = dnslib.DNSRecord.question(qname="example.com", qtype="A")
        dns_req = DNSReqMsg(request.pack(), (_TEST_HOSTNAME, _TEST_PORT))
        assert ResolverService._handle_external(dns_req) is True
        assert dns_req.cache_key in ResolverService._dns_cache

        dns_req_fail = DNSReqMsg(request.pack(), (_TEST_HOSTNAME, _TEST_PORT))
        with patch(
            "src.services.dns.external_resolver.ExternalResolverService.resolve",
            side_effect=lambda _req: _query_mock(False)
        ):
            assert ResolverService._handle_external(dns_req_fail) is False


        ResolverService.stop()


def test_send_reply(logger):
    from unittest.mock import MagicMock

    TEST_HOSTNAME = "127.0.0.1"
    TEST_PORT = 53535
    with patch.object(ResolverService, "_work_listen_traffic", return_value=None), \
        patch("src.services.dns.db.DnsStatsDb.increment") as mock_increment:
        ResolverService.init(logger, host=TEST_HOSTNAME, port=TEST_PORT)
        ResolverService.start()

        _mock_sock = MagicMock()
        ResolverService._dns_socket = _mock_sock
        ResolverService._dns_socket_lock = threading.RLock()

        _request = dnslib.DNSRecord.question(qname="example.com",qtype="A")
        _response = _request.reply()
        _response.add_answer(dnslib.RR("example.com", dnslib.QTYPE.A, rdata=dnslib.A("1.2.3.4"), ttl=60))

        ResolverService._send_reply(DNSReqMsg(_request.pack(), (TEST_HOSTNAME, TEST_PORT)), _response)

        assert _mock_sock.sendto.called
        _sent_data, _addr = _mock_sock.sendto.call_args[0]
        assert _addr == (TEST_HOSTNAME, TEST_PORT)
        assert dnslib.DNSRecord.parse(_sent_data).header.id == _request.header.id
        assert dnslib.DNSRecord.parse(_sent_data).q.qname == _request.q.qname
        assert dnslib.DNSRecord.parse(_sent_data).rr[0].rdata == dnslib.A("1.2.3.4")

        ResolverService._dns_socket = None
        ResolverService.stop()


# # =============
# # Threads Tests
# # =============

def test_work_purge_cache(logger):
    _TEST_HOSTNAME = "127.0.0.1"
    _TEST_PORT = 53535

    with patch.object(ResolverService, "_work_listen_traffic", return_value=None), \
         patch.object(ResolverService, "_work_process_dns_packet", return_value=None), \
         patch.object(ResolverService, "_send_reply", return_value=None):

        key1 = "key_long"
        key2 = "key_short"

        ResolverService._dns_cache[key1] = (dnslib.DNSRecord.question("example.com"), 60, time.time())
        ResolverService._dns_cache[key2] = (dnslib.DNSRecord.question("example.com"), 1, time.time() - 2)

        assert len(ResolverService._dns_cache) == 2
        assert ResolverService._purge_cache(ResolverService._dns_cache_lock, ResolverService._dns_cache) == 1
        assert key2 not in ResolverService._dns_cache
        assert key1 in ResolverService._dns_cache


@pytest.mark.parametrize("success_percent, packets_counter",[(0.5, 100),(1.0, 200)])
def test_work_listen_traffic_real_socket(logger, success_percent,packets_counter):
    import random
    import socket

    import dnslib

    RESOLVER_HOST, RESOLVER_PORT = "127.0.0.1", 53535

    valid_qry = dnslib.DNSRecord.question("example.com", qtype="A")
    invalid_qry = b"invalid_dns_packet"

    def _send_dns_packets(packets_counter=100, success_rate=1.0) -> tuple[int,int]:
        total = valid = 0
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            for _ in range(packets_counter):
                total += 1
                if random.random() < success_rate:
                    sender.sendto(valid_qry.pack(), (RESOLVER_HOST, RESOLVER_PORT))
                    valid += 1
                else:
                    sender.sendto(invalid_qry, (RESOLVER_HOST, RESOLVER_PORT))
        return total, valid

    with patch.object(ResolverService, "_work_process_dns_packet", return_value=None), \
         patch.object(ResolverService, "_send_reply", return_value=None):

        ResolverService.init(
            logger,
            host=RESOLVER_HOST,
            port=RESOLVER_PORT,
            msg_size=1500,
            receive_queue_size=1000
        )
        ResolverService.start()
        time.sleep(1)

        _processed_counter = 0
        _start = time.perf_counter()
        _total_sent, _valid_sent = _send_dns_packets(packets_counter, success_percent)
        _enqueued = []

        while _processed_counter < _valid_sent:
            while not ResolverService._dns_request_queue.empty():
                _enqueued.append(ResolverService._dns_request_queue.get_nowait())
                _processed_counter += 1
            time.sleep(0.0005)

        _delay = time.perf_counter() - _start
        print(
            f"success:{success_percent} total:{_total_sent} valid:{_valid_sent} "
            f"delay:{_delay:.3f}s or {_total_sent/_delay if _delay else 0:.3f} packets/sec."
        )

        assert len(_enqueued) == _processed_counter
        for data, _addr in _enqueued:
            assert data == valid_qry.pack()

        ResolverService.stop()

@pytest.mark.parametrize("max_workers,request_count",[(1, 250),(8, 250),(16, 250)])
def test_work_process_dns_packet_udp(logger, max_workers, request_count):
    import itertools

    RESOLVER_HOST, RESOLVER_PORT = "127.0.0.1", 53535
    CLIENT_HOST, CLIENT_PORT = "127.0.0.1", 54545

    def _handle_blacklisted_mock(dns_req):
        if "ads" in dns_req.domain.lower():
            reply = dns_req.dns_message.reply()
            reply.header.rcode = 5  # REFUSED
            ResolverService._send_reply(dns_req, reply)
            return True
        return False

    def _handle_external_mock(dns_req) -> bool:
        if "fail.com" in dns_req.domain:
            return False  # forces SERVFAIL path

        reply = dns_req.dns_message.reply()
        reply.add_answer(
            dnslib.RR(
                dns_req.domain,
                dnslib.QTYPE.A,
                rdata=dnslib.A("1.2.3.4"),
                ttl=60,
            )
        )
        reply.header.rcode = 0
        ResolverService._send_reply(dns_req, reply)

        with ResolverService._dns_cache_lock:
            ResolverService._dns_cache[dns_req.cache_key] = (reply, 60, time.time())

        time.sleep(0.1)
        return True

    with patch.object(ResolverService, "_handle_blacklist", side_effect=_handle_blacklisted_mock), \
         patch.object(ResolverService, "_handle_external", side_effect=_handle_external_mock):

        ResolverService.init(
            logger,
            host=RESOLVER_HOST,
            port=RESOLVER_PORT,
            max_workers=max_workers,
            max_ttl_cache_size=2000,
            max_dedup_size=100,
            receive_queue_size=2000
        )
        ResolverService.start()
        time.sleep(0.5)

        client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_sock.bind((CLIENT_HOST, CLIENT_PORT))
        client_sock.settimeout(5)

        domains = itertools.cycle(
            [
                "example.com",
                "example-ads.com",
                "test.com",
                "fail.com",
                "123"
            ]
        )

        for i in range(request_count):
            query = dnslib.DNSRecord.question(next(domains), qtype="A")
            query.header.id = i + 1
            client_sock.sendto(query.pack(), (RESOLVER_HOST, RESOLVER_PORT))
            time.sleep(0.0001)

        replies = []
        start = time.perf_counter()

        while len(replies) < request_count:
            data, _ = client_sock.recvfrom(1500)
            replies.append(dnslib.DNSRecord.parse(data))
            _data = dnslib.DNSRecord.parse(data)
            # print(_data.header.id, _data.q.qname, _data.header.rcode)

        ResolverService.stop()
        client_sock.close()

        elapsed = time.perf_counter() - start
        print(
            f"workers={max_workers}, requests={request_count}, "
            f"delay={elapsed:.3f}s {request_count / elapsed if elapsed else 0:.3f} packets/sec."
        )

        assert len(replies) == request_count

        for reply in replies:
            qname = str(reply.q.qname)
            if "ads" in qname:
                assert reply.header.rcode == 5  # REFUSED
            if "123" in qname:
                assert reply.header.rcode == 3  # NXDOMAIN
            elif "fail.com" in qname:
                assert reply.header.rcode == 2  # SERVFAIL



# =================
# Integration Tests
# =================
