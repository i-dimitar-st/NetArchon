import os
import random
import socketserver
import statistics
import threading
import time
from typing import Any, Generator
from unittest.mock import MagicMock

import dnslib
import pytest

from src.models.models import DNSReqMsg
from src.services.dns.external_resolver import ExternalResolverService

#  Fixtures

@pytest.fixture
def worker_count() -> int:
    _cpu_count = os.cpu_count() or 4
    return ((_cpu_count + 4) * 4)


@pytest.fixture
def logger() -> MagicMock:
    return MagicMock()

@pytest.fixture
def base_lag() -> float:
    return 0.004

@pytest.fixture
def dns_servers() -> list[str]:
    return ["127.0.0.1", "127.0.0.2","127.0.0.3"]

@pytest.fixture
def dns_servers_real() -> list[str]:
    return ["1.1.1.1", "8.8.8.8","9.9.9.9"]

@pytest.fixture(scope="module")
def dns_port() -> int:
    return 35353

@pytest.fixture(scope="module")
def workers() -> list[int]:
    return [int(((os.cpu_count() or 4) + 4) * 4)]

@pytest.fixture
def dns_request() -> dnslib.DNSRecord:
    return dnslib.DNSRecord.question("google.com")


@pytest.fixture
def dns_request_msg(dns_request) -> DNSReqMsg:
    return DNSReqMsg(dns_request.pack(), ("127.0.0.1", 0))


@pytest.fixture
def domains() -> list[str]:
    return [
        "google.com",
        "cloudflare.com",
        "github.com",
        "stackoverflow.com",
        "python.org",
        "wikipedia.org",
        "mozilla.org",
        "reddit.com",
        "docker.com",
        "npmjs.com",
    ]

@pytest.fixture
def domains_multiplier() -> list[int]:
     return [1,5,10,20]

# Mock Servers

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
        delay = self.server.delay  # type: ignore
        if delay:
            if isinstance(delay, tuple):
                time.sleep(random.uniform(*delay))
            else:
                time.sleep(delay)
        sock.sendto(reply.pack(), self.client_address)


class MockDNSServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    daemon_threads = True
    def __init__(self, server_address, handler_cls, delay=0.0):
        super().__init__(server_address, handler_cls)
        self.delay = delay


def start_mock_dns_server(ip,port,delay) -> MockDNSServer:
    server = MockDNSServer((ip,port), MockDNSHandler, delay=delay)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"Started mock dns @ {ip}:{port} with delay: {delay}.")
    return server


@pytest.fixture(scope="function")
def mock_dns_servers(dns_servers,dns_port,base_lag) -> Generator[None, Any, None]:

    servers = []
    for ip in dns_servers:
        # This delay should match server delay
        delay = base_lag
        server = start_mock_dns_server(ip, dns_port,delay)
        servers.append(server)

    yield

    for server in servers:
        server.shutdown()
        server.server_close()


# Helpers

def helper_simulate_submission_delay(requests_count:int,index:int,base_lag:float) -> None:
    if requests_count*0.2 <= index < requests_count*0.4:
            time.sleep(random.uniform(0.001, 0.002))
    if requests_count*0.6 <= index < requests_count*0.8:
            time.sleep(random.uniform(0.001, 0.002))
    else:
         time.sleep(base_lag)


def helper_pprint_stats(latencies, successes, failures, elapsed,submit_end, worker) -> None:
    latencies.sort()
    print(
        f"DNS batch {worker} workers: {len(latencies)} reqs, "
        f"{successes} success / {failures} fail, "
        f"avg {statistics.mean(latencies)*1000:.1f} ms, "
        f"P50 {statistics.median(latencies)*1000:.1f} ms, "
        f"P90 {latencies[int(0.9*len(latencies))-1]*1000:.1f} ms, "
        f"P99 {latencies[int(0.99*len(latencies))-1]*1000:.1f} ms, "
        f"submit_end {submit_end*1000:.1f} ms, "
        f"elapsed {elapsed*1000:.1f} ms"
    )


def test_resolve_external(
        logger,
        dns_request_msg,
        dns_servers,
        mock_dns_servers,
        dns_port
    ) -> None:
    ExternalResolverService.init(
        logger=logger,
        dns_servers=dns_servers,
        port=dns_port,
        timeout=3,
        timeout_buffer=1,
        max_msg_size=1500,
        workers=1,
    )

    ExternalResolverService.start()
    assert ExternalResolverService._executor is not None

    ExternalResolverService.stop()
    assert ExternalResolverService._executor is None

    ExternalResolverService.start()
    raw_reply,dns_server = ExternalResolverService.resolve(dns_request_msg)
    reply = dnslib.DNSRecord.parse(raw_reply)
    assert dns_server in dns_servers
    assert reply.header.rcode == 0
    assert len(reply.rr) > 0

    ExternalResolverService.stop()


def test_batch_resolve_external_mock_servers(
    logger,
    dns_servers,
    domains,
    mock_dns_servers,
    base_lag,
    dns_port,
    worker_count,
    domain_multiplier = 5
):
    def _resolve_thread(req: DNSReqMsg,submitted_time:float):
        _started: float = time.monotonic()
        _start_delay = _started - submitted_time
        reply = ExternalResolverService.resolve(req)
        duration = time.monotonic() - _started
        print(
            f"{threading.current_thread().name} "
            f"server={reply[1]} "
            f"queue={_start_delay*1000:.1f}ms "
            f"total={duration*1000:.1f}ms"
        )
        with results_lock:
            results.append((reply[0], duration))

    results = []
    threads = []
    results_lock = threading.Lock()
    _domains = domains * domain_multiplier
    fake_addr = ("127.0.0.1", 60000)

    ExternalResolverService.init(
        logger=logger,
        dns_servers=dns_servers,
        port=dns_port,
        timeout=5,
        timeout_buffer=1,
        max_msg_size=1450,
        workers=worker_count,
    )
    ExternalResolverService.start()

    start = time.monotonic()

    requests = [
        DNSReqMsg(
            raw=dnslib.DNSRecord.question(domain).pack(),
            addr=fake_addr,
        )
        for domain in _domains
    ]
    for index,req in enumerate(requests):
        t = threading.Thread(target=_resolve_thread, name=f"tester-thread-{index}", args=(req,time.monotonic(),))
        helper_simulate_submission_delay(len(requests),index,base_lag)
        t.start()
        threads.append(t)
    _sibmit_end = time.monotonic() - start

    for t in threads:
        t.join(timeout=1)

    ExternalResolverService.stop()

    successes = 0
    failures = 0
    latencies = []

    for reply, duration in results:
        latencies.append(duration)
        if reply and dnslib.DNSRecord.parse(reply).header.rcode == 0:
            successes += 1
        else:
            failures += 1

    elapsed = time.monotonic() - start
    helper_pprint_stats(latencies,successes,failures,elapsed,_sibmit_end,worker_count)
    assert failures == 0


def test_batch_resolve_external_real_servers(
    logger,
    dns_servers_real,
    base_lag,
    domains,
    worker_count,
    domain_multiplier=5
):

    def _resolve_thread(req: DNSReqMsg, submitted_time: float):
        started = time.monotonic()
        queue_delay = started - submitted_time
        reply = ExternalResolverService.resolve(req)
        duration = time.monotonic() - started
        print(
            f"{threading.current_thread().name} "
            f"server={reply[1]} "
            f"queue={queue_delay*1000:.1f}ms "
            f"total={duration*1000:.1f}ms"
        )
        with results_lock:
            results.append((reply[0], duration))

    results = []
    threads = []
    results_lock = threading.Lock()
    _domains = domains * domain_multiplier

    ExternalResolverService.init(
        logger=logger,
        dns_servers=dns_servers_real,
        port=53,
        timeout=5,
        timeout_buffer=1,
        max_msg_size=1450,
        workers=worker_count,
    )
    ExternalResolverService.start()

    start = time.monotonic()
    for index, domain in enumerate(_domains):
        t = threading.Thread(
            target=_resolve_thread,
            name=f"real-thread-{index}",
            args=(DNSReqMsg(dnslib.DNSRecord.question(domain).pack(), ("0.0.0.0", 0)), time.monotonic())
        )
        helper_simulate_submission_delay(len(_domains),index,base_lag)
        t.start()
        threads.append(t)
    submit_end = time.monotonic() - start

    for t in threads:
        t.join(timeout=5)

    ExternalResolverService.stop()

    successes = 0
    failures = 0
    latencies = []

    for reply, duration in results:
        latencies.append(duration)
        if reply and dnslib.DNSRecord.parse(reply).header.rcode == 0:
            successes += 1
        else:
            failures += 1

    elapsed = time.monotonic() - start
    helper_pprint_stats(latencies, successes, failures, elapsed, submit_end, worker_count)
    assert failures == 0


def test_pressure_determine_best_worker_count(
    logger,
    dns_servers,
    domains,
    domains_multiplier,
    mock_dns_servers,
    base_lag,
    dns_port
):

    def _resolve_thread(req: DNSReqMsg):
        start = time.monotonic()
        reply = ExternalResolverService.resolve(req)
        with results_lock:
            results.append((reply[0],  time.monotonic() - start))

    cpu_count = os.cpu_count() or 4
    worker_counts = [
        1,
        cpu_count * 1,
        cpu_count * 4,
        cpu_count * 8,
        cpu_count * 16,
        cpu_count * 32
    ]

    worker_totals:dict[int,float] = {}

    for multiplier in domains_multiplier:
        _domains = domains * multiplier
        fake_addr = ("127.0.0.1", 60000)
        results = []
        results_lock = threading.Lock()

        print(f"\n--- Testing total domains: {len(_domains)} ---")

        for worker in worker_counts:
            results.clear()
            threads = []

            ExternalResolverService.init(
                logger=logger,
                dns_servers=dns_servers,
                port=dns_port,
                timeout=15,
                timeout_buffer=1,
                max_msg_size=1450,
                workers=worker,
            )
            ExternalResolverService.start()
            start_time = time.monotonic()

            requests = [
                DNSReqMsg(raw=dnslib.DNSRecord.question(domain).pack(), addr=fake_addr)
                for domain in _domains
            ]

            for index, req in enumerate(requests):
                t = threading.Thread(target=_resolve_thread, args=(req,))
                t.start()
                helper_simulate_submission_delay(len(requests),index,base_lag)
                threads.append(t)

            for t in threads:
                t.join(timeout=10)

            ExternalResolverService.stop()

            successes = 0
            failures = 0
            latencies = []

            for reply, duration in results:
                latencies.append(duration)
                if reply and dnslib.DNSRecord.parse(reply).header.rcode == 0:
                    successes += 1
                else:
                    failures += 1

            elapsed = time.monotonic() - start_time
            if latencies:
                latencies.sort()
                avg = statistics.mean(latencies)
                p50 = statistics.median(latencies)
                p95 = latencies[int(0.95 * len(latencies)) - 1]
                score = (avg * 0.333) + (p95 * 0.333) + (p50 * 0.333)
            else:
                avg = p50 = p95 = score = 0

            print(f"Workers:{worker}, Score:{score:.4f}, Avg:{avg:.4f}, p50:{p50:.4f}, P95:{p95:.4f}, Delay:{elapsed:.4f}")
            worker_totals[worker] = worker_totals.get(worker, 0) + score

    print("Workers sorted by score:", ", ".join(
        f"{worker}:{delay:.4f}"
        for worker, delay in sorted(
            worker_totals.items(),
            key=lambda each: each[1]
            )
        )
    )



