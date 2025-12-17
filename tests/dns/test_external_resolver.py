import time
from ipaddress import IPv4Address
from os import cpu_count
from unittest.mock import MagicMock

import pytest
from dnslib import DNSRecord

from src.services.dns.external_resolver import ExternalResolverService


@pytest.fixture
def logger():
    return MagicMock()

@pytest.fixture
def dns_servers():
    return [
        IPv4Address("1.1.1.1"),
        IPv4Address("8.8.8.8"),
    ]

@pytest.fixture
def dns_request():
    return DNSRecord.question("google.com")

@pytest.fixture
def domains():
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
        "npmjs.com"
    ] * 25


def test_init_start_stop_real_dns(logger, dns_servers):
    ExternalResolverService.init(
        logger=logger,
        dns_servers=dns_servers,
        timeout=3,
        timeout_buffer=1,
        max_msg_size=1500,
        workers=1
    )
    ExternalResolverService.start()
    assert ExternalResolverService._executor is not None
    ExternalResolverService.stop()
    assert ExternalResolverService._executor is None


def test_resolve_external_real_dns(logger, dns_servers, dns_request):
    ExternalResolverService.init(
        logger=logger,
        dns_servers=dns_servers,
        timeout=3,
        timeout_buffer=1,
        max_msg_size=1500,
        workers=1
    )
    ExternalResolverService.start()
    reply = ExternalResolverService.resolve_external(dns_request)
    ExternalResolverService.stop()
    assert reply is not None
    assert reply.header.rcode == 0  # NOERROR
    assert len(reply.rr) > 0


def test_batch_real_dns_queries_workers(logger,dns_servers,domains):
    cpu_counter = int(cpu_count() or 4)
    worker_settings = [1, 2,cpu_counter,cpu_counter*2]
    sleep_time=0.02

    for workers in worker_settings:
        ExternalResolverService.init(
            logger=logger,
            dns_servers=dns_servers,
            timeout=1,
            timeout_buffer=1,
            max_msg_size=1500,
            workers=workers
        )
        ExternalResolverService.start()
        requests = [DNSRecord.question(domain) for domain in domains]

        successes = 0
        failures = 0
        response_times = []

        for req in requests:
            _start = time.monotonic()
            reply = ExternalResolverService.resolve_external(req)
            response_times.append(time.monotonic()-_start)
            if reply and reply.header.rcode == 0:
                successes += 1
            else:
                failures += 1
            time.sleep(sleep_time)


        total_response_time = sum(response_times)
        avg_response_time = total_response_time / len(response_times)
        min_response_time = min(response_times)
        max_response_time = max(response_times)

        ExternalResolverService.stop()
        print("\n")
        print(f"=== DNS batch test with {workers} workers ===")
        print(f"Total requests : {len(requests)}")
        print(f"Success        : {successes}")
        print(f"Failures       : {failures}")
        print(f"Total time     : {total_response_time:.2f}s")
        print(f"Avg per query  : {avg_response_time*1000:.4f} ms")
        print(f"Min per query  : {min_response_time*1000:.4f} ms")
        print(f"Max per query  : {max_response_time*1000:.4f} ms\n")

        assert successes > 0
