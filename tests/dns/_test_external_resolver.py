import time
from ipaddress import IPv4Address
from os import cpu_count
from unittest.mock import MagicMock

import pytest
from dnslib import DNSRecord

from src.services.dns.external_resolver_async import AsyncExternalResolverService
from src.services.dns.external_resolver import ExternalResolverService


# -------------------------
# Shared fixtures
# -------------------------

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
    base = [
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
    return base * 25


# =========================
# AsyncExternalResolverService tests
# =========================

def test_async_init_real_dns(logger, dns_servers):
    AsyncExternalResolverService.init(
        logger=logger,
        dns_servers=dns_servers,
        timeout=3,
        timeout_buffer=1,
        max_msg_size=1500,
    )

    assert AsyncExternalResolverService.dns_servers is not None
    assert len(AsyncExternalResolverService.dns_servers) == len(dns_servers)


def test_async_resolve_external_real_dns(logger, dns_servers, dns_request):
    AsyncExternalResolverService.init(
        logger=logger,
        dns_servers=dns_servers,
        timeout=3,
        timeout_buffer=1,
        max_msg_size=1500,
    )

    reply = AsyncExternalResolverService.resolve_external(dns_request)

    assert reply is not None
    assert reply.header.rcode == 0
    assert len(reply.rr) > 0


def test_async_batch_real_dns_queries(logger, dns_servers, domains):
    AsyncExternalResolverService.init(
        logger=logger,
        dns_servers=dns_servers,
        timeout=1,
        timeout_buffer=1,
        max_msg_size=1232,
    )

    requests = [DNSRecord.question(domain) for domain in domains]

    successes = 0
    failures = 0
    response_times = []

    for req in requests:
        start = time.monotonic()
        reply = AsyncExternalResolverService.resolve_external(req)
        response_times.append(time.monotonic() - start)

        if reply and reply.header.rcode == 0:
            successes += 1
        else:
            failures += 1

    avg = sum(response_times) / len(response_times)

    print("\n=== Async DNS batch test ===")
    print(f"Total requests : {len(requests)}")
    print(f"Success        : {successes}")
    print(f"Failures       : {failures}")
    print(f"Avg per query  : {avg * 1000:.3f} ms")
    print(f"Min per query  : {min(response_times) * 1000:.3f} ms")
    print(f"Max per query  : {max(response_times) * 1000:.3f} ms")

    assert successes > 0


# =========================
# ExternalResolverService (threaded) tests
# =========================

def test_threaded_init_start_stop_real_dns(logger, dns_servers):
    ExternalResolverService.init(
        logger=logger,
        dns_servers=dns_servers,
        timeout=3,
        timeout_buffer=1,
        max_msg_size=1500,
        workers=1,
    )

    ExternalResolverService.start()
    assert ExternalResolverService._executor is not None

    ExternalResolverService.stop()
    assert ExternalResolverService._executor is None


def test_threaded_resolve_external_real_dns(logger, dns_servers, dns_request):
    ExternalResolverService.init(
        logger=logger,
        dns_servers=dns_servers,
        timeout=3,
        timeout_buffer=1,
        max_msg_size=1500,
        workers=1,
    )

    ExternalResolverService.start()
    reply = ExternalResolverService.resolve_external(dns_request)
    ExternalResolverService.stop()

    assert reply is not None
    assert reply.header.rcode == 0
    assert len(reply.rr) > 0


def test_threaded_batch_real_dns_queries_workers(logger, dns_servers, domains):
    cpu_counter = int(cpu_count() or 4)
    worker_settings = [1, 2, cpu_counter, cpu_counter * 2]
    sleep_time = 0.02

    for workers in worker_settings:
        ExternalResolverService.init(
            logger=logger,
            dns_servers=dns_servers,
            timeout=1,
            timeout_buffer=1,
            max_msg_size=1500,
            workers=workers,
        )
        ExternalResolverService.start()

        requests = [DNSRecord.question(domain) for domain in domains]

        successes = 0
        failures = 0
        response_times = []

        for req in requests:
            start = time.monotonic()
            reply = ExternalResolverService.resolve_external(req)
            response_times.append(time.monotonic() - start)

            if reply and reply.header.rcode == 0:
                successes += 1
            else:
                failures += 1

            time.sleep(sleep_time)

        ExternalResolverService.stop()

        avg = sum(response_times) / len(response_times)

        print(f"\n=== DNS batch test with {workers} workers ===")
        print(f"Total requests : {len(requests)}")
        print(f"Success        : {successes}")
        print(f"Failures       : {failures}")
        print(f"Avg per query  : {avg * 1000:.4f} ms")
        print(f"Min per query  : {min(response_times) * 1000:.4f} ms")
        print(f"Max per query  : {max(response_times) * 1000:.4f} ms")

        assert successes > 0
