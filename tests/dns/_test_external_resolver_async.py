import time
from ipaddress import IPv4Address
from unittest.mock import MagicMock

import pytest
from dnslib import DNSRecord

from src.services.dns.external_resolver_async import AsyncExternalResolverService


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

def test_init_real_dns(logger, dns_servers):
    AsyncExternalResolverService.init(
        logger=logger,
        dns_servers=dns_servers,
        timeout=3,
        timeout_buffer=1,
        max_msg_size=1500,
    )

    assert AsyncExternalResolverService.dns_servers is not None
    assert len(AsyncExternalResolverService.dns_servers) == len(dns_servers)


def test_resolve_external_real_dns(logger, dns_servers, dns_request):
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

def test_batch_real_dns_queries(logger, dns_servers, domains):
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

    total = sum(response_times)
    avg = total / len(response_times)
    min_t = min(response_times)
    max_t = max(response_times)

    print("\n=== Async DNS batch test ===")
    print(f"Total requests : {len(requests)}")
    print(f"Success        : {successes}")
    print(f"Failures       : {failures}")
    print(f"Avg per query  : {avg * 1000:.3f} ms")
    print(f"Min per query  : {min_t * 1000:.3f} ms")
    print(f"Max per query  : {max_t * 1000:.3f} ms")

    assert successes > 0
