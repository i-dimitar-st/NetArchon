from dnslib import CLASS
from dnslib import DNSRecord, DNSLabel, QTYPE, RR, A, DNSQuestion
from utils.dns_utils import DNSUtils


def make_dns_record(
    rname=DNSLabel("example.com."),
    rtype=QTYPE.A,
    rclass=CLASS.IN,
    rdata=A("1.2.3.4"),
    ttls=None,
) -> DNSRecord:
    if ttls is None:
        ttls = [300]

    record = DNSRecord()
    record.add_question(DNSQuestion(rname, rtype))
    for _ttl in ttls:
        record.add_answer(
            RR(rname=rname, rtype=rtype, rclass=rclass, ttl=_ttl, rdata=rdata)
        )
    return record


def test_normalize_domain():
    assert DNSUtils.normalize_domain("Example.COM.") == "example.com"
    assert DNSUtils.normalize_domain("Test.Domain") == "test.domain"
    assert DNSUtils.normalize_domain("") == ""


def test_is_valid_domain():
    cases = [
        ("example.com", True),
        ("sub-domain.example.com", True),
        ("valid-domain_123.com", True),
        ("", False),
        ("a" * 64 + ".com", False),
        ("-bad.example.com", False),
        ("bad-.example.com", False),
        ("bad..example.com", False),
        ("a." * 127 + "a", False),
        ("bad!domain.com", False),
    ]

    for domain, expected in cases:
        assert (
            DNSUtils.is_valid_domain(domain) == expected
        ), f"Failed for domain: {domain}"


def test_is_local_query():
    cases = [
        ("home.local", "home.local", True),  # exact zone match
        ("sub.home.local", "home.local", True),  # subdomain match
        ("a.b.home.local", "home.local", True),  # deeper subdomain
        ("host.other.local", "home.local", False),  # different zone
        ("invalid_query", "home.local", False),  # invalid
    ]

    for query, zone, expected in cases:
        assert type(query) is str, f"Query must be str, got {type(query)}"
        assert type(zone) is str, f"Zone must be str, got {type(zone)}"
        assert type(expected) is bool, f"Expected must be bool, got {type(expected)}"
        assert (
            DNSUtils.is_local_query(query, zone) == expected
        ), f"Failed for {query=}, {zone=}"


def test_extract_hostname():
    zone = "home.local"

    # Positive
    assert DNSUtils.extract_hostname("host.home.local", zone) == "host"
    assert DNSUtils.extract_hostname("subdomain.home.local", zone) == "subdomain"
    assert DNSUtils.extract_hostname("home.local", zone) == ""

    # Negative
    assert DNSUtils.extract_hostname("otherdomain.com", zone) == ""
    assert DNSUtils.extract_hostname("deep.sub.home.local", zone) == "deep.sub"


def test_extract_ttl():
    assert DNSUtils.extract_ttl(make_dns_record(ttls=[10, 20, 5, 30])) == 5
    assert DNSUtils.extract_ttl(make_dns_record(ttls=[42])) == 42
    assert DNSUtils.extract_ttl(make_dns_record(ttls=[])) == 0


def test_generate_cache_key():
    dns_record = make_dns_record()
    key = DNSUtils.generate_cache_key(dns_record)
    assert key == (dns_record.q.qname, dns_record.q.qtype)
