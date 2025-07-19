import concurrent.futures
import socket
import sys
import threading
import time
import unittest
from pathlib import Path

from dnslib import QTYPE, DNSRecord

root_dir = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(root_dir))
from services.dns.dns import DNSUtils

root_dir = Path(__file__).parent.parent.resolve()
TIMEOUT = 15
PORT = 53
HOST = "0.0.0.0"
QTYPE = "A"
DOMAIN = "google.com"


def send_dns_query(qname=DOMAIN, qtype=QTYPE, server=HOST, port=PORT, timeout=TIMEOUT):

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.settimeout(timeout)
            request = DNSRecord.question(qname, qtype.upper()).pack()
            sock.sendto(request, (server, port))
            data, _ = sock.recvfrom(1232)
            response = DNSRecord.parse(data)
            return response
        except socket.timeout:
            return None

        except Exception as err:
            return None


def print_response(response: DNSRecord = None):

    if not response:
        raise ValueError("Missing input")

    ips_ttls = [(str(rr.rdata), rr.ttl) for rr in response.rr if rr.rtype in (QTYPE.A, QTYPE.AAAA)]

    print(
        f"id:{response.header.id} | rcode:{response.header.rcode} qname:{response.q.qname} qtype:{response.q.qtype}"
    )
    print(
        f"answers:{len(response.rr)} | auth:{len(response.auth)} | addl:{len(response.ar)} | ip_ttl:{ips_ttls}"
    )

    if response.rr:
        print("\nANSWER")
        for rr in response.rr:
            print(rr)

    if response.auth:
        print("\nAUTHORITY")
        for rr in response.auth:
            print(rr)

    if response.ar:
        print("\nADDITIONAL")
        for rr in response.ar:
            print(rr)


class TestDNSResolver(unittest.TestCase):

    def test_0_valid_domain(self):
        domain = "google.com"
        qtype = "A"
        _res = send_dns_query(domain, qtype)
        self.assertTrue(_res and _res.header.rcode == 0)

    def test_1_invalid_domain_too_long(self):
        domain = f"{'abc'*300}.com"
        qtype = "A"
        _res = send_dns_query(domain, qtype)
        self.assertTrue(_res is None or _res.header.rcode != 0)

    def test_2_invalid_domain_invalid_chars(self):
        domain = "invalid_domain"
        qtype = "A"
        _res = send_dns_query(domain, qtype)
        self.assertTrue(_res is None or _res.header.rcode != 0)

    def test_3_invalid_domain_ip_instead_of_name(self):
        domain = "127.0.0.1"
        qtype = "A"
        _res = send_dns_query(domain, qtype)
        self.assertTrue(_res is None or _res.header.rcode != 0)

    def test_4_invalid_domain_malformed(self):
        domain = "..bad..name.."
        qtype = "A"
        _res = send_dns_query(domain, qtype)
        self.assertTrue(_res is None or _res.header.rcode != 0)

    def test_5_burst_queries_same_url(self):
        results = []
        lock = threading.Lock()
        _valid_domains = [
            ("google.com", "A"),
            ("microsoft.com", "A"),
            ("apple.com", "A"),
            ("github.com", "A"),
            ("wikipedia.org", "A"),
            ("stackoverflow.com", "A"),
            ("amazon.com", "A"),
            ("openai.com", "A"),
            ("mozilla.org", "A"),
            ("linkedin.com", "A"),
        ]

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(_valid_domains)) as executor:
            futures = {}
            for domain, qtype in _valid_domains:
                submit_time = time.monotonic()
                future = executor.submit(send_dns_query, domain, qtype)
                futures[future] = (domain, qtype, submit_time)

            for future in concurrent.futures.as_completed(futures, timeout=15):
                domain, qtype, submit_time = futures[future]
                try:
                    result = future.result(timeout=10)
                    delay = time.monotonic() - submit_time

                    self.assertIsNotNone(result, msg=f"No response from {domain}")
                    self.assertEqual(result.header.rcode, 0, msg=f"Bad rcode from {domain}")
                    self.assertLess(
                        delay, TIMEOUT + 1, msg=f"Slow response from {domain}: {delay:.2f}s"
                    )

                    with lock:
                        results.append((domain, delay))

                except Exception as e:
                    self.fail(f"Query to {domain} failed with exception: {e}")

        if results:
            delays = [_delay for _res, _delay in results]
            print("\n Burst Stats")
            print(f"Min: {min(delays):.3f}s")
            print(f"Max: {max(delays):.3f}s")
            print(f"Avg: {sum(delays) / len(delays):.3f}s")

    def test_6_continuous_queries(self):

        results = []
        domains = ["google.com", "facebook.com"]
        qtype = "A"

        for i in range(30):
            start = time.monotonic()
            domain = domains[i % len(domains)]
            result = send_dns_query(domain, qtype, timeout=10)
            delay = time.monotonic() - start
            self.assertIsNotNone(result)
            self.assertEqual(result.header.rcode, 0)
            self.assertLess(delay, TIMEOUT + 1)
            results.append(result.header.rcode)
            time.sleep(1)
        self.assertEqual(len(results), 30)


if __name__ == "__main__":
    unittest.main(verbosity=2)
