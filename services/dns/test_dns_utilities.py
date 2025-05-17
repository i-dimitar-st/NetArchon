#!/usr/bin/env python3

import unittest
from scapy.all import IP, UDP, DNS, DNSQR, sr1, DNSRR
from dns_utilities import DNSQuery, DNSQueries,is_valid_domain,is_valid_external_domain


class TestIsValidExternalDomain(unittest.TestCase):

    def test_valid_fqdn_with_trailing_dot(self):
        self.assertTrue(is_valid_external_domain(DNSQR(qname=b"daji.example.")))

    def test_valid_domain_without_trailing_dot(self):
        self.assertTrue(is_valid_external_domain( DNSQR(qname=b"example.com")))

    def test_single_label_domain_invalid(self):
        self.assertFalse(is_valid_external_domain(DNSQR(qname=b"localhost")))

    def test_label_with_hyphen_inside(self):
        self.assertTrue(is_valid_external_domain(DNSQR(qname=b"my-domain.com")))

    def test_label_starts_with_hyphen(self):
        self.assertFalse(is_valid_external_domain(DNSQR(qname=b"-invalid.com")))

    def test_label_ends_with_hyphen(self):
        self.assertFalse(is_valid_external_domain(DNSQR(qname=b"invalid-.com")))

    def test_empty_label(self):
        self.assertFalse(is_valid_external_domain(DNSQR(qname=b".com")))

    def test_domain_too_long(self):
        long_domain = "a" * 254 + ".com"
        self.assertFalse(is_valid_external_domain(DNSQR(qname=long_domain.encode())))

    def test_non_dnsqr_input(self):
        self.assertFalse(is_valid_external_domain("not a DNSQR"))

    def test_qname_is_bytes(self):
        self.assertTrue(is_valid_external_domain(DNSQR(qname=b"valid-domain.org")))

    def test_qname_is_str(self):
        self.assertTrue(is_valid_external_domain(DNSQR(qname="valid-domain.org")))

    def test_malformed(self):
        self.assertFalse(is_valid_external_domain(DNSQR(qname='initplayback')))

class TestIsValidDomain(unittest.TestCase):

    def test_valid_domain_simple(self):
        self.assertTrue(is_valid_domain(DNSQR(qname='example.com')))

    def test_valid_domain_with_subdomain(self):
        self.assertTrue(is_valid_domain(DNSQR(qname='sub.domain.co.uk')))

    def test_invalid_domain_starts_with_hyphen(self):
        self.assertFalse(is_valid_domain(DNSQR(qname='-invalid.com')))

    def test_invalid_domain_too_long(self):
        long_label = 'a' * 64
        self.assertFalse(is_valid_domain(DNSQR(qname=f'{long_label}.com')))

    def test_invalid_domain_label_characters(self):
        self.assertFalse(is_valid_domain(DNSQR(qname='inv@lid.com')))

    def test_empty_qname(self):
        self.assertFalse(is_valid_domain(DNSQR(qname='')))

    def test_qname_is_none(self):
        self.assertFalse(is_valid_domain(DNSQR(qname=None)))
    
    def test_malformed(self):
        self.assertTrue(is_valid_domain(DNSQR(qname='initplayback')))

class TestDNSQuery(unittest.TestCase):

    def test_valid_inputs(self):
        """DNS = 1.1.1.1 + query=android-context-data.googleapis.com"""
        dns_server = '1.1.1.1'
        query = "android-context-data.googleapis.com"
        dns_query = DNSQuery(dns_server_ip=dns_server)
        dns_query_record = DNSQR(qname=query, qtype="A", qclass="IN")

        response = dns_query.query(dns_query=dns_query_record)

        self.assertIsNotNone(response)
        self.assertTrue(response.haslayer(DNS))
        self.assertEqual(response[DNS].qd.qname.decode().rstrip('.'), query)
        self.assertGreater(response[DNS].ancount, 0)


class TestDNSQueries(unittest.TestCase):

    def test_query_all(self):
        """1.1.1.3,1.1.1.1,9.9.9.9 + android-context-data.googleapis.com"""
        servers = ["1.1.1.3", "1.1.1.1", "9.9.9.9"]
        qname = "android-context-data.googleapis.com"
        query_record = DNSQR(qname=qname, qtype="A", qclass="IN")
        response = DNSQueries(servers).query_best_from_multiple_servers(dns_query_record=query_record)

        self.assertIsInstance(response, IP)
        self.assertIsNotNone(response)
        self.assertTrue(response.haslayer(DNS))
        self.assertEqual(response[DNS].qd.qname.decode().rstrip('.'), qname)


def test():
    unittest.main(verbosity=2)


if __name__ == "__main__":
    test()
