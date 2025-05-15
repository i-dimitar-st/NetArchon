#!/usr/bin/env python3

import unittest
from scapy.all import IP, UDP, DNS, DNSQR, sr1, DNSRR
from dns_utilities import DNSQuery, DNSQueries


# class TestDNSQuery(unittest.TestCase):

# def test_valid_inputs(self):
#     dns_server = '1.1.1.1'
#     query = "android-context-data.googleapis.com"
#     dns_query = DNSQuery(dns_server_ip=dns_server)
#     dns_query_record = DNSQR(qname=query, qtype="A", qclass="IN")

#     response = dns_query.query(dns_query=dns_query_record)

#     self.assertIsNotNone(response)
#     self.assertTrue(response.haslayer(DNS))
#     self.assertEqual(response[DNS].qd.qname.decode().rstrip('.'), query)
#     self.assertGreater(response[DNS].ancount, 0)


class TestDNSQueries(unittest.TestCase):

    def test_query_all(self):
        servers = ["1.1.1.3", "1.1.1.1", "9.9.9.9"]
        qname = "android-context-data.googleapis.com"
        query_record = DNSQR(qname=qname, qtype="A", qclass="IN")
        response = DNSQueries(servers).query_best_from_multiple_servers(query_question=query_record)

        self.assertIsInstance(response, IP)
        self.assertIsNotNone(response)
        self.assertTrue(response.haslayer(DNS))
        self.assertEqual(response[DNS].qd.qname.decode().rstrip('.'), qname)


def test():
    unittest.main(verbosity=2)


if __name__ == "__main__":
    test()
