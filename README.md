# NetArchon

**Pre-release** — NetArchon is currently in active development. APIs, behavior, and structure may change.

---

## Overview

**NetArchon** is a self-hosted network control platform for managing and securing local networks. Designed to run on a dedicated device (e.g., Raspberry Pi), it provides:

-   Robust **DHCP server** with ARP-based IP conflict detection
-   Production-grade **recursive DNS resolver** with caching and domain/URL/IP filtering
-   **Traffic monitoring** for network visibility
-   **Flask-based web interface** for control and diagnostics
-   Real-time **visualization** using Grafana
-   **Machine learning-driven blacklist engine** for proactive filtering

---

## Core Components

### DHCP Server

-   Supports DHCP message types as per [RFC 2131](https://datatracker.ietf.org/doc/html/rfc2131):  
    DISCOVER, OFFER, REQUEST, DECLINE, RELEASE, INFORM
-   Basic lease management: issuing, renewing, releasing IP addresses
-   Address conflict detection using ARP
-   Transaction ID validation and message deduplication
-   Sends appropriate ACK and NAK responses based on lease state
-   Persistent lease storage with periodic lease cleanup

**Planned enhancements:**

-   DHCP relay agent (RFC 2131 Section 4.3.2)
-   DHCPv6 support (RFC 3315)
-   Authentication/security extensions
-   Advanced options (PXE boot, vendor-specific options)

---

### DNS Server

-   Recursive resolution with fallback to external resolvers
-   Pattern-based filtering for domains, IPs, and full URLs
-   Local static zones for host overrides
-   TTL-based caching with MRU eviction
-   Query deduplication and asynchronous resolution pipeline

Built to follow DNS core standards ([RFC 1034](https://datatracker.ietf.org/doc/html/rfc1034), [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035)):

-   Standard DNS query/response over UDP
-   Recursive resolution with transaction ID validation
-   TTL caching and static zone overrides
-   Error responses including `REFUSED` and `SERVFAIL`
-   Real-time blacklisting and deduplication

**Partial / Pending Support:**

-   EDNS(0) (RFC 6891)
-   TCP fallback for large packets
-   DNSSEC (RFC 4033–4035)
-   NXDOMAIN caching (RFC 2308)
-   Full QCLASS/QTYPE support
-   CNAME/DNAME chaining
-   Truncation bit and response size limits

---

### Blacklisting & Threat Detection

-   Centralized filtering for DNS and DHCP queries
-   Static blacklists/whitelists with wildcards, regex, URL paths
-   Community threat intelligence feeds integration
-   LSTM-based detection for suspicious domains
-   Real-time scoring and dynamic blocking

---

### Traffic Monitoring

-   Packet capture and passive analysis via Scapy
-   Logs DHCP/DNS events, device activity, anomalies
-   Maintains historical query and lease data

---

### Web Dashboard

-   Flask-based interface
-   Real-time lease tables and DNS query logs
-   Rule configuration and diagnostics
-   Optional role-based access control

---

### Visualization

-   Grafana integration using SQLite data
-   Live dashboards for DNS, DHCP, and filtering events

---

## Requirements

-   Linux (Raspberry Pi OS, Debian, Ubuntu)
-   Python 3.8+
-   Python packages: `scapy`, `dnslib`, `flask`, `torch`, `apscheduler`, `jinja2`, etc.

---

## Installation

```bash
git clone https://gitlab.com/i.dimitar.st/netarchon.git
cd netarchon

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt

./run.sh
```
