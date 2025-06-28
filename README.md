# NetArchon

**Pre-release** — NetArchon is currently in active development. APIs, behavior, and structure may change.

## Overview

**NetArchon** is a self-hosted network control platform designed for managing and securing local networks. It runs efficiently on dedicated devices like Raspberry Pi and offers:

-   Robust **DHCP server** with ARP-based IP conflict detection
-   Production-grade **recursive DNS resolver** featuring caching and domain/URL/IP filtering
-   **Traffic monitoring** tools for enhanced network visibility
-   **Flask-based web interface** for seamless control and diagnostics
-   Real-time **visualization** through Grafana dashboards
-   LSTM-based recurrent neural network blacklist engine for proactive threat filtering

The project architecture follows a strict class-per-module pattern. While this approach may feel somewhat detached from typical OOP conventions, it is intentionally chosen to prioritize long-term simplicity and memory stability.

This design enforces:

-   Encapsulation of functionality
-   Clear modularity and separation of concerns
-   Thread-safe operations and lifecycle management

Ideally, this structure simplifies testing, maintenance, and future extensions.

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

### DNS Server

-   Asynchronous recursive resolution with parallel queries to multiple external resolvers for faster failover and reduced latency
-   Pattern-based filtering supporting exact matches, wildcards, and rule-based (fnmatch-style) filtering for domains, IPs, and full URLs
-   Dynamic blacklist management with automatic periodic reloads without service interruption
-   Local static zones enabling host overrides for custom domain-to-IP mappings within the network
-   Multi-layer caching strategy combining TTL-based caching with MRU eviction and query deduplication to optimize response times and reduce upstream queries
-   Robust query deduplication preventing repeated processing of identical queries within a short timeframe
-   Full lifecycle management of services with graceful startup, shutdown, and restart capabilities
-   Real-time blacklisting enforcement integrated into query processing pipeline, returning REFUSED responses immediately
-   Comprehensive metrics and query history tracking for analytics and monitoring
-   Standard DNS query/response over UDP with transaction ID validation and protection against spoofing
-   Support for error responses including REFUSED and SERVFAIL on blacklist hits or resolution failures
-   TTL caching and local zone overrides ensuring authoritative responses for internal domains

#### Built to follow

-   [RFC 1034](https://datatracker.ietf.org/doc/html/rfc1034)
-   [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035)

**Partial / Pending Support:**

-   EDNS(0) ([RFC 6891](https://datatracker.ietf.org/doc/html/rfc6891)) for extended DNS capabilities
-   TCP fallback for handling large DNS messages
-   DNSSEC ([RFC 4033–4035](https://datatracker.ietf.org/doc/html/rfc4033)) for secure DNS validation
-   NXDOMAIN caching ([RFC 2308](https://datatracker.ietf.org/doc/html/rfc2308)) to reduce repeated negative queries
-   Full support for QCLASS/QTYPE variations
-   CNAME/DNAME chaining and proper handling of DNS aliasing
-   Handling of truncation bit and response size limits for UDP packets

### Blacklisting & Threat Detection

-   Centralized filtering for DNS and DHCP queries
-   Static blacklists/whitelists with wildcards, regex, URL paths
-   Community threat intelligence feeds integration
-   LSTM-based detection for suspicious domains
-   Real-time scoring and dynamic blocking

### Traffic Monitoring

-   Packet capture and passive analysis via Scapy
-   Logs DHCP/DNS events, device activity, anomalies
-   Maintains historical query and lease data

### Web Dashboard

-   Flask-based interface
-   Real-time lease tables and DNS query logs
-   Rule configuration and diagnostics
-   Optional role-based access control

### Visualization

-   Grafana integration using SQLite data
-   Live dashboards for DNS, DHCP, and filtering events

## Requirements

-   Linux (Raspberry Pi OS, Debian, Ubuntu)
-   Python 3.8+
-   Python packages: `scapy`, `dnslib`, `flask`, `torch`, `apscheduler`, `jinja2`, etc.

## Installation

... pending
