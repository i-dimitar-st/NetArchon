# NetArchon

**Pre-release** — NetArchon is currently in active development. APIs, behavior, and structure may change.

## Overview

**NetArchon** is a self-hosted network control platform designed for managing and securing local networks. It runs efficiently on dedicated devices like Raspberry Pi and offers:

-   **DHCP server** with ARP-based IP conflict detection
-   **DNS resolver** featuring caching and domain/URL/IP filtering
-   **Metrics**
-   **GUI (web app)**
-   **Neutral net blacklist** for proactive threat filtering

The project architecture tries to follow "class-as-a-service" more of a lite aktor nets (sort of).

## Features

### DHCP Server

-   DHCP message types as per [RFC 2131](https://datatracker.ietf.org/doc/html/rfc2131):  
    DISCOVER, OFFER, REQUEST, DECLINE, RELEASE, INFORM
-   Lease management: issuing, renewing, releasing IP addresses
-   Address conflict detection using ARP
-   Deduplication (filtering)
-   Persistent lease storage with periodic lease cleanup
-   Lease classes:
    -   Dynamic (DHCP managed)
    -   Static (Static allocation mac->IP as settable by client)
    -   Manual (Discovered clients with static IP set)

### DNS Server

-   Multi-threaded engine for first served server
-   Local static zones enabling host overrides for custom domain-to-IP mappings within the network
-   Caching (TTL based):
    -   Positiv hit caching
    -   Negative hit caching
    -   Configurable
-   Standard UDP query/response
-   Following:
    -   [RFC 1034](https://datatracker.ietf.org/doc/html/rfc1034)
    -   [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035)

### Blacklisting & Threat Detection

-   Static blacklists
-   Fixed and wildcards lookup
-   Live configuration
-   LSTM-based detection for suspicious domains
-   Real-time scoring and dynamic blocking (if enabled)

### Logging

-   Maintains historical query and lease data

### Web Dashboard

-   HTTPS (self generated certs)
-   XSS & script injection protection
-   Real-time lease tables and DNS query logs
-   Real-time metrics
-   Rule configuration and diagnostics
-   Flask

## Requirements

-   Linux (Raspberry Pi OS, Debian, Ubuntu)
-   Python 3.8+
-   Major dependancies: `scapy`, `dnslib`, `flask`, `torch`, `uvicorn`

## Installation

... pending
