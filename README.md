# NetArchon

## Overview

NetArchon is a local network control platform designed to run on a dedicated device (Raspberry Pi or similar). It empowers you to manage your LAN with:

- **DHCP server** (using `scapy`)
  - Full DHCP protocol handling (DISCOVER, OFFER, REQUEST, etc.)
  - Client-specific time-based access control
  - IP conflict detection via ARP
  - Persistent leases and TTL-based reservations
- **DNS server** (using `dnslib`)
  - Block unwanted IPs, hostnames, **domains, and full URLs with pattern matching**
  - Custom filtering policies for network-wide DNS control
- **Network traffic monitoring** (using `scapy`)
- **Web GUI dashboard** (Flask-based)
  - Real-time overview and configuration
- **Visualization via Grafana**
  - Detailed network stats and history

NetArchon aims to give you full control over your home or small office network with open-source tools.

---

## Features

- Fully featured DHCP server with conflict detection and lease management
- DNS filtering and blocking at the DNS level
- Network statistics collection and monitoring
- Web interface for easy management and overview
- Extensible and modular architecture

---

## Installation

### Requirements

- Linux-based system (Raspberry Pi OS, Ubuntu, Debian recommended)
- Python 3.8+
- `scapy`, `dnslib`, `flask`, and other Python dependencies (install with `pip`)
- Optional: Grafana for visualization

### Quick Setup

```bash
# Clone repository
git clone https://gitlab.com/i.dimitar.st/netarchon.git
cd netarchon

# Create Python virtual environment and activate
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# To finish
run.sh
```
