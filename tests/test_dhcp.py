import sys
import os
import time
import json
import pytest
from unittest.mock import patch, MagicMock


# Add the parent directory to the sys.path to make 'service' accessible
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Now you can import service
from ..services.dhcp_server import DHCPServer

@pytest.fixture
def dhcp_server():
    server = DHCPServer()
    server.leased_ips.clear()  # Ensure clean state
    return server

def test_load_config(dhcp_server):
    """ Test if the configuration loads correctly """
    assert dhcp_server.server_ip == "192.168.20.100"
    assert dhcp_server.router_ip == "192.168.20.1"
    assert dhcp_server.lease_time == 86400  # Default lease time

def test_get_next_available_ip(dhcp_server):
    """ Test IP allocation """
    allocated_ip = dhcp_server.get_next_available_ip()
    assert allocated_ip is not None
    assert allocated_ip.startswith("192.168.20.")

def test_dhcp_offer_generation(dhcp_server):
    """ Test if DHCP offer packet is generated correctly """
    client_mac = "aa:bb:cc:dd:ee:ff"
    transaction_id = 0x12345678

    offer = dhcp_server.build_dhcp_offer(client_mac, transaction_id)
    
    assert offer is not None
    assert offer[1].src == dhcp_server.server_ip
    assert offer[DHCP].options[0][1] == "offer"

def test_dhcp_ack_generation(dhcp_server):
    """ Test if DHCP ACK is generated correctly """
    client_mac = "aa:bb:cc:dd:ee:ff"
    transaction_id = 0x87654321

    # Manually assign an IP lease
    dhcp_server.leased_ips[client_mac] = ("192.168.20.110", time.time() + 86400)

    ack = dhcp_server.build_dhcp_ack(client_mac, transaction_id)
    
    assert ack is not None
    assert ack[1].src == dhcp_server.server_ip
    assert ack[DHCP].options[0][1] == "ack"

def test_handle_dhcp_discover(dhcp_server):
    """ Test handling of DHCP Discover messages """
    with patch("scapy.all.sendp") as mock_sendp:
        mock_packet = MagicMock()
        mock_packet.haslayer.return_value = True
        mock_packet[DHCP].options = [(53, 1)]  # DHCP Discover
        mock_packet[BOOTP].chaddr = b"\xaa\xbb\xcc\xdd\xee\xff"
        mock_packet[BOOTP].xid = 1234

        dhcp_server.handle_dhcp_request(mock_packet)

        mock_sendp.assert_called_once()

def test_handle_dhcp_request(dhcp_server):
    """ Test handling of DHCP Request messages """
    client_mac = "aa:bb:cc:dd:ee:ff"
    transaction_id = 5678
    dhcp_server.leased_ips[client_mac] = ("192.168.20.110", time.time() + 86400)

    with patch("scapy.all.sendp") as mock_sendp:
        mock_packet = MagicMock()
        mock_packet.haslayer.return_value = True
        mock_packet[DHCP].options = [(53, 3)]  # DHCP Request
        mock_packet[BOOTP].chaddr = b"\xaa\xbb\xcc\xdd\xee\xff"
        mock_packet[BOOTP].xid = transaction_id

        dhcp_server.handle_dhcp_request(mock_packet)

        mock_sendp.assert_called_once()

def test_lease_expiry(dhcp_server):
    """ Test that expired leases are removed """
    client_mac = "aa:bb:cc:dd:ee:ff"
    dhcp_server.leased_ips[client_mac] = ("192.168.20.110", time.time() - 10)  # Already expired

    dhcp_server.cleanup_expired_leases()
    
    assert client_mac not in dhcp_server.leased_ips

def test_logging_statistics(dhcp_server, caplog):
    """ Test that DHCP statistics are logged """
    with patch("logging.Logger.info") as mock_log:
        dhcp_server.log_statistics()
        mock_log.assert_called()

