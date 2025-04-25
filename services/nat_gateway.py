import scapy.all as scapy
import ipaddress
import socket
import logging
import json
import time
from threading import Thread, Event
import os

# Path to the NAT gateway configuration file
CONFIG_FILE = "config/nat_config.json"

# Define directory and file path for logging
LOG_DIR = "logs"
LOG_FILE = "network-gateway.log"
LOG_PATH = os.path.join(LOG_DIR, LOG_FILE)

# Ensure the log directory exists before logging
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

# Create a logger specifically for NATGateway, with custom formatting
nat_logger = logging.getLogger('NAT-SERVICE')
nat_logger.setLevel(logging.INFO)

# File handler for logging to a file (appends to log file)
file_handler = logging.FileHandler(LOG_PATH, mode='a')
file_handler.setLevel(logging.INFO)

# Set a log message format, with customized timestamp
formatter = logging.Formatter(
    '%(asctime)s | %(levelname)s | NAT-SERVICE | %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
file_handler.setFormatter(formatter)

# Add the file handler to the logger
nat_logger.addHandler(file_handler)

# Common protocols for logging and debugging purposes
PROTOCOLS = {
    1: "ICMP",      # Internet Control Message Protocol
    6: "TCP",       # Transmission Control Protocol
    17: "UDP",      # User Datagram Protocol
    53: "DNS",      # Domain Name System (typically UDP)
    80: "HTTP",     # HyperText Transfer Protocol (typically TCP)
    443: "HTTPS"     # HTTP Secure (typically TCP)
}


class NATGateway:
    def __init__(self):
        """
        Initialize the NAT Gateway service.
        This method loads the configuration, sets up the necessary data structures, 
        and starts threads for network statistics logging.
        """
        self.load_config()  # Load the NAT configuration from the JSON file
        self.gateway_mac_cache = {}  # Initialize a cache for resolved MAC addresses
        self.nat_table = {}  # Table to store translated IP addresses for session tracking
        self.my_ip_address = ''

        # Initialize network traffic statistics counters
        self.packets_received = 0
        self.bytes_received = 0
        self.packets_forwarded = 0
        self.bytes_forwarded = 0

        # Event for graceful shutdown of the service
        self.shutdown_event = Event()

        # Start a background thread that logs network statistics periodically
        self.stats_thread = Thread(target=self.stats_logger)
        # Daemon thread will terminate when the main program exits
        self.stats_thread.daemon = True
        self.stats_thread.start()

    def load_config(self):
        """
        Load the NAT gateway configuration from a JSON file.
        This configuration includes network settings, client range, etc.
        If the configuration file is missing or malformed, an error is logged.
        """
        try:
            with open(CONFIG_FILE, "r") as f:
                self.config = json.load(f)
            nat_logger.info("Configuration loaded successfully.")
        except Exception as e:
            nat_logger.error(f"Failed to load config: {e}")
            self.config = {}

        # Fetch the gateway's public IP from the config
        self.my_ip_address = self.config.get("this_machine_ip", "192.168.20.100")
        if not self.my_ip_address:
            nat_logger.error("Translated IP ('this_machine_ip') not found in config. Using default IP '192.168.20.100'.")
            self.my_ip_address = "192.168.20.100"

    def get_gateway_mac(self, gateway_ip):
        """
        Retrieve and cache the MAC address of the upstream gateway for efficient future lookups.
        Uses ARP to resolve the MAC address and retries if necessary.
        If the MAC address can't be found, the broadcast address is used as a fallback.
        """

        try:
            # Use ipaddress module to validate if the IP address is valid
            ipaddress.ip_address(gateway_ip)  # This will raise a ValueError if the IP is invalid
        except ValueError:
            nat_logger.error(f"Invalid IP address format: {gateway_ip}")
            return None

        if gateway_ip in self.gateway_mac_cache:
            return self.gateway_mac_cache[gateway_ip]

        # Try to resolve the MAC address of the gateway IP
        gateway_mac = scapy.getmacbyip(gateway_ip)
        nat_logger.info(f"Gateway IP:{gateway_ip} MAC:{gateway_mac}")

        # Retry ARP request up to 3 times if the MAC is not found
        if gateway_mac is None:
            nat_logger.warning(f"MAC address for {gateway_ip} not found, retrying ARP request.")
            for _ in range(3):
                gateway_mac = scapy.getmacbyip(gateway_ip)
                if gateway_mac:
                    break
                time.sleep(1)  # Wait before retrying

        # If still unresolved, fallback to the broadcast MAC address
        if gateway_mac is None:
            nat_logger.error(f"Failed to resolve MAC address for {gateway_ip}, using broadcast.")
            gateway_mac = "ff:ff:ff:ff:ff:ff"

        # Cache the resolved MAC address for future use
        self.gateway_mac_cache[gateway_ip] = gateway_mac
        return gateway_mac

    def packet_handler(self, packet):
        """
        Handle incoming network packets based on NAT rules.
        This method determines if a packet should be forwarded, altered, or discarded.
        It also handles packet fragmentation if the packet size exceeds the MTU.
        """
        if packet.haslayer(scapy.IP):
            self.packets_received += 1
            self.bytes_received += len(packet)

            protocol_name = PROTOCOLS.get(packet[scapy.IP].proto, f"Unknown ({packet[scapy.IP].proto}).")

            # Log incoming packets with protocol information
            nat_logger.debug(f"Received packet from {packet[scapy.IP].src} using {protocol_name} protocol.")

            # Determine the behavior for packet forwarding based on the source and destination IPs
            if packet[scapy.IP].src in self.config.get("client_range", ""):
                self.nat_table[packet[scapy.IP].src] = self.my_ip_address  # Map internal client IP to gateway's public IP
                packet[scapy.IP].src = self.my_ip_address  # Change source IP to gateway IP
                nat_logger.info(f"{packet[scapy.IP].src}, mapped to {self.my_ip_address}")

            # Destination NAT (DNAT): Forward incoming packets to local network
            if packet[scapy.IP].dst == self.my_ip_address:
                # If the destination is the gateway, translate it to a client IP
                if packet[scapy.IP].src in self.nat_table:
                    translated_ip = self.nat_table[packet[scapy.IP].src]
                    packet[scapy.IP].dst = translated_ip  # Translate back to internal IP
                    nat_logger.info(f"Destination NAT applied to packet destined for {packet[scapy.IP].src}, forwarded to {translated_ip}")
                else:
                    packet[scapy.IP].dst = "192.168.20.1"  # Default to gateway if no mapping exists
                    nat_logger.warning(f"Unknown client {packet[scapy.IP].src}, forwarding to default gateway.")

                # Set the MAC address for the translated packet
                gateway_mac = self.get_gateway_mac("192.168.20.1")
                packet[scapy.Ether].dst = gateway_mac

            # Recalculate IP checksum after modification
            del packet[scapy.IP].chksum

            # Handle packet fragmentation if the packet size exceeds the MTU (Maximum Transmission Unit)
            if len(packet) > 1500:
                nat_logger.warning("Packet exceeds MTU, fragmenting...")
                fragments = scapy.fragment(packet, fragsize=1480)
                for fragment in fragments:
                    scapy.sendp(fragment, iface=self.config["interface"], verbose=False)
                    self.packets_forwarded += 1
                    self.bytes_forwarded += len(fragment)
            else:
                # Send the packet to the correct interface after processing
                scapy.sendp(packet, iface=self.config["interface"], verbose=False)
                self.packets_forwarded += 1
                self.bytes_forwarded += len(packet)

    def log_network_statistics(self):
        """
        Log network traffic statistics including the number of packets and bytes received and forwarded.
        """
        nat_logger.info(
            f"Stats | Received: PCK {self.packets_received}, Bytes {self.bytes_received} | Forwarded: PCK {self.packets_forwarded}, Bytes {self.bytes_forwarded}")

    def stats_logger(self):
        """
        Periodically log network statistics every 60 seconds.
        This method runs in a separate thread and is responsible for reporting the status of network traffic.
        """
        while not self.shutdown_event.is_set():
            time.sleep(60)  # Sleep for 60 seconds
            self.log_network_statistics()

    def start_sniffing(self):
        """
        Start sniffing for IP packets in a separate thread.
        The packet_handler method will be called to handle and process the packets.
        """
        nat_logger.info(
            "Started, sniffing and forwarding traffic.")
        scapy.sniff(filter="ip", prn=self.packet_handler, store=False,
                    stop_filter=lambda _: self.shutdown_event.is_set())

    def start(self):
        """
        Start the NAT Gateway service.
        This method initializes the sniffing process and starts the service in a separate thread.
        """
        nat_logger.info("Starting Gateway service...")
        self.sniff_thread = Thread(target=self.start_sniffing)
        self.sniff_thread.daemon = True
        self.sniff_thread.start()
        nat_logger.info("Service running.")

    def stop(self):
        """
        Gracefully stop the NAT Gateway service.
        This method ensures that all threads are stopped and that the service is shut down cleanly.
        """
        nat_logger.info("Shutting down NAT Gateway...")
        self.shutdown_event.set()  # Signal shutdown
        self.sniff_thread.join()  # Wait for sniffing thread to finish
        self.stats_thread.join()  # Wait for stats thread to finish
        nat_logger.info("NAT Gateway has been stopped.")

# Uncomment the following lines to run NATGateway standalone
# if __name__ == "__main__":
#     nat_logger.info("Starting net-archon services...")
#     nat_gateway = NATGateway()
#     nat_gateway.start()
#     try:
#         while True:
#             time.sleep(1)
#     except KeyboardInterrupt:
#         nat_gateway.stop()
