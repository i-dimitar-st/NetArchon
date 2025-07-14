from ipaddress import IPv4Address
from logging import Logger
from threading import RLock

from scapy.layers.dhcp import BOOTP
from scapy.packet import Packet
from scapy.sendrecv import sendp

from config.config import config
from services.dhcp.client_discovery import ClientDiscoveryService
from services.dhcp.db_dhcp_leases import DHCPStorage
from services.dhcp.db_dhcp_stats import DHCPStats
from services.dhcp.models import (
    DHCPArpClient,
    DHCPLeaseType,
    DHCPMessage,
    DHCPMessageType,
    DHCPResponseFactory,
    DHCPType,
)
from services.dhcp.reservation_cache import LeaseReservationCache
from services.dhcp.utils import extract_dhcp_type_from_packet, is_ip_in_subnet

DHCP_CONFIG = config.get("dhcp")
INTERFACE = str(DHCP_CONFIG.get("interface"))
SERVER_IP = str(DHCP_CONFIG.get("ip"))
LEASE_TIME = int(DHCP_CONFIG.get("lease_time_seconds"))
NO_IP_ASSIGNED = str(DHCP_CONFIG.get("no_ip_assigned"))


def is_request_valid(dhcp_msg: DHCPMessage) -> bool:
    """
    Validates a parsed DHCPMessage object for required fields.

    Returns:
        bool: True if valid, False otherwise.
    """
    if not dhcp_msg.mac or not dhcp_msg.dhcp_type or dhcp_msg.dhcp_type not in DHCPType:
        return False

    return True


class DHCPMessageHandler:

    _lock = RLock()
    logger: Logger

    @classmethod
    def init(cls, logger: Logger):
        """
        Initilise
        Args:
            logger: Logger instance where to log.
        """
        cls.logger: Logger = logger

    @classmethod
    def handle_message(cls, dhcp_msg: DHCPMessage):
        """
        Process an incoming DHCP message based on its DHCP type.

        Dependencies:
            - DhcpMessage: a structured representation of a DHCP packet, must have `dhcp_type`.
            - DHCPType: Enum defining valid DHCP message types (DISCOVER, REQUEST, etc.).
            - Threading lock (`cls._lock`) for concurrency control.
            - Logger (`cls.logger`) for logging warnings and exceptions.

        Args:
            dhcp_message (DhcpMessage): Parsed DHCP message object.

        Behavior:
            - Acquires thread lock for safe concurrent access.
            - Uses a match-case statement to dispatch the message to the appropriate handler method:
                * DISCOVER -> _handle_discover
                * REQUEST  -> _handle_request
                * DECLINE  -> _handle_decline
                * RELEASE  -> _handle_release
                * INFORM   -> _handle_inform
            - Logs a warning for unknown DHCP message types.
            - Catches and logs any exceptions with full traceback to avoid crashing the handler.

        Usage:
            Called whenever a DHCP message is received and parsed.
            Example:
                DHCPHandler.handle_message(parsed_dhcp_message)
        """
        with cls._lock:

            try:
                DHCPStats.increment(key="received_total")

                if not is_request_valid(dhcp_msg):
                    DHCPStats.increment(key="received_malformed")
                    return

                match dhcp_msg.dhcp_type:
                    case DHCPType.DISCOVER:
                        cls._handle_discover(dhcp_msg)
                    case DHCPType.REQUEST:
                        cls._handle_request(dhcp_msg)
                    case DHCPType.DECLINE:
                        cls._handle_decline(dhcp_msg)
                    case DHCPType.RELEASE:
                        cls._handle_release(dhcp_msg)
                    case DHCPType.INFORM:
                        cls._handle_inform(dhcp_msg)
                    case _:
                        cls.logger.warning("Unknown dhcp type %s.", dhcp_msg.dhcp_type)

            except Exception as err:
                cls.logger.exception("%s error processing packet: %s.", cls.__name__, err)

    @classmethod
    def _handle_discover(cls, dhcp_msg: DHCPMessage):
        """Handle DHCPDISCOVER: propose an available IP or ignore if none.

        Returns True if an OFFER was sent, False otherwise.
        """
        with cls._lock:
            cls.logger.debug("DISCOVER XID=%s, MAC=%s.", dhcp_msg.xid, dhcp_msg.mac)

            proposed_ip: IPv4Address | None = ClientDiscoveryService.get_available_ip()
            if not proposed_ip:
                cls.logger.warning("No available IP to offer.")
                return

            LeaseReservationCache.reserve(ip=str(proposed_ip), mac=dhcp_msg.mac)

            cls._send_response(
                DHCPResponseFactory.build(
                    dhcp_type=DHCPType.OFFER,
                    your_ip=str(proposed_ip),
                    request_packet=dhcp_msg.packet,
                )
            )
            cls.logger.debug(f"Sent OFFER with IP {proposed_ip} to MAC {dhcp_msg.mac}")

    @classmethod
    def _handle_request(cls, dhcp_msg: DHCPMessage):
        cls.logger.debug(
            "DHCP REQUEST XID:%s MAC:%s IPreq:%s, HOSTNAME:%s",
            dhcp_msg.xid,
            dhcp_msg.mac,
            dhcp_msg.requested_ip,
            dhcp_msg.hostname,
        )

        with cls._lock:

            if cls._handle_request_after_offer(dhcp_msg):
                return

            lease = DHCPStorage.get_lease_by_mac(dhcp_msg.mac)

            if cls._handle_request_init_reboot(dhcp_msg, lease):
                return

            if cls._handle_request_renew_rebind(dhcp_msg, lease):
                return

            if dhcp_msg.requested_ip and dhcp_msg.ciaddr != NO_IP_ASSIGNED:
                cls.logger.warning("Invalid REQUEST: IP change without DISCOVER")
            else:
                cls.logger.debug("Invalid REQUEST: Missing valid IP info")

            cls._send_response(
                DHCPResponseFactory.build(
                    dhcp_type=DHCPType.NAK,
                    your_ip=NO_IP_ASSIGNED,
                    request_packet=dhcp_msg.packet,
                )
            )

    @classmethod
    def _handle_request_after_offer(cls, dhcp_msg: DHCPMessage) -> bool:

        if not (dhcp_msg.requested_ip and dhcp_msg.server_id and dhcp_msg.ciaddr == NO_IP_ASSIGNED):
            return False  # Not a request-after-offer case

        # Client is formally requesting an IP from a server after receiving an OFFER, and it hasn't yet configured any IP locally.
        if dhcp_msg.server_id != SERVER_IP:
            cls.logger.debug("REQUEST after OFFER: Server ID mismatch")
            cls._send_response(
                DHCPResponseFactory.build(
                    dhcp_type=DHCPType.NAK,
                    your_ip=NO_IP_ASSIGNED,
                    request_packet=dhcp_msg.packet,
                )
            )
            return True

        if not is_ip_in_subnet(dhcp_msg.requested_ip):
            cls.logger.debug("REQUEST after OFFER: Requested IP outside subnet")
            cls._send_response(
                DHCPResponseFactory.build(
                    dhcp_type=DHCPType.NAK,
                    your_ip=NO_IP_ASSIGNED,
                    request_packet=dhcp_msg.packet,
                )
            )
            return True

        if LeaseReservationCache.get_ip(dhcp_msg.mac) == dhcp_msg.requested_ip:
            DHCPStorage.add_lease(
                mac=dhcp_msg.mac,
                ip=dhcp_msg.requested_ip,
                hostname=dhcp_msg.hostname,
                lease_time=LEASE_TIME,
                lease_type=DHCPLeaseType.DYNAMIC,
            )
            LeaseReservationCache.unreserve(dhcp_msg.requested_ip, dhcp_msg.mac)
            cls._send_response(
                DHCPResponseFactory.build(
                    dhcp_type=DHCPType.ACK,
                    your_ip=dhcp_msg.requested_ip,
                    request_packet=dhcp_msg.packet,
                )
            )
            return True

        cls.logger.debug("NAK REQUEST after OFFER mismatch")
        return False

    @classmethod
    def _handle_request_init_reboot(cls, dhcp_msg: DHCPMessage, lease) -> bool:
        if not (dhcp_msg.requested_ip and dhcp_msg.ciaddr == NO_IP_ASSIGNED):
            return False

        if not is_ip_in_subnet(dhcp_msg.requested_ip):
            cls.logger.debug("NAK INIT-REBOOT: IP outside subnet")
            cls._send_response(
                DHCPResponseFactory.build(
                    dhcp_type=DHCPType.NAK,
                    your_ip=NO_IP_ASSIGNED,
                    request_packet=dhcp_msg.packet,
                )
            )
            return True

        _arp_client: DHCPArpClient | None = ClientDiscoveryService.get_live_client_by_ip(
            dhcp_msg.requested_ip
        )

        if _arp_client and _arp_client.mac != dhcp_msg.mac:
            cls.logger.debug("NAK INIT-REBOOT: IP used by different MAC")
            cls._send_response(
                DHCPResponseFactory.build(
                    dhcp_type=DHCPType.NAK,
                    your_ip=NO_IP_ASSIGNED,
                    request_packet=dhcp_msg.packet,
                )
            )
            return True
        if lease and lease[1] == dhcp_msg.requested_ip or not _arp_client:
            DHCPStorage.add_lease(
                mac=dhcp_msg.mac,
                ip=dhcp_msg.requested_ip,
                hostname=dhcp_msg.hostname,
                lease_time=LEASE_TIME,
                lease_type=DHCPLeaseType.DYNAMIC,
            )
            LeaseReservationCache.unreserve(dhcp_msg.requested_ip, dhcp_msg.mac)
            cls._send_response(
                DHCPResponseFactory.build(
                    dhcp_type=DHCPType.ACK,
                    your_ip=dhcp_msg.requested_ip,
                    request_packet=dhcp_msg.packet,
                )
            )
            return True

        cls.logger.debug("NAK INIT-REBOOT: no matching lease and IP in use")
        cls._send_response(
            DHCPResponseFactory.build(
                dhcp_type=DHCPType.NAK,
                your_ip=NO_IP_ASSIGNED,
                request_packet=dhcp_msg.packet,
            )
        )
        return True

    @classmethod
    def _handle_request_renew_rebind(cls, dhcp_msg: DHCPMessage, lease) -> bool:
        if dhcp_msg.ciaddr == NO_IP_ASSIGNED or dhcp_msg.requested_ip:
            return False  # Not renew/rebind request

        if not is_ip_in_subnet(dhcp_msg.ciaddr):
            cls.logger.debug("NAK RENEW/REBIND IP outside subnet")
            cls._send_response(
                DHCPResponseFactory.build(
                    dhcp_type=DHCPType.NAK,
                    your_ip=NO_IP_ASSIGNED,
                    request_packet=dhcp_msg.packet,
                )
            )
            return True

        _arp_client = ClientDiscoveryService.get_live_client_by_ip(dhcp_msg.ciaddr)
        if _arp_client and not (lease and lease[1] == dhcp_msg.ciaddr):
            cls.logger.debug("NAK RENEW/REBIND IP in use or lease mismatch")
            cls._send_response(
                DHCPResponseFactory.build(
                    dhcp_type=DHCPType.NAK,
                    your_ip=NO_IP_ASSIGNED,
                    request_packet=dhcp_msg.packet,
                )
            )
            return True

        # Lease is valid or IP is free
        DHCPStorage.add_lease(
            mac=dhcp_msg.mac,
            ip=dhcp_msg.ciaddr,
            hostname=dhcp_msg.hostname,
            lease_time=LEASE_TIME,
            lease_type=DHCPLeaseType.DYNAMIC,
        )
        LeaseReservationCache.unreserve(dhcp_msg.ciaddr, dhcp_msg.mac)
        cls._send_response(
            DHCPResponseFactory.build(
                dhcp_type=DHCPType.ACK,
                your_ip=dhcp_msg.ciaddr,
                request_packet=dhcp_msg.packet,
            )
        )
        return True

    @classmethod
    def _handle_decline(cls, dhcp_message: DHCPMessage):
        """Handles DHCP Decline messages (RFC 2131, Section 4.3.2)"""

        cls.logger.info(
            "Received DHCPDECLINE XID=%s, IPsrc=%s, MAC=%s.",
            dhcp_message.xid,
            dhcp_message.src_ip,
            dhcp_message.mac,
        )

        with cls._lock:
            _declined_ip = dhcp_message.requested_ip
            LeaseReservationCache.unreserve(ip=dhcp_message.requested_ip, mac=dhcp_message.mac)
            _existing_lease = DHCPStorage.get_lease_by_mac(dhcp_message.mac)
            # Case 1: The client has a lease and it is for the declined IP
            if _existing_lease and _existing_lease[1] == _declined_ip:
                cls.logger.debug(
                    "MAC:%s declined IP:%s, removing lease from database.",
                    dhcp_message.mac,
                    _declined_ip,
                )
                DHCPStorage.remove_lease_by_mac(dhcp_message.mac)
            else:
                # Case 2: The client declined the IP and doesnt have active lease
                cls.logger.debug(
                    "Client %s declined IP %s, but no lease found.", dhcp_message.mac, _declined_ip
                )

    @classmethod
    def _handle_release(cls, dhcp_message: DHCPMessage):
        """DHCP Release (Section 4.4 of RFC 2131) sent by client to release from IP address"""

        cls.logger.debug(
            "Received DHCPRELEASE XID=%s, IP=%s, MAC=%s.",
            dhcp_message.xid,
            dhcp_message.src_ip,
            dhcp_message.mac,
        )

        with cls._lock:
            DHCPStorage.remove_lease_by_mac(dhcp_message.mac)

    @classmethod
    def _handle_inform(cls, dhcp_message: DHCPMessage):
        """DHCPINFORM (Section 3.3.2 of RFC 2131)"""

        cls.logger.debug(
            "Received DHCPINFORM XID=%s, IP=%s, Requested=%s.",
            dhcp_message.xid,
            dhcp_message.src_ip,
            dhcp_message.param_req_list,
        )

        with cls._lock:
            cls._send_response(
                DHCPResponseFactory.build(
                    dhcp_type=DHCPType.ACK,
                    your_ip=dhcp_message.src_ip,
                    request_packet=dhcp_message.packet,
                )
            )

    @classmethod
    def _send_response(cls, packet: Packet):
        """
        Send a DHCP packet on the configured network interface.

        Args:
            packet (Packet): The DHCP packet to send (Scapy Packet).

        Behavior:
            - Increments global DHCP stats counters: total sent and by DHCP message type.
            - Logs details DHCP type, transaction ID (XID), client mac, and your IP.
            - Sends the packet on the pre-configured interface using `sendp`.
            - Catches and logs any exceptions without raising.
        """
        try:

            DHCPStats.increment(key="sent_total")

            _stats_key = (
                f"sent_{DHCPMessageType(extract_dhcp_type_from_packet(packet)).name.lower()}"
            )

            DHCPStats.increment(key=_stats_key)
            cls.logger.debug(
                "Send TYPE:%s, XID:%s, CHADDR:%s, YIADDR:%s.",
                extract_dhcp_type_from_packet(packet),
                packet[BOOTP].xid,
                packet[BOOTP].chaddr[:6].hex(":"),
                packet[BOOTP].yiaddr,
            )

            sendp(packet, iface=INTERFACE, verbose=False)
        except Exception as err:
            cls.logger.error("Failed to send DHCP response %s", err)
