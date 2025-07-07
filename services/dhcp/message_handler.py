from ipaddress import IPv4Address
from logging import Logger
from threading import RLock
from typing import List
from scapy.sendrecv import sendp
from scapy.layers.dhcp import BOOTP
from scapy.packet import Packet

from models.models import (
    DHCPResponseFactory,
    ArpClient,
    DhcpMessage,
    DHCPType,
    DHCPLeaseType,
)
from services.dhcp.db_core import DHCPStorage, DHCPStats
from services.dhcp.client_discovery import ClientDiscoveryService
from services.dhcp.lease_reservation_cache import LeaseReservationCache
from utils.dhcp_utils import DHCPUtilities
from config.config import config


DHCP_CONFIG = config.get("dhcp")
INTERFACE = DHCP_CONFIG.get("interface")
SERVER_IP = DHCP_CONFIG.get("ip")
LEASE_TIME = DHCP_CONFIG.get("lease_time_seconds")
NO_IP_ASSIGNED = DHCP_CONFIG.get("no_ip_assigned")


class DHCPMessageHandler:

    _lock = RLock()
    logger: Logger

    @classmethod
    def init(cls, logger: Logger):
        cls.logger: Logger = logger

    @classmethod
    def handle_message(cls, dhcp_message: DhcpMessage):
        with cls._lock:
            try:
                match dhcp_message.dhcp_type:
                    case DHCPType.DISCOVER:
                        cls._handle_discover(dhcp_message)
                    case DHCPType.REQUEST:
                        cls._handle_request(dhcp_message)
                    case DHCPType.DECLINE:
                        cls._handle_decline(dhcp_message)
                    case DHCPType.RELEASE:
                        cls._handle_release(dhcp_message)
                    case DHCPType.INFORM:
                        cls._handle_inform(dhcp_message)
                    case _:
                        cls.logger.warning("Type %s unknown.", dhcp_message.dhcp_type)

            except Exception as err:
                cls.logger.exception(
                    "%s error processing packet: %s.", cls.__name__, err
                )

    @classmethod
    def _handle_discover(cls, dhcp_message: DhcpMessage):
        """Handles DHCPDISCOVER messages (RFC 2131, Section 4.1) sent by clients to discover DHCP servers."""
        with cls._lock:
            cls.logger.debug(
                "Rcvd DISCOVER XID=%s, MAC=%s.", dhcp_message.xid, dhcp_message.mac
            )
            proposed_ip: IPv4Address | None = ClientDiscoveryService.get_available_ip()
            if not proposed_ip:
                cls.logger.warning("No available IP")
                return

            LeaseReservationCache.reserve(ip=str(proposed_ip), mac=dhcp_message.mac)
            offer = DHCPResponseFactory.build(
                dhcp_type=DHCPType.OFFER,
                your_ip=str(proposed_ip),
                request_packet=dhcp_message.packet,
            )
            cls._send_response(offer)

    @classmethod
    def _handle_request(cls, dhcp_message: DhcpMessage):

        cls.logger.debug(
            f"DHCP REQUEST "
            f"XID:{dhcp_message.xid}, "
            f"MAC:{dhcp_message.mac}, "
            f"IP_req:{dhcp_message.requested_ip}, "
            f"HOSTNAME:{dhcp_message.hostname}."
        )

        with cls._lock:
            dhcp_type = DHCPType.NAK
            your_ip = NO_IP_ASSIGNED
            lease = DHCPStorage.get_lease_by_mac(dhcp_message.mac)

            # 1) REQUEST after OFFER
            if (
                dhcp_message.requested_ip
                and dhcp_message.server_id
                and dhcp_message.ciaddr == NO_IP_ASSIGNED
            ):
                if (
                    dhcp_message.server_id == SERVER_IP
                    and DHCPUtilities.is_ip_in_subnet(dhcp_message.requested_ip)
                ):
                    offered_ip = LeaseReservationCache.get_ip(dhcp_message.mac)
                    if offered_ip == dhcp_message.requested_ip:
                        DHCPStorage.add_lease(
                            dhcp_message.mac,
                            dhcp_message.requested_ip,
                            dhcp_message.hostname,
                            LEASE_TIME,
                        )
                        LeaseReservationCache.unreserve(
                            dhcp_message.requested_ip, dhcp_message.mac
                        )
                        dhcp_type, your_ip = DHCPType.ACK, dhcp_message.requested_ip
                    else:
                        cls.logger.debug("NAK REQUEST after OFFER mismatch")

            # 2) INIT-REBOOT
            elif dhcp_message.requested_ip and dhcp_message.ciaddr == NO_IP_ASSIGNED:
                if DHCPUtilities.is_ip_in_subnet(dhcp_message.requested_ip):
                    arp_client: ArpClient | None = (
                        ClientDiscoveryService.get_live_client_by_ip(
                            dhcp_message.requested_ip
                        )
                    )
                    if not arp_client or arp_client.mac == dhcp_message.mac:
                        if (
                            lease
                            and lease[1] == dhcp_message.requested_ip
                            or not arp_client
                        ):
                            DHCPStorage.add_lease(
                                dhcp_message.mac,
                                dhcp_message.requested_ip,
                                dhcp_message.hostname,
                                LEASE_TIME,
                            )
                            LeaseReservationCache.unreserve(
                                dhcp_message.requested_ip, dhcp_message.mac
                            )
                            dhcp_type, your_ip = DHCPType.ACK, dhcp_message.requested_ip
                        else:
                            cls.logger.debug(
                                "NAK INIT-REBOOT no matching lease and IP in use"
                            )
                    else:
                        cls.logger.debug("NAK INIT-REBOOT: IP used by different MAC")
                else:
                    cls.logger.debug("NAK INIT-REBOOT: IP outside subnet")

            # 3) RENEW/REBIND
            elif (
                dhcp_message.ciaddr != NO_IP_ASSIGNED and not dhcp_message.requested_ip
            ):
                if DHCPUtilities.is_ip_in_subnet(dhcp_message.ciaddr):
                    arp_client = ClientDiscoveryService.get_live_client_by_ip(
                        dhcp_message.ciaddr
                    )
                    if not arp_client or (lease and lease[1] == dhcp_message.ciaddr):
                        DHCPStorage.add_lease(
                            dhcp_message.mac,
                            dhcp_message.ciaddr,
                            dhcp_message.hostname,
                            LEASE_TIME,
                        )
                        LeaseReservationCache.unreserve(
                            dhcp_message.ciaddr, dhcp_message.mac
                        )
                        dhcp_type, your_ip = DHCPType.ACK, dhcp_message.ciaddr
                    else:
                        cls.logger.debug("NAK RENEW/REBIND IP in use or lease mismatch")
                else:
                    cls.logger.debug("NAK RENEW/REBIND IP outside subnet")

            # 4) Invalid IP change without DISCOVER
            elif dhcp_message.requested_ip and dhcp_message.ciaddr != NO_IP_ASSIGNED:
                cls.logger.warning("Invalid REQUEST: IP change without DISCOVER")
            else:
                cls.logger.debug("Invalid REQUEST: Missing valid IP info")

            response = DHCPResponseFactory.build(
                dhcp_type=dhcp_type, your_ip=your_ip, request_packet=dhcp_message.packet
            )
            cls._send_response(response)

    @classmethod
    def _handle_decline(cls, dhcp_message: DhcpMessage):
        """Handles DHCP Decline messages (RFC 2131, Section 4.3.2)"""

        declined_ip = dhcp_message.requested_ip
        LeaseReservationCache.unreserve(
            ip=dhcp_message.requested_ip, mac=dhcp_message.mac
        )
        cls.logger.debug(
            "Received DHCPDECLINE XID=%s, IP=%s, MAC=%s.",
            dhcp_message.xid,
            declined_ip,
            dhcp_message.mac,
        )

        with cls._lock:
            _existing_lease = DHCPStorage.get_lease_by_mac(dhcp_message.mac)
            # Case 1: The client has a lease and it is for the declined IP
            if _existing_lease and _existing_lease[1] == declined_ip:
                cls.logger.debug(
                    "MAC:%s declined IP:%s, removing lease from database.",
                    dhcp_message.mac,
                    declined_ip,
                )
                DHCPStorage.remove_lease_by_mac(dhcp_message.mac)
            else:
                # Case 2: The client declined the IP and doesnt have active lease
                cls.logger.debug(
                    "Client %s declined IP %s, but no lease found.",
                    dhcp_message.mac,
                    declined_ip,
                )

            response: Packet = DHCPResponseFactory.build(
                dhcp_type=DHCPType.NAK,
                your_ip=NO_IP_ASSIGNED,
                request_packet=dhcp_message.packet,
            )

            cls._send_response(response)

    @classmethod
    def _handle_release(cls, dhcp_message: DhcpMessage):
        """DHCP Release (Section 4.4 of RFC 2131) sent by the client to release an IP address that it no longer needs."""

        cls.logger.debug(
            "Received DHCPRELEASE XID=%s, IP=%s, MAC=%s.",
            dhcp_message.xid,
            dhcp_message.src_ip,
            dhcp_message.mac,
        )

        with cls._lock:
            DHCPStorage.remove_lease_by_mac(dhcp_message.mac)

    @classmethod
    def _handle_inform(cls, dhcp_message: DhcpMessage):
        """DHCPINFORM (Section 3.3.2 of RFC 2131)"""

        cls.logger.debug(
            "Received DHCPINFORM XID=%s, IP=%s, Requested=%s.",
            dhcp_message.xid,
            dhcp_message.src_ip,
            dhcp_message.param_req_list,
        )

        with cls._lock:
            ack: Packet = DHCPResponseFactory.build(
                dhcp_type=DHCPType.ACK,
                your_ip=dhcp_message.src_ip,
                request_packet=dhcp_message.packet,
            )
            cls._send_response(ack)

    @classmethod
    def _send_response(cls, packet: Packet):
        """Send a DHCP packet on the configured interface."""
        try:
            DHCPStats.increment(key="sent_total")
            DHCPStats.increment(
                key=f"sent_{DHCPLeaseType(DHCPUtilities.extract_dhcp_type_from_packet(packet)).name.lower()}"
            )
            cls.logger.debug(
                "Send: TYPE:%s, XID:%s, CHADDR:%s, YIADDR:%s.",
                DHCPUtilities.extract_dhcp_type_from_packet(packet),
                packet[BOOTP].xid,
                packet[BOOTP].chaddr[:6].hex(":"),
                packet[BOOTP].yiaddr,
            )
            sendp(packet, iface=INTERFACE, verbose=False)
        except Exception as err:
            cls.logger.error("Failed to send DHCP response %s", err)
