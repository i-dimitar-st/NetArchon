from collections import Counter
from dataclasses import dataclass, field
from threading import RLock

from app.config.config import config
from app.services.dhcp.models import DHCPArpClient

DHCP_CONFIG = config.get("dhcp")
CLIENT_DISCOVERY = DHCP_CONFIG.get("client_discovery")
MIN_CTR = int(CLIENT_DISCOVERY.get("min_ctr"))
START_CTR = int(CLIENT_DISCOVERY.get("start_ctr"))
MAX_CTR = int(CLIENT_DISCOVERY.get("max_ctr"))
INCREMENT = 1


@dataclass
class LiveClients:
    # We want fields here to make it per object property
    _lock: RLock = field(default_factory=RLock, init=False, repr=False)
    live_clients: Counter[DHCPArpClient] = field(default_factory=Counter)
    max_ctr: int = MAX_CTR
    start_ctr: int = START_CTR
    min_ctr: int = MIN_CTR

    def increase(self, client: DHCPArpClient):
        """
        Add new or increase exsiting count for a given DHCPArpClient.

        Purpose:
        - Track how frequently a client is observed as 'live'.
        - Cap count to avoid overflow and unnecessary increments.
        - Add client to the active client set if observed.

        Args:
            client (DHCPArpClient): Client to add or increment.
        """
        with self._lock:
            _client_ctr: int = self.live_clients.get(client, self.start_ctr)
            if _client_ctr < self.max_ctr:
                self.live_clients[client] = _client_ctr + INCREMENT

    def decrease(self, client: DHCPArpClient):
        """
        Decrement the count for a given DHCPArpClient.

        Purpose:
        - Reflect that a client was not seen in the latest scan iteration.
        - Allow clients to be removed when their count drops below min_count.

        Args:
            client (DHCPArpClient): Client to decrement.

        Behavior:
        - Decrement client count if it is at least min_count.
        - Run cleanup to remove any clients whose counts drop below min_count.
        """
        with self._lock:
            if client in self.live_clients:
                self.live_clients[client] -= INCREMENT
                self._clean()

    def is_live(self, client: DHCPArpClient) -> bool:
        """
        Check if a client is currently considered live.

        Args:
            client (DHCPArpClient): The client to check.

        """
        with self._lock:
            return self.live_clients.get(client, 0) >= self.min_ctr

    def get_tracked_clients(self) -> set[DHCPArpClient]:
        """
        Get copy of live clients.
        Purpose:
        - Provide external callers with the current active clients.
        - Return a new set to prevent external mutation of internal state.

        Returns:
            Set of DHCPArpClient currently tracked (count >= min_count).
        """
        with self._lock:
            return {client for client, count in self.live_clients.items() if count >= self.min_ctr}

    def get_count_for_client(self, client: DHCPArpClient) -> int:
        """
        Get the current count for a specific DHCPArpClient.

        Args:
            client (DHCPArpClient): The client to query.

        Returns:
            int: The count associated with the client, or 0 if not tracked.
        """
        with self._lock:
            return self.live_clients.get(client, 0)

    def get_client_by_ip(self, ip: str) -> DHCPArpClient | None:
        """
        Search and return a client by IP address.

        Args:
            ip (str): IP address to look up.
        """
        with self._lock:
            for client, count in self.live_clients.items():
                if client.ip == ip and count >= self.min_ctr:
                    return client
        return None

    def get_client_by_mac(self, mac: str) -> DHCPArpClient | None:
        """
        Search and return a client by MAC address.
        """
        with self._lock:
            for client, count in self.live_clients.items():
                if count >= self.min_ctr and client.mac.lower() == mac.lower():
                    return client
        return None

    def _clean(self):
        """
        Internal prune to remove clients with counts below min_count.
        """
        with self._lock:
            _expired_clients: set[DHCPArpClient] = {
                _client for _client, _count in self.live_clients.items() if _count < self.min_ctr
            }
            for client in _expired_clients:
                self.live_clients.pop(client, None)
