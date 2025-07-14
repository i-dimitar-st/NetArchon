from collections import Counter
from dataclasses import dataclass, field
from threading import RLock

from config.config import config
from services.dhcp.models import DHCPArpClient

DHCP_CONFIG = config.get("dhcp")
CLIENT_DISCOVERY = DHCP_CONFIG.get("client_discovery")
MIN_CTR = int(CLIENT_DISCOVERY.get("min_ctr"))
MAX_CTR = int(CLIENT_DISCOVERY.get("max_ctr"))


@dataclass
class LiveClients:
    arp_clients: set[DHCPArpClient] = field(default_factory=set)
    arp_client_counts: Counter[DHCPArpClient] = field(default_factory=Counter)
    max_count: int = MAX_CTR
    min_count: int = MIN_CTR
    _lock: RLock = field(default_factory=RLock, init=False, repr=False)

    def increase(self, client: DHCPArpClient):
        """
        Add new or increase exsiting count for a given DHCPArpClient.

        Purpose:
        - Track how frequently a client is observed as 'live'.
        - Cap count to avoid overflow and unnecessary increments.
        - Add client to the active client set if observed.

        Args:
            client (DHCPArpClient): Client to add or increment.

        Behavior:
        - If client count is below max_count, increment by 1.
        - Clean up clients that fall below min_count after updating counts.
        """
        with self._lock:
            _client_ctr: int = self.arp_client_counts.get(client, 0)
            if _client_ctr < self.max_count:
                self.arp_client_counts[client] = _client_ctr + 1
                self.arp_clients.add(client)
            self._clean()

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
            _client_ctr: int = self.arp_client_counts.get(client, 0)
            if _client_ctr >= self.min_count:
                self.arp_client_counts[client] = _client_ctr - 1
            self._clean()

    def get_tracked_clients(self) -> set[DHCPArpClient]:
        """
        Get copy of live clients.

        Returns:
            Set of DHCPArpClient currently tracked (count >= min_count).

        Purpose:
        - Provide external callers with the current active clients.
        - Return a new set to prevent external mutation of internal state.
        """
        return set(self.arp_clients)

    def get_client_count(self, client: DHCPArpClient) -> int:
        """
        Get the current count for a specific DHCPArpClient.

        Args:
            client (DHCPArpClient): The client to query.

        Returns:
            int: The count associated with the client, or 0 if not tracked.
        """
        with self._lock:
            return self.arp_client_counts.get(client, -1)

    def _clean(self):
        """Internal prune to remove clients with counts below min_count."""
        with self._lock:
            _clients_to_clean: set[DHCPArpClient] = {
                _client for _client, _ctr in self.arp_client_counts.items() if _ctr < self.min_count
            }
            for _client in _clients_to_clean:
                print("before delete: ", len(self.arp_clients))
                self.arp_client_counts.pop(_client, None)
                self.arp_clients.discard(_client)
                print("deleting ", _client, " left:", len(self.arp_clients))
