from collections import Counter
from dataclasses import dataclass, field
from threading import RLock

from config.config import config
from services.dhcp.models import DHCPArpClient

DHCP_CONFIG = config.get("dhcp")
CLIENT_DISCOVERY = DHCP_CONFIG.get("client_discovery")
MIN_CTR = int(CLIENT_DISCOVERY.get("min_ctr"))
START_CTR = int(CLIENT_DISCOVERY.get("start_ctr"))
MAX_CTR = int(CLIENT_DISCOVERY.get("max_ctr"))
INCREMENT = 1


@dataclass
class LiveClients:
    live_clients: set[DHCPArpClient] = field(default_factory=set)
    client_counter: Counter[DHCPArpClient] = field(default_factory=Counter)
    max_count: int = MAX_CTR
    start_count: int = START_CTR
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
            _client_ctr: int = self.client_counter.get(client, self.start_count)
            if _client_ctr < self.max_count:
                self.client_counter[client] = _client_ctr + INCREMENT
                self.live_clients.add(client)
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
            if client in self.client_counter:
                self.client_counter[client] = self.client_counter[client] - INCREMENT
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
        with self._lock:
            return set(self.live_clients)

    def get_count_for_client(self, client: DHCPArpClient) -> int | None:
        """
        Get the current count for a specific DHCPArpClient.

        Args:
            client (DHCPArpClient): The client to query.

        Returns:
            int: The count associated with the client, or START_CTR=0 if not tracked.
        """
        with self._lock:
            return self.client_counter.get(client)

    def get_client_by_ip(self, ip: str) -> DHCPArpClient | None:
        """
        Search and return a client by IP address.

        Args:
            ip (str): IP address to look up.

        Returns:
            DHCPArpClient or None: Client with matching IP, or None if not found.
        """
        with self._lock:
            for client in self.live_clients:
                if client.ip == ip:
                    return client
        return None

    def get_client_by_mac(self, mac: str) -> DHCPArpClient | None:
        """
        Search and return a client by MAC address.

        Args:
            mac (str): MAC address to look up.

        Returns:
            DHCPArpClient or None: Client with matching MAC, or None if not found.
        """
        with self._lock:
            for client in self.live_clients:
                if client.mac.lower() == mac.lower():
                    return client
        return None

    def _clean(self):
        """Internal prune to remove clients with counts below min_count."""
        with self._lock:
            _clients_to_clean: set[DHCPArpClient] = {
                _client for _client, _ctr in self.client_counter.items() if _ctr < self.min_count
            }
            for _client in _clients_to_clean:
                print("dropping: ", _client)
                self.client_counter.pop(_client, None)
                self.live_clients.discard(_client)
