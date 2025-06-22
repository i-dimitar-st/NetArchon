from pydantic import BaseModel, Field, IPvAnyAddress
from typing import List, Dict, Optional, Any


class Meta(BaseModel):
    name: str
    version: str
    date: str


class App(BaseModel):
    host: str
    port: int
    threaded: bool


class Certificates(BaseModel):
    cert: str
    key: str


class Paths(BaseModel):
    root: str
    database: str
    logs: str
    certificates: str


class NetworkLAN(BaseModel):
    name: str
    mac: str
    ip: IPvAnyAddress
    subnet_mask: str
    gateway: IPvAnyAddress
    cidr: str
    broadcast_ip: IPvAnyAddress
    family: str
    role: str


class Network(BaseModel):
    lan: NetworkLAN


class DNS(BaseModel):
    host: str
    port: int
    dns_servers: List[str]
    cache_ttl: int
    blacklists: str
    msg_size: int
    process_workers: int
    external_workers: int
    external_timeout: float
    local_timeout: float
    zones: Dict[str, Dict[str, Any]]


class DHCPTimeouts(BaseModel):
    arp: int
    worker_get: float
    worker_sleep: float
    lease_discovery: int
    persistence: int


class DHCP(BaseModel):
    interface: str
    host: str
    port: int
    router_ip: str
    ip: str
    mac: str
    broadcast_ip: str
    broadcast_mac: str
    subnet: str
    ntp_server: str
    ip_pool_start: str
    ip_pool_end: str
    cidr: int
    lease_time_seconds: int
    mtu: int
    rcvd_queue_size: int
    deque_size: int
    timeouts: DHCPTimeouts


class DBSubConfig(BaseModel):
    type: str
    path: str
    max_records: Optional[int] = None


class Database(BaseModel):
    persistence_interval: int
    blacklists_loading_interval: int
    dhcp: Dict[str, DBSubConfig]
    dns: Dict[str, DBSubConfig]


class LoggingFormatter(BaseModel):
    format: str
    datefmt: str


class LoggingHandler(BaseModel):
    class_: str = Field(..., alias="class")
    filename: str
    maxBytes: int
    backupCount: int
    encoding: str
    mode: str
    level: str
    formatter: str


class Logging(BaseModel):
    levels: Dict[str, str]
    formatters: Dict[str, LoggingFormatter]
    handlers: Dict[str, LoggingHandler]
    root: Dict[str, List[str] | str]


class ConfigSchema(BaseModel):
    meta: Meta
    app: App
    certificates: Certificates
    paths: Paths
    network: Network
    dns: DNS
    dhcp: DHCP
    database: Database
    logging: Logging
