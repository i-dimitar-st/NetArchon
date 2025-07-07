import time
import asyncio
from concurrent.futures import ThreadPoolExecutor
from scapy.all import ARP, Ether, srp, IP, ICMP
from ipaddress import IPv4Network
import time


def send_arp_request(iface: str, ip: str, timeout: float) -> dict | None:
    _start = time.monotonic()
    _answered, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        timeout=timeout,
        iface=iface,
        verbose=False,
    )

    if _answered:
        if len(_answered) > 1:
            print("more than 1 responded, getting first only")
        _, _recv = _answered[0]
        return {
            "ip": _recv.psrc,
            "mac": _recv.hwsrc,
            "rtt": time.monotonic() - _start,
        }

    return None


async def fresh_arp_scan_async(
    iface: str = "enp2s0",
    cidr: str = "192.168.20.0/24",
    timeout: float = 1.0,
    retries: int = 2,
    delay: float = 0.2,
):
    live_hosts = {}
    _loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()
    _executor = ThreadPoolExecutor(max_workers=50)

    for _ in range(retries):
        _tasks = [
            _loop.run_in_executor(_executor, send_arp_request, iface, str(ip), timeout)
            for ip in IPv4Network(cidr, strict=False).hosts()
        ]
        for _answers in await asyncio.gather(*_tasks):
            if _answers:
                live_hosts[_answers["ip"]] = {
                    "mac": _answers["mac"],
                    "rtt": _answers["rtt"],
                }
        await asyncio.sleep(delay)

    _executor.shutdown(wait=False)
    return live_hosts


# def fresh_arp_scan(
#     iface: str = "enp2s0",
#     cidr: str = "192.168.20.0/24",
#     timeout: float = 2.0,
#     retries: int = 2,
#     delay: float = 1,
# ):
#     network = IPv4Network(cidr, strict=False)
#     live_hosts = {}
#     packets = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
#         pdst=[str(ip) for ip in network.hosts()]
#     )
#     for _ in range(retries):
#         start = time.monotonic()
#         answered, unanswered = srp(
#             packets,
#             timeout=timeout,
#             iface=iface,
#             verbose=False,
#         )

#         for sent, recv in answered:
#             rtt = (float(recv.time) - float(sent.time)) * 1000
#             live_hosts[recv.psrc] = {
#                 "mac": recv.hwsrc,
#                 "rtt": rtt,
#                 "scan_rtt": time.monotonic() - start,
#             }

#         time.sleep(delay)

#     return live_hosts


# def ping_scan(
#     iface: str = "enp2s0", cidr: str = "192.168.20.0/24", timeout: float = 5.0
# ):
#     packets = [
#         Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst=str(ip)) / ICMP()
#         for ip in IPv4Network(cidr, strict=False).hosts()
#     ]
#     answered, _ = srp(packets, iface=iface, timeout=timeout, verbose=False)
#     return [recv[IP].src for _, recv in answered]


if __name__ == "__main__":
    print("=== ARP Scan Results Asyncio ===")
    for idx, (ip, content) in enumerate(
        asyncio.run(fresh_arp_scan_async(timeout=2)).items()
    ):
        print(f"{idx}: {ip} {content}")

    # print("=== ARP Scan Results ===")
    # for idx, (ip, content) in enumerate(fresh_arp_scan(timeout=2).items()):
    #     print(f"{idx}: {ip} {content}")

    # print("\n=== Ping Scan Results ===")
    # for idx, ip in enumerate(ping_scan()):
    #     print(f"{idx}: {ip}")
