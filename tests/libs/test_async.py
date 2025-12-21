import pytest
import requests
import statistics
import asyncio
import time
import threading
import aiohttp
import dnslib
import socket
from typing import List, Optional
from src.libs.workers import AsyncWorkerThread,SyncWorkerThread


def make_dns_query(domain: str, qtype: str = "A") -> dnslib.DNSRecord:
    """Generate a DNSRecord query for a domain."""
    return dnslib.DNSRecord.question(domain, qtype=qtype)


async def probe_dns_server(request: dnslib.DNSRecord,dns_server: str = "1.1.1.1", port: int = 53, timeout: float = 2.0, max_msg_size: int = 1500):
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        await loop.sock_sendto(sock, request.pack(), (dns_server, port))
        data = await asyncio.wait_for(loop.sock_recv(sock, max_msg_size), timeout)
        response = dnslib.DNSRecord.parse(data)
        return response, dns_server
    finally:
        sock.close()


def probe_dns_server_sync(request: dnslib.DNSRecord, dns_server: str = "1.1.1.1", port: int = 53, timeout: float = 2.0, max_msg_size: int = 1500):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(request.pack(), (dns_server, port))
        data, _ = sock.recvfrom(max_msg_size)
        response = dnslib.DNSRecord.parse(data)
        return response, dns_server
    finally:
        sock.close()


def fetch_url_sync(url: str, timeout: float = 10.0) -> tuple[int, str]:
    res = requests.get(url, timeout=timeout)
    return res.status_code, res.text


async def fetch_url_async(url: str, timeout: float = 10.0):
    async with aiohttp.ClientSession() as session:
        async with session.get(url, timeout=timeout) as resp: # type: ignore
            text = await resp.text()
            return resp.status, text


async def async_sleep(name: str, delay: float, fail=False):
    await asyncio.sleep(delay)
    if fail:
        raise ValueError(f"{name} failed")
    return name


def sync_sleep(name: str, delay: float, fail=False):
    time.sleep(delay)
    if fail:
        raise ValueError(f"{name} failed")
    return name


@pytest.mark.asyncio
async def test_submit_job_async():

    worker = AsyncWorkerThread()
    args = (f"task", 0.5, False)
    kwargs = {"name":"task","delay":0.5,"fail":False}

    # Happy
    assert worker.submit_job(func=async_sleep, args=args).result() == "task"
    assert worker.submit_job(func=async_sleep, kwargs=kwargs).result() == "task"

    with pytest.raises(ValueError):
        worker.submit_job(func=async_sleep, args=(f"task", 0.5, True),timeout=1).result()

    # Timeout
    with pytest.raises(asyncio.TimeoutError):
        worker.submit_job(func=async_sleep, args=args,timeout=0.1).result()

    # Happy
    with pytest.raises(TypeError):
        worker.submit_job(func=async_sleep, args="123").result() # type: ignore
    with pytest.raises(TypeError):
        worker.submit_job(func="123", args=args).result() # type: ignore
    with pytest.raises(TypeError):
        worker.submit_job(func=async_sleep, kwargs="123").result() # type: ignore
    with pytest.raises(TypeError):
        worker.submit_job(func=async_sleep, kwargs=kwargs,timeout={}).result() # type: ignore

    worker.stop()


def test_submit_job_sync():
    worker = SyncWorkerThread()
    args = (f"task", 0.5, False)
    kwargs = {"name":"task","delay":0.5,"fail":False}

    # Happy
    assert worker.submit_job(func=sync_sleep, args=args).result() == "task"
    assert worker.submit_job(func=sync_sleep, kwargs=kwargs).result() == "task"

    with pytest.raises(ValueError):
        worker.submit_job(func=sync_sleep, args=(f"task", 0.5, True),timeout=1).result()

    # Timeout
    with pytest.raises(asyncio.TimeoutError):
        worker.submit_job(func=sync_sleep, args=args,timeout=0.1).result()

    # Wrong input
    with pytest.raises(TypeError):
        worker.submit_job(func=sync_sleep, args="123").result() # type: ignore
    with pytest.raises(TypeError):
        worker.submit_job(func="123", args=args).result() # type: ignore
    with pytest.raises(TypeError):
        worker.submit_job(func=sync_sleep, kwargs="123").result() # type: ignore
    with pytest.raises(TypeError):
        worker.submit_job(func=sync_sleep, kwargs=kwargs,timeout={}).result() # type: ignore

    worker.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "delay,qty",
    [
        (0.1, 1),
        (0.1, 50),
        (0.1, 200),
    ],
)
async def test_concurrent_sleep_async(delay:float,qty:int):
    _start: float = time.time()

    worker = AsyncWorkerThread()
    results: List[Optional[str]] = [None] * qty
    timings: List[Optional[float]] = [None] * qty

    def _submit(index: int):
        args = (f"task-{index}", delay, False)
        start = time.time()
        fut = worker.submit_job(func=async_sleep, args=args)
        results[index] = fut.result()
        end = time.time()
        timings[index] = end - start

    threads = [threading.Thread(target=_submit, args=(i,)) for i in range(qty)]

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert all(str(res).startswith("task-") for res in results)
    print(f"\nTook:{time.time()-_start:.3f}s Min:{min(timings):.3f}s Max:{max(timings):.3f}s Avg:{statistics.mean(timings):.3f}s") # type: ignore

    worker.stop()


@pytest.mark.parametrize(
    "delay,qty",
    [
        (0.1, 1),
        (0.1, 50),
        (0.1, 200),
    ],
)
def test_concurrent_sleep_sync(delay:float,qty:int):
    _start: float = time.time()

    worker = SyncWorkerThread()
    results: List[Optional[str]] = [None] * qty
    timings: List[Optional[float]] = [None] * qty

    def _submit(index: int):
        args = (f"task-{index}", delay, False)
        start = time.time()
        fut = worker.submit_job(func=sync_sleep, args=args)
        results[index] = fut.result()
        end = time.time()
        timings[index] = end - start

    threads = [threading.Thread(target=_submit, args=(i,)) for i in range(qty)]

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert all(str(res).startswith("task-") for res in results)
    print(f"\nTook:{time.time()-_start:.3f}s Min:{min(timings):.3f}s Max:{max(timings):.3f}s Avg:{statistics.mean(timings):.3f}s") # type: ignore

    worker.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url,qty",
    [
        ("https://example.com", 10),
        ("https://example.com", 10),
    ],
)
async def test_concurrent_url_async(url:str,qty:int):
    _start: float = time.time()
    worker = AsyncWorkerThread()
    results: List[Optional[str]] = [None] * qty
    timings: List[Optional[float]] = [None] * qty
    url_timeout = 10

    def _submit(index: int):
        args = (url, url_timeout)
        start = time.time()
        fut = worker.submit_job(func=fetch_url_async, args=args)
        results[index] = fut.result()
        end = time.time()
        timings[index] = end - start

    threads = [threading.Thread(target=_submit, args=(i,)) for i in range(qty)]

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert all(res and res[0] == 200 for res in results)
    print(f"\nTook:{time.time()-_start:.3f}s Min:{min(timings):.3f}s Max:{max(timings):.3f}s Avg:{statistics.mean(timings):.3f}s") # type: ignore

    worker.stop()


@pytest.mark.parametrize(
    "url,qty",
    [
        ("https://example.com", 10),
        ("https://example.com", 10),
    ],
)
def test_concurrent_url_sync(url:str,qty:int):
    _start: float = time.time()
    worker = SyncWorkerThread()
    results: List[Optional[str]] = [None] * qty
    timings: List[Optional[float]] = [None] * qty
    url_timeout = 10

    def _submit(index: int):
        args = (url, url_timeout)
        start = time.time()
        fut = worker.submit_job(func=fetch_url_sync, args=args)
        results[index] = fut.result()
        end = time.time()
        timings[index] = end - start

    threads = [threading.Thread(target=_submit, args=(i,)) for i in range(qty)]

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert all(res and res[0] == 200 for res in results)
    print(f"\nTook:{time.time()-_start:.3f}s Min:{min(timings):.3f}s Max:{max(timings):.3f}s Avg:{statistics.mean(timings):.3f}s") # type: ignore

    worker.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url,server,qty",
    [
        ("example.com", "1.1.1.1", 5),
        ("example.com", "8.8.8.8", 5),
        ("example.com", "1.1.1.1", 10),
    ],
)
async def test_concurrent_dns_req_async(url:str,server:str,qty:int) -> None:
    _start: float = time.time()
    worker = AsyncWorkerThread()
    results: List[Optional[str]] = [None] * qty
    timings: List[Optional[float]] = [None] * qty
    req = make_dns_query(url)
    url_timeout = 10

    def _submit(index: int):
        args = (req,server)
        start = time.time()
        fut = worker.submit_job(func=probe_dns_server, args=args)
        results[index] = fut.result()
        end = time.time()
        timings[index] = end - start

    threads = [threading.Thread(target=_submit, args=(i,)) for i in range(qty)]

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert all(res and res[0].header.rcode == 0 for res in results) # type: ignore
    print(f"\nTook:{time.time()-_start:.3f}s Min:{min(timings):.3f}s Max:{max(timings):.3f}s Avg:{statistics.mean(timings):.3f}s") # type: ignore

    worker.stop()


@pytest.mark.parametrize(
    "url,server,qty",
    [
        ("example.com", "1.1.1.1", 5),
        ("example.com", "8.8.8.8", 5),
        ("example.com", "1.1.1.1", 10),
    ],
)
def test_concurrent_dns_req_sync(url:str,server:str,qty:int):
    _start: float = time.time()
    worker = SyncWorkerThread()
    results: List[Optional[str]] = [None] * qty
    timings: List[Optional[float]] = [None] * qty
    req = make_dns_query(url)
    url_timeout = 10

    def _submit(index: int):
        args = (req,server)
        start = time.time()
        fut = worker.submit_job(func=probe_dns_server_sync, args=args)
        results[index] = fut.result()
        end = time.time()
        timings[index] = end - start

    threads = [threading.Thread(target=_submit, args=(i,)) for i in range(qty)]

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert all(res and res[0].header.rcode == 0 for res in results) # type: ignore
    print(f"\nTook:{time.time()-_start:.3f}s Min:{min(timings):.3f}s Max:{max(timings):.3f}s Avg:{statistics.mean(timings):.3f}s") # type: ignore

    worker.stop()

