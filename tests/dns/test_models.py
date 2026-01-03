import socket
import threading
import time

from dnslib import QTYPE, DNSRecord

from src.services.dns.models import (
    DNSCache,
    DNSMessageQueue,
    DNSReqMsg,
    DNSRequestType,
    DNSResponseCode,
    DnsSocket,
)


def test_dns_response_code() -> None:
    assert DNSResponseCode.NO_ERROR == 0
    assert DNSResponseCode.NOT_IMPLEMENTED == 4
    assert str(DNSResponseCode.REFUSED) == "5"


def test_dns_request_type() -> None:
    assert DNSRequestType.A == 1
    assert DNSRequestType.AAAA == 28
    assert str(DNSRequestType.MX) == "15"


def test_dns_req_msg() -> None:
    raw = DNSRecord.question(qname="eXaMple.com.", qtype="A").pack()
    qry = DNSRecord.parse(raw)
    addr = ("127.0.0.1", 5353)

    msg = DNSReqMsg(raw, addr)

    # Properties
    assert msg.raw == raw
    assert msg.addr == addr
    assert msg.domain == "example.com"
    assert msg.dns_message.q.qtype == QTYPE.A

    # Methods
    assert msg.dns_message.pack() == raw
    assert (qry.q.qname, qry.q.qtype) == msg.cache_key
    assert (
        qry.q.qname,
        qry.q.qtype,
        qry.header.id,
        addr[0],
    ) == msg.dedup_key


def test_DNSCache() -> None:
    cache = DNSCache(max_size=5, max_ttl=1)
    record = DNSRecord.question("example.com")

    # Happy
    for index in range(2):
        cache.set(f"example-{index}.com", record)
        assert cache.get(f"example-{index}.com") == record

    # Clearing
    cache.clear()
    assert len(cache._cache.keys()) == 0

    # Saving & overwriting
    for index in range(10):
        cache.set(f"example-{index}.com", record)
        item = cache.get(f"example-{index}.com")
        assert item and item.pack() == record.pack()
    assert len(cache._cache.keys()) == 5

    # Eviction
    for index in range(5):
        assert cache.get(f"example-{index}.com") is None
    for index in range(5, 10):
        item = cache.get(f"example-{index}.com")
        assert item and item.pack() == record.pack()

    # Expiry
    cache.clear()
    cache.set("example.com", record)
    time.sleep(1.1)
    assert cache.get("example.com") is None
    assert len(cache._cache.keys()) == 0


def test_DNSMessageQueue() -> None:
    queue = DNSMessageQueue(max_size=2)

    # Empty
    assert queue.get() is None
    queue.drain()
    assert queue.get() is None

    # FIFO
    queue.set(1)
    queue.set(2)

    assert queue.get() == 1
    assert queue.get() == 2
    assert queue.get() is None

    # Overflow
    queue.set("a")
    queue.set("b")
    queue.set("c")
    assert queue.get() == "b"
    assert queue.get() == "c"
    assert queue.get() is None

    # Drain
    queue.set(10)
    queue.set(20)
    queue.drain()
    assert queue.get() is None

    # task_done
    queue.task_done()
    queue.set(10)
    queue.task_done()
    queue.task_done()

    # Overwriting
    queue = DNSMessageQueue(max_size=1)
    start = time.time()
    for index in range(3):
        queue.set(index)
    assert queue.get() == 2
    assert queue.get() is None

    # Non blocking vs immediate get get
    queue = DNSMessageQueue(max_size=3)
    start = time.time()
    for index in range(3):
        queue.set(index)
    for index in range(3):
        queue.get(timeout=0.1)
    duration = time.time() - start
    assert duration < 0.01

    # Non blocking vs immediate get get
    queue = DNSMessageQueue(max_size=3)
    start = time.time()
    for index in range(3):
        queue.set(index)
    for index in range(3):
        queue.get()
    duration = time.time() - start
    assert duration < 0.01


def test_DNSMessageQueue_pressure() -> None:

    items = 2000
    timeout = 1/10000
    max_expected = items * timeout
    max_expected_full_queue = items * timeout * 5

    queue = DNSMessageQueue(max_size=1024)
    start = time.time()
    for index in range(items):
        queue.set(index)
    duration = time.time() - start
    assert duration < max_expected

    queue = DNSMessageQueue(max_size=1)
    start = time.time()
    for index in range(items):
        queue.set(index, timeout=timeout)
    duration = time.time() - start
    assert duration < max_expected_full_queue


    produced, consumed = [], []
    producers_qty = 1
    consumers_qty = 200
    # Optimum number is driven by the lag in processing
    # producer 0.005 consumer consumer 0.2 => 40 processors required
    items_per_producer = 100
    total_items = producers_qty * items_per_producer
    queue = DNSMessageQueue(max_size=1024)

    def producer(start_index):
        for i in range(1, items_per_producer + 1):
            value = start_index + i
            produced.append(value)
            queue.set(value)
            time.sleep(0.003)

    def consumer():
        while len(consumed) < total_items:
            item = queue.get()
            if item is not None:
                consumed.append(item)
                time.sleep(0.5)

    threads = []
    for p in range(producers_qty):
        threads.append(threading.Thread(target=producer, args=(p * items_per_producer,)))
    start = time.time()
    for _ in range(consumers_qty):
        threads.append(threading.Thread(target=consumer))

    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=1)
    assert len(consumed) == len(produced)


def test_DnsSocket():
    server = DnsSocket(host="127.0.0.1", port=0)
    server_port = server._sock.getsockname()[1]

    client = DnsSocket(host="127.0.0.1", port=0)
    client_port = client._sock.getsockname()[1]

    client.send(b"ping", ("127.0.0.1", server_port))
    _data = server.receive(timeout=0.1)
    assert _data is not None
    assert _data[0] == b"ping"

    client.send(b"x", ("127.0.0.1", server_port))
    _data = server.receive(timeout=0.1)
    assert _data and _data[0] == b"x"

    client.send(b"x" * 1024, ("127.0.0.1", server_port))
    _data = server.receive(timeout=0.1)
    assert _data and _data[0] == b"x" * 1024

    client.send(b"x" * 1500, ("127.0.0.1", server_port))
    _data = server.receive(timeout=0.1)
    assert _data and _data[0] == b"x" * 1500

    client.send(b"x" * 2000, ("127.0.0.1", server_port))
    _data = server.receive(timeout=0.1)
    assert _data and _data[0] == b"x" * 1500

    server.send(b"x"*1500, ("127.0.0.1", client_port))
    _data = client.receive(timeout=0.1)
    assert _data and _data[0] == b"x"*1500

    server.close()
    server.close()
    server.send(b"data", ("127.0.0.1", client_port))
    client.close()


def test_DnsSocket_pressure():
    server = DnsSocket(host="127.0.0.1", port=0, buffer_size=1024*1024*16)
    port = server._sock.getsockname()[1]
    num_senders = 10
    num_receivers = 10
    messages_per_sender = 1500
    msg = b'x' * 1500
    received = []
    expected_messages = num_senders * messages_per_sender

    stop_flag = threading.Event()

    def _receiver():
        while not stop_flag.is_set() or len(received) < expected_messages:
            while True:
                data = server.receive(timeout=0.001, msg_size=1500)
                if not data:
                    break
                received.append(data[0])

    def _sender():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 16 * 1024 * 1024)
            for _ in range(messages_per_sender):
                sock.sendto(msg, ("127.0.0.1", port))

    recv_threads = [threading.Thread(target=_receiver) for _ in range(num_receivers)]
    for t in recv_threads:
        t.start()

    _start = time.perf_counter()
    sender_threads = [threading.Thread(target=_sender) for _ in range(num_senders)]
    for t in sender_threads: t.start()
    for t in sender_threads: t.join()
    duration = time.perf_counter() - _start

    stop_flag.set()
    for t in recv_threads: t.join()
    server.close()
    assert expected_messages == len(received)
    assert all(len(m) <= 1500 for m in received)

    print(f"Duration: {duration:.3f} Messages: {len(received)} "
          f"Throughput: {sum(len(m) for m in received)*8 / duration / 1_000_000:.2f} Mb/sec")

