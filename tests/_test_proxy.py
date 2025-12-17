import http.client
import statistics
import threading
import time
from queue import Queue

import pytest

PROXY_HOST = "0.0.0.0"
PROXY_PORT = 8899
TIMEOUT = 10
LOCAL_SERVER_HOST = "127.0.0.1"
LOCAL_SERVER_PORT = 9000


def make_http_request(host_header: str) -> http.client.HTTPResponse:
    conn = http.client.HTTPConnection(PROXY_HOST, PROXY_PORT, timeout=TIMEOUT)
    conn.request(
        method="GET",
        url=f"http://{host_header}/",
        headers={"User-Agent": "pytest-http-client"}
    )
    return conn.getresponse()


def test_proxy_running():
    """Sanity check: proxy must be up."""
    try:
        response: http.client.HTTPResponse = make_http_request("example.com")
        assert response.status is not None
        response.close()
    except Exception as e:
        pytest.fail(f"Proxy is NOT running on {PROXY_HOST}:{PROXY_PORT}: {e}")


def test_allowed_request():
    """Allowed domain should NOT be blocked."""
    response: http.client.HTTPResponse = make_http_request("example.com")
    assert response.status == 200
    response.close()


def test_blocked_request():
    response: http.client.HTTPResponse = make_http_request("ads.ekipa.mk")
    assert response.status == 403 or response.status == 400
    response.close()


def worker(host: str, queue: Queue):
    """Thread worker to perform request, measure duration, and store result in queue."""
    try:
        start_time = time.perf_counter()
        response: http.client.HTTPResponse = make_http_request(host)
        duration = time.perf_counter() - start_time
        status = response.status
        response.read()
        response.close()
        queue.put({"host": host, "status": status, "duration": duration})
    except Exception as e:
        queue.put({"host": host, "error": str(e)})

def generate_stats(results):
    if not results:
        print("No results.")
        return

    durations = [r["duration"] for r in results if "duration" in r]
    statuses  = [r["status"] for r in results if "status" in r]
    errors    = [r for r in results if "error" in r]

    print("=== Batch Statistics ===")
    print(f"Total requests:       {len(results)}")
    print(f"Successful responses: {len(statuses)}")
    print(f"Errors:               {len(errors)}")

    if not durations:
        print("No duration data.")
        return

    # Pre-sort once
    durations_sorted = sorted(durations)
    count = len(durations_sorted)

    # Percentile helpers
    def percentile(sorted_list, q):
        idx = int(q * (len(sorted_list) - 1))
        return sorted_list[idx]

    print(f"Min duration:         {durations_sorted[0]:.4f} s")
    print(f"Max duration:         {durations_sorted[-1]:.4f} s")
    print(f"Avg duration:         {statistics.mean(durations_sorted):.4f} s")
    print(f"Median duration:      {statistics.median(durations_sorted):.4f} s")
    print(f"Std deviation:        {statistics.pstdev(durations_sorted):.4f} s")
    print(f"95th percentile:      {percentile(durations_sorted, 0.95):.4f} s")
    print(f"99th percentile:      {percentile(durations_sorted, 0.99):.4f} s")


def test_batch_requests(number_request: int = 1000):
    """Send concurrent requests to the proxy for /short and /long endpoints."""
    queue = Queue()
    workers = []

    # Phase 1: /short
    short_hosts = [f"{LOCAL_SERVER_HOST}:{LOCAL_SERVER_PORT}/short"] * number_request
    for host in short_hosts:
        _worker = threading.Thread(target=worker, args=(host, queue), daemon=True)
        _worker.start()
        workers.append(_worker)
        time.sleep(0.01)
    for _worker in workers:
        _worker.join()

    short_results = []
    while not queue.empty():
        short_results.append(queue.get())

    print("\n=== /short Results ===")
    generate_stats(short_results)

    for _result in short_results:
        if "status" in _result:
            assert _result["status"] == 200 or _result["status"] == 301, f"Unexpected response from {_result['host']}: {_result['status']}"
        else:
            pytest.fail(f"Request failed for {_result['host']}: {_result['error']}")

    # Phase 2: /long
    queue.queue.clear()  # reset the queue
    workers.clear()
    long_hosts = [f"{LOCAL_SERVER_HOST}:{LOCAL_SERVER_PORT}/long"] * number_request
    for host in long_hosts:
        _worker = threading.Thread(target=worker, args=(host, queue), daemon=True)
        _worker.start()
        workers.append(_worker)
        time.sleep(0.01)
    for _worker in workers:
        _worker.join()

    long_results = []
    while not queue.empty():
        long_results.append(queue.get())

    print("\n=== /long Results ===")
    generate_stats(long_results)

    for _result in long_results:
        if "status" in _result:
            assert _result["status"] == 200 or _result["status"] == 301, f"Unexpected response from {_result['host']}: {_result['status']}"
        else:
            pytest.fail(f"Request failed for {_result['host']}: {_result['error']}")
