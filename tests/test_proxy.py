import time
import pytest
import threading
import http.client
from queue import Queue


PROXY_HOST = "0.0.0.0"
PROXY_PORT = 8899


def make_http_request(host_header: str) -> http.client.HTTPResponse:
    conn = http.client.HTTPConnection(PROXY_HOST, PROXY_PORT, timeout=5)
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


def test_batch_requests(number_request:int = 20):
    """Send 50 concurrent requests to the proxy."""
    queue = Queue()
    workers = []
    hosts = ["example.com"] * number_request

    for host in hosts:
        _worker = threading.Thread(target=worker, args=(host, queue))
        _worker.start()
        workers.append(_worker)
        time.sleep(0.5)

    for _worker in workers:
        _worker.join()

    results = []
    while not queue.empty():
        results.append(queue.get())

    for _each in results:
        print(_each)
    for _result in results:
        if "status" in _result:
            assert _result["status"] == 200, f"Unexpected response from {_result['host']}: {_result['status']}"
        else:
            pytest.fail(f"Request failed for {_result['host']}: {_result['error']}")
