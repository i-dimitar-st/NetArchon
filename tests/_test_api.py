import time
import pytest
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://192.168.20.100:8443"
HEALTZ_ENDPOINT = f"{BASE_URL}/healtz"
ITERATIONS = 5

@pytest.mark.parametrize("iteration", range(1, ITERATIONS + 1))
def test_healtz(iteration):
    start_time = time.time()
    response = requests.get(HEALTZ_ENDPOINT,verify=False)
    duration = (time.time() - start_time) * 1000

    print(f"Iteration {iteration}/{ITERATIONS} | Status code: {response.status_code} | Time: {duration:.2f} ms")
    assert response.status_code == 200, f"Unexpected status code: {response.status_code}"

    try:
        data = response.json()
    except Exception as e:
        pytest.fail(f"Response is not valid JSON: {e}")

    payload_status = data.get("payload", {}).get("status")
    assert payload_status == "ok", f"Expected payload.status='ok', got '{payload_status}'"
