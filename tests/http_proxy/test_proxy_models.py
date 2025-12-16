from src.services.http_proxy.models import ProxyStatsType, HttpRequestRejectedBadRequest, HttpRequestRejectedForbidden


def test_proxy_stats_type_str_and_value():
    assert str(ProxyStatsType.PROXY_RECEIVED) == "proxy_received"
    assert ProxyStatsType.PROXY_RECEIVED.value == "proxy_received"
    assert ProxyStatsType.PROXY_BAD_REQUEST.value == "proxy_bad_request"
    assert ProxyStatsType.PROXY_BLOCKED_HIT.value == "proxy_blocked_hit"
    assert ProxyStatsType.PROXY_HIT.value == "proxy_hit"
    assert isinstance(ProxyStatsType.PROXY_HIT, str)
    assert ProxyStatsType("proxy_hit") is ProxyStatsType.PROXY_HIT


def test_http_request_rejected_bad_request():
    exc = HttpRequestRejectedBadRequest()

    assert exc.status_code == 400
    assert exc.reason == b"Bad Request"
    assert exc.headers == {b"Content-Type": b"text/plain"}
    assert exc.body == b"Host header is missing or invalid."


def test_http_request_rejected_forbidden():
    exc = HttpRequestRejectedForbidden()

    assert exc.status_code == 403
    assert exc.reason == b"Forbidden"
    assert exc.headers == {b"Content-Type": b"text/plain"}
    assert exc.body == b"This site is blocked by the proxy."
