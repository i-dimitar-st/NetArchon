# test_utils_lua.py
import pytest
from pathlib import Path
from lupa import LuaRuntime
from src.services.http_proxy.utils import extract_hostname, is_ip_address, is_in_subnet


def test_extract_hostname():
    assert extract_hostname("Example.COM") == "example.com"
    assert extract_hostname(None) == ""


def test_is_ip_address():
    assert is_ip_address("192.168.20.1") is True
    assert is_ip_address("0.0.0.0") is True
    assert is_ip_address("255.255.255.255") is True
    assert is_ip_address("127.0.0.1") is True
    assert is_ip_address("256.1.1.1") is False
    assert is_ip_address("192.168.1") is False
    assert is_ip_address("192.168.1.1.1") is False
    assert is_ip_address("abcd") is False
    assert is_ip_address("") is False
    assert is_ip_address(None) is False


def test_is_in_subnet():
    assert is_in_subnet("192.168.20.1", "192.168.20.100", "24") is True
    assert is_in_subnet("192.168.20.5", "192.168.20.100", "24") is True
    assert is_in_subnet("192.168.20.250", "192.168.20.100", "24") is True
    assert is_in_subnet("192.168.20.0", "192.168.20.100", "24") is True
    assert is_in_subnet("192.168.20.255", "192.168.20.100", "24") is True

    assert is_in_subnet("192.168.21.1", "192.168.20.100", "24") is False
    assert is_in_subnet("192.168.19.255", "192.168.20.100", "24") is False

    assert is_in_subnet("192.168.20.1", "192.168.20.100", "32") is False
    assert is_in_subnet("192.168.20.100", "192.168.20.100", "32") is True
    assert is_in_subnet("192.168.20.1", "192.168.20.100", "16") is True

    assert is_in_subnet("abcd", "192.168.20.100", "24") is False
    assert is_in_subnet(None, "192.168.20.100", "24") is False
    assert is_in_subnet("192.168.20.1", None, "24") is False

