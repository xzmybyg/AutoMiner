import socket

import pytest
from app.policy import Denied, check_url, request, resolve


def target(**kw):
    return dict(
        {
            "scheme": "https",
            "host": "app.example.com",
            "port": 443,
            "kind": "owned",
            "paths": ["/api"],
            "deny_paths": ["/api/admin"],
            "bound_ips": ["93.184.216.34"],
        },
        **kw,
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://app.example.com.evil.test/api",
        "https://sub.app.example.com/api",
        "http://app.example.com/api",
        "https://app.example.com:444/api",
        "https://app.example.com/api2",
        "https://app.example.com/api/admin/users",
        "https://app.example.com/api/%2e%2e/admin",
        "https://app.example.com/api/%252e%252e/admin",
        "https://app.example.com/api%2fadmin",
        "https://app.example.com/api\\admin",
        "https://user@app.example.com/api",
        "https://app.example.com/api#fragment",
        "https://app.example.com/api/%00",
        "https://app.example.com/api/%GG",
    ],
)
def test_reject_outside_and_ambiguous(url):
    with pytest.raises(Denied):
        check_url(target(), url)


def test_valid_path():
    assert check_url(target(), "https://app.example.com/api/items").path == "/api/items"


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "169.254.169.254",
        "10.0.0.1",
        "::1",
        "::ffff:127.0.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "93.184.216.35",
    ],
)
def test_dns_rebinding_and_internal(monkeypatch, address):
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *a, **kw: [(0, 0, 0, "", (address, 443))]
    )
    with pytest.raises(Denied):
        resolve(target())


def test_lab_exact_binding(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *a, **kw: [(0, 0, 0, "", ("172.30.10.10", 8080))]
    )
    t = target(kind="lab", bound_ips=["172.30.10.10"])
    assert resolve(t) == ["172.30.10.10"]


def test_public_target_cannot_masquerade_as_lab(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *a, **kw: [(0, 0, 0, "", ("93.184.216.34", 443))]
    )
    with pytest.raises(Denied):
        resolve(target(kind="lab"))


def test_ipv6_global(monkeypatch):
    address = "2606:4700:4700::1111"
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *a, **kw: [(0, 0, 0, "", (address, 443))]
    )
    assert resolve(target(bound_ips=[address])) == [address]


def test_redirect_not_followed_and_proxy_ignored(monkeypatch):
    calls = []

    class Response:
        status = 302

        def read1(self, n):
            return b""

        def getheaders(self):
            return [("Location", "https://outside.test/")]

        def getheader(self, k):
            return "https://outside.test/"

    class Connection:
        sock = None

        def __init__(self, *args, **kw):
            calls.append(args)

        def request(self, *args, **kw):
            pass

        def getresponse(self):
            return Response()

        def close(self):
            pass

    monkeypatch.setenv("HTTPS_PROXY", "http://outside.test:9999")
    monkeypatch.setattr("app.policy.resolve", lambda t: ["93.184.216.34"])
    monkeypatch.setattr("app.policy.PinnedHTTPS", Connection)
    result = request(target(), "https://app.example.com/api")
    assert result["redirect_blocked"] and len(calls) == 1
    assert calls[0][-1] == "93.184.216.34"
