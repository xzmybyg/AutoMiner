import socket

import pytest
from app.policy import Denied, check_url, resolve
from app.schemas import TargetInput
from app.store import now


def target(**changes):
    return dict(
        {
            "kind": "local",
            "scheme": "http",
            "host": "localhost",
            "port": 5177,
            "paths": ["/"],
            "deny_paths": ["/danger"],
            "bound_ips": [],
        },
        **changes,
    )


@pytest.fixture
def native(monkeypatch):
    monkeypatch.setenv("DESKTOP_LOCAL_TARGETS", "1")
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **kw: [
            (0, 0, 0, "", ("127.0.0.1", 5177)),
            (0, 0, 0, "", ("::1", 5177)),
        ],
    )


def test_native_localhost_and_ipv6(native):
    assert set(resolve(target())) == {"127.0.0.1", "::1"}
    assert check_url(target(), "http://localhost:5177/").hostname == "localhost"


def test_native_mode_required(monkeypatch):
    monkeypatch.delenv("DESKTOP_LOCAL_TARGETS", raising=False)
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *a, **kw: [(0, 0, 0, "", ("127.0.0.1", 5177))]
    )
    with pytest.raises(Denied):
        resolve(target())


@pytest.mark.parametrize("port", [80, 445, 2375, 2376, 3306, 5432, 6379, 8000, 49199])
def test_control_and_system_ports_blocked(native, monkeypatch, port):
    monkeypatch.setenv("CONTROL_PORTS", "8000,49199")
    with pytest.raises(Denied):
        resolve(target(port=port))


@pytest.mark.parametrize(
    "address",
    ["127.0.0.2", "10.0.0.1", "93.184.216.34", "169.254.169.254", "::ffff:127.0.0.1"],
)
def test_localhost_rebinding_blocked(native, monkeypatch, address):
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *a, **kw: [(0, 0, 0, "", (address, 5177))]
    )
    with pytest.raises(Denied):
        resolve(target())


def test_verified_binding_must_not_change(native):
    with pytest.raises(Denied):
        resolve(target(bound_ips=["127.0.0.1"]))


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:5177/",
        "http://localhost:5178/",
        "http://localhost:5177/danger/run",
    ],
)
def test_local_scope_is_exact(url):
    with pytest.raises(Denied):
        check_url(target(), url)


def test_cannot_declare_arbitrary_host_local():
    with pytest.raises(ValueError):
        TargetInput(
            name="Local",
            kind="local",
            scheme="http",
            host="evil.example",
            port=5177,
            statement="Synthetic local test app",
            expires_at=now() + 3600,
            ownership_declared=True,
        )
