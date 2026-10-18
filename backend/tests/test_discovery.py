import json

import pytest
from app.discovery import (
    DiscoveryInput,
    Selection,
    extract,
    history,
    import_selected,
    process,
    start,
)
from app.main import app, emergency_stop, revoke, tick
from app.policy import Denied
from app.service import all_of, create, get, locked, save
from app.store import Session, now
from fastapi import HTTPException
from fastapi.testclient import TestClient


def fixture():
    with locked() as s:
        return create(
            s,
            "target",
            {
                "name": "fixture",
                "kind": "owned",
                "scheme": "https",
                "host": "app.example",
                "port": 443,
                "paths": ["/"],
                "deny_paths": ["/logout"],
                "verified": True,
                "revoked": False,
                "version": 1,
                "expires_at": now() + 300,
                "used": 0,
                "request_budget": 30,
            },
        )


def run_discovery(monkeypatch, target, budget=4, depth=1):
    d = start(
        target["id"],
        DiscoveryInput(seeds=["/"], request_budget=budget, max_depth=depth),
    )
    with locked() as s:
        row = get(s, d["id"])
        row.update(status="running", deadline=now() + 120)
        save(s, row)
    sent = []

    def transport(target, url, before_send):
        before_send()
        sent.append(url)
        body = (
            '<a href="/page">page</a><a href="https://outside.example/api/private">outside</a><a href="/logout">logout</a><script src="/app.js"></script>'
            if url.endswith("/")
            else (
                'fetch("/api/read");axios.post("/api/write");const hint="/api/unknown";'
                if url.endswith(".js")
                else '<a href="/deeper">deep</a>'
            )
        )
        return {
            "status": 200,
            "headers": {
                "Content-Type": "text/javascript"
                if url.endswith(".js")
                else "text/html"
            },
            "body": body,
            "truncated": False,
        }

    monkeypatch.setattr("app.discovery.request", transport)
    process(d["id"])
    return history(target["id"])[0], sent


def test_bounded_discovery_never_requests_candidate_business_api_or_outside(
    monkeypatch,
):
    target = fixture()
    row, sent = run_discovery(monkeypatch, target)
    assert row["status"] == "completed"
    assert sent == [
        "https://app.example:443/",
        "https://app.example:443/page",
        "https://app.example:443/app.js",
    ]
    assert not any("/api/" in u or "/logout" in u or "outside" in u for u in sent)
    candidates = row["candidates"]
    assert any(
        c["method"] == "POST" and c["url"].endswith("/api/write") for c in candidates
    )
    assert any(not c["importable"] and "outside" in c["url"] for c in candidates)
    assert any(c["method"] == "UNKNOWN" and not c["importable"] for c in candidates)
    with Session() as s:
        assert get(s, target["id"])["used"] == 3
        assert all_of(s, "endpoint") == []
    chosen = next(c for c in candidates if c["method"] == "POST")
    imported = import_selected(row["id"], Selection(candidate_ids=[chosen["id"]]))[
        "imported"
    ]
    assert len(imported) == 1 and not imported[0]["executable"]
    assert (
        import_selected(row["id"], Selection(candidate_ids=[chosen["id"]]))["imported"]
        == []
    )


def test_budget_depth_and_query_seeds(monkeypatch):
    target = fixture()
    with pytest.raises(HTTPException):
        start(target["id"], DiscoveryInput(seeds=["/?token=secret"]))
    row, sent = run_discovery(monkeypatch, target, budget=1)
    assert len(sent) == 1 and row["used"] == 1 and "预算" in row["note"]
    row, sent = run_discovery(monkeypatch, target, budget=4, depth=0)
    assert len(sent) == 1 and row["used"] == 1


def test_openapi_relative_server_and_templates_and_no_secret_retention():
    target = fixture()
    document = {
        "openapi": "3.0.0",
        "servers": [{"url": "/v1"}],
        "paths": {"/users": {"get": {}}, "/users/{id}": {"delete": {}}},
    }
    rows, hints = extract(
        target,
        "https://app.example/docs/openapi.json",
        json.dumps(document),
        "application/json",
    )
    assert rows[0]["url"] == "https://app.example/v1/users" and rows[0]["importable"]
    assert not rows[1]["importable"] and hints == []
    rows, _ = extract(
        target,
        "https://app.example/",
        'fetch("/api/x?token=TOPSECRET");',
        "text/javascript",
    )
    assert all("TOPSECRET" not in json.dumps(c) and not c["importable"] for c in rows)
    rows, _ = extract(
        target,
        "https://app.example/",
        '<a href="https://outside.example/api/x?token=TOPSECRET">x</a><a href="https://user:PASSWORD@outside.example/api/x">y</a>',
        "text/html",
    )
    assert "TOPSECRET" not in json.dumps(rows) and "PASSWORD" not in json.dumps(rows)
    rows, _ = extract(
        target,
        "https://app.example/",
        '{"openapi":"3.0.0","paths":{"/x":{"get":{}}}}',
        "application/json",
    )
    assert rows[0]["url"] == "https://app.example:443/x"


def test_revocation_after_first_response_stops_remaining_requests(monkeypatch):
    target = fixture()
    d = start(target["id"], DiscoveryInput(seeds=["/"]))
    with locked() as s:
        row = get(s, d["id"])
        row.update(status="running", deadline=now() + 120)
        save(s, row)
    sent = []

    def transport(target, url, before_send):
        before_send()
        sent.append(url)
        revoke(target["id"])
        return {
            "status": 200,
            "headers": {"Content-Type": "text/html"},
            "body": '<a href="/next">next</a>',
            "truncated": False,
        }

    monkeypatch.setattr("app.discovery.request", transport)
    process(d["id"])
    row = history(target["id"])[0]
    assert len(sent) == 1 and row["status"] == "stopped"
    with pytest.raises(Denied):
        import_selected(d["id"], Selection(candidate_ids=[row["candidates"][0]["id"]]))


def test_gateway_scheduler_auth_and_emergency_stop(monkeypatch):
    target = fixture()
    d = start(target["id"], DiscoveryInput(seeds=["/"]))
    client = TestClient(app)
    assert client.get(f"/api/targets/{target['id']}/discoveries").status_code == 401
    monkeypatch.setattr("app.main.ROLE", "gateway")
    calls = []
    monkeypatch.setattr("app.discovery.process", lambda ident: calls.append(ident))
    tick()
    assert calls == [d["id"]]
    emergency_stop()
    assert history(target["id"])[0]["status"] == "stopped"


@pytest.mark.parametrize("budget", [1, 4])
def test_automatic_scan_registers_safe_candidates_without_sending_business_requests(
    monkeypatch, budget
):
    target = fixture()
    sent = []

    def transport(target, url, before_send):
        before_send()
        sent.append(url)
        return {
            "status": 200,
            "headers": {"Content-Type": "text/html"},
            "body": '<script src="/assets/app.js"></script>fetch("/api/read");axios.post("/api/write");'
            'fetch("/api/users/{id}");fetch("https://outside.example/api/no");'
            '<a href="/next">next</a>',
            "truncated": False,
        }

    monkeypatch.setattr("app.discovery.request", transport)
    for repeat in range(2):
        row = start(
            target["id"],
            DiscoveryInput(automatic=True, request_budget=budget, max_depth=1),
        )
        assert row["seeds"] == ["https://app.example:443/"]
        with locked() as s:
            current = get(s, row["id"])
            current.update(status="running", deadline=now() + 120)
            save(s, current)
        process(row["id"])
        row = history(target["id"])[0]
        assert row["status"] == "completed"
        assert row["auto_imported"] == (3 if repeat == 0 else 0)
    with Session() as s:
        endpoints = all_of(s, "endpoint")
    assert len(endpoints) == 3
    assert {(e["method"], e["url"].split("/")[-1]) for e in endpoints} == {
        ("GET", "read"),
        ("POST", "write"),
        ("GET", "next"),
    }
    assert not next(e for e in endpoints if e["method"] == "POST")["executable"]
    assert not any("/api/" in url or "outside" in url for url in sent)


def test_automatic_scan_respects_authorized_paths_and_inactive_targets():
    target = fixture()
    with locked() as s:
        target["paths"] = ["/app"]
        save(s, target)
    row = start(
        target["id"], DiscoveryInput(automatic=True, seeds=["https://outside.example/"])
    )
    assert row["seeds"] == ["https://app.example:443/app"]
    with pytest.raises(HTTPException):
        start(target["id"], DiscoveryInput())
    revoke(target["id"])
    with pytest.raises(Denied):
        start(target["id"], DiscoveryInput(automatic=True))
