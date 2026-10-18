"""Actual local HTTP fixture traffic; map only the validated lab IP into test loopback."""

import http.client
import importlib.util
import socket
import threading
from http.server import HTTPServer
from pathlib import Path

from app.main import app
from app.service import get, locked, process_job, save
from app.store import Session, now
from fastapi.testclient import TestClient


def test_fixture_end_to_end(monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "fixture_server", Path(__file__).resolve().parents[2] / "demo" / "server.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    server = HTTPServer(("127.0.0.1", 0), module.Demo)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    original_resolve = socket.getaddrinfo
    original_connection = http.client.HTTPConnection

    def resolve(host, port, *args, **kw):
        if host == "demo":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("172.30.10.10", port))]
        return original_resolve(host, port, *args, **kw)

    def connection(address, port, **kwargs):
        assert address == "172.30.10.10" and port == 8080
        return original_connection("127.0.0.1", server.server_port, **kwargs)

    monkeypatch.setattr("app.policy.socket.getaddrinfo", resolve)
    monkeypatch.setattr("app.policy.http.client.HTTPConnection", connection)
    client = TestClient(app)
    headers = {"X-API-Key": "test-token"}

    def post(path, data):
        response = client.post("/api" + path, headers=headers, json=data)
        assert response.status_code == 200, response.text
        return response.json()

    try:
        target = post(
            "/targets",
            {
                "name": "HTTP fixture",
                "kind": "lab",
                "scheme": "http",
                "host": "demo",
                "port": 8080,
                "paths": ["/"],
                "bound_ips": ["172.30.10.10"],
                "statement": "Isolated synthetic local fixture",
                "expires_at": now() + 3600,
                "request_budget": 30,
            },
        )
        with locked() as s:
            target["verified"] = True
            save(s, target)
        endpoints = post(
            "/targets/" + target["id"] + "/imports",
            {
                "format": "manual",
                "document": {
                    "requests": [
                        {"url": "http://demo:8080" + p}
                        for p in ("/public", "/fixture/shared", "/secure/admin")
                    ]
                },
            },
        )["imported"]
        accounts = [
            post(
                "/targets/" + target["id"] + "/accounts",
                {
                    "name": role,
                    "role": role,
                    "headers": {"X-Test-Account": role},
                    "synthetic_data_only": True,
                },
            )["id"]
            for role in ("reader", "admin")
        ]
        job = post(
            "/jobs",
            {
                "target_id": target["id"],
                "endpoint_ids": [e["id"] for e in endpoints],
                "account_ids": accounts,
                "request_budget": 9,
            },
        )
        with locked() as s:
            job.update(status="running", deadline=now() + 120)
            save(s, job)
        process_job(job["id"])
        state = client.get("/api/state", headers=headers).json()
        assert len(state["evidence"]) == 9
        assert all(e["state"] == "complete" for e in state["evidence"])
        secure = next(e for e in endpoints if e["url"].endswith("/secure/admin"))
        results = {
            e["role"]: e["status"]
            for e in state["evidence"]
            if e["endpoint_id"] == secure["id"]
        }
        assert results == {"anonymous": 403, "reader": 403, "admin": 200}
        assert all(f["endpoint_id"] != secure["id"] for f in state["finding"])
        assert all(f["status"] == "pending" for f in state["finding"])
        with Session() as s:
            assert get(s, job["id"])["used"] == 9
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
