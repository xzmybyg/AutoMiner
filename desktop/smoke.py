"""Disposable end-to-end fixture for source and packaged desktop service testing."""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx


def check(runtime):
    challenge = {"value": ""}
    counts = {"proof": 0, "test": 0}

    class Fixture(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path == "/.well-known/autominer-verification.txt":
                counts["proof"] += 1
                body = challenge["value"].encode()
                self.send_response(200)
            elif self.path == "/redirect":
                counts["test"] += 1
                body = b""
                self.send_response(302)
                self.send_header("Location", "http://localhost:1/outside")
            elif self.path == "/fixture/discovery":
                counts["test"] += 1
                body = b'<script>fetch("/fixture/discovered");axios.post("/fixture/write");</script><a href="http://127.0.0.1:1/outside?token=TOPSECRET">outside</a>'
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
            else:
                counts["test"] += 1
                body = (
                    b'{"fixture":"synthetic-only","token":"synthetic-response-token"}'
                )
                self.send_response(200)
            if self.path != "/fixture/discovery":
                self.send_header("Content-Type", "application/json")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Set-Cookie", "session=synthetic-cookie-value; HttpOnly")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with httpx.Client(
            base_url=runtime.origin,
            headers={"X-API-Key": runtime.environment["APP_TOKEN"]},
            trust_env=False,
            timeout=15,
        ) as client:
            response = client.get("/")
            assert response.status_code == 200 and "AutoMiner" in response.text, (
                "前端资源缺失"
            )
            response = client.post(
                "/api/targets",
                json={
                    "name": "Desktop disposable fixture",
                    "kind": "local",
                    "scheme": "http",
                    "host": "127.0.0.1",
                    "port": server.server_port,
                    "paths": ["/fixture", "/redirect"],
                    "deny_paths": [],
                    "bound_ips": [],
                    "statement": "Owned disposable synthetic desktop fixture",
                    "expires_at": time.time() + 300,
                    "request_budget": 5,
                    "ownership_declared": True,
                },
            )
            assert response.status_code == 200, response.text
            target = response.json()
            response = client.post(f"/api/targets/{target['id']}/verify", json={})
            assert response.status_code == 403, "空证明文件不能通过验证"
            challenge["value"] = target["challenge"]
            response = client.post(f"/api/targets/{target['id']}/verify", json={})
            assert response.status_code == 200, response.text
            root = f"http://127.0.0.1:{server.server_port}"
            response = client.post(
                f"/api/targets/{target['id']}/imports",
                json={
                    "format": "manual",
                    "document": {
                        "requests": [
                            {"url": root + "/fixture"},
                            {"url": root + "/redirect"},
                            {"url": "http://127.0.0.1:1/outside"},
                        ]
                    },
                },
            )
            assert response.status_code == 200, response.text
            imported = response.json()
            assert len(imported["imported"]) == 2 and len(imported["rejected"]) == 1
            job_input = {
                "target_id": target["id"],
                "endpoint_ids": [e["id"] for e in imported["imported"]],
                "request_budget": 2,
                "duration_seconds": 30,
            }
            response = client.post("/api/jobs", json=job_input)
            assert response.status_code == 200, response.text
            job_id = response.json()["id"]
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                state = client.get("/api/state").json()
                job = next(j for j in state["job"] if j["id"] == job_id)
                if job["status"] not in ("queued", "running"):
                    break
                time.sleep(0.2)
            assert job["status"] == "completed" and job["used"] == 2, json.dumps(job)
            evidence = [e for e in state["evidence"] if e.get("job_id") == job_id]
            assert len(evidence) == 2 and all(
                e["state"] == "complete" and e.get("sent_at") for e in evidence
            )
            assert any(e["redirect_blocked"] for e in evidence), "范围外跳转未被标记"
            assert counts == {"proof": 2, "test": 2}, str(counts)
            response = client.post(
                f"/api/targets/{target['id']}/discoveries",
                json={
                    "seeds": [root + "/fixture/discovery"],
                    "request_budget": 1,
                    "max_depth": 1,
                },
            )
            assert response.status_code == 200, response.text
            discovery_id = response.json()["id"]
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                discovered = client.get(
                    f"/api/targets/{target['id']}/discoveries"
                ).json()[0]
                if discovered["status"] not in ("queued", "running"):
                    break
                time.sleep(0.2)
            assert discovered["status"] == "completed", json.dumps(discovered)
            assert discovered["id"] == discovery_id and discovered["used"] == 1
            assert (
                len(discovered["requests"]) == 1 and len(discovered["candidates"]) == 3
            )
            assert "TOPSECRET" not in json.dumps(discovered)
            chosen = next(
                c
                for c in discovered["candidates"]
                if c["url"].endswith("/fixture/discovered")
            )
            assert (
                client.post(
                    f"/api/discoveries/{discovery_id}/import",
                    json={"candidate_ids": [chosen["id"]]},
                ).status_code
                == 200
            )
            assert counts == {"proof": 2, "test": 3}, str(counts)
            assert (
                client.post(f"/api/targets/{target['id']}/revoke", json={}).status_code
                == 200
            )
            assert client.post("/api/jobs", json=job_input).status_code == 403
            assert client.get(
                f"/api/targets/{target['id']}/report?format=zip"
            ).content.startswith(b"PK")
            detail = client.get(f"/api/jobs/{job_id}").json()
            assert len(detail["endpoints"]) == 2 and detail["logs"]
            assert all(e.get("checks") for e in detail["evidence"])
            exchanges = [e["http_exchange"] for e in detail["evidence"]]
            assert all(exchange["request"]["method"] == "GET" for exchange in exchanges)
            assert "synthetic-only" in exchanges[0]["response"]["body"]
            assert "synthetic-cookie-value" not in json.dumps(exchanges)
            assert "synthetic-response-token" not in json.dumps(exchanges)
            assert (
                client.get(
                    f"/api/targets/{target['id']}/report?format=md&job_id={job_id}"
                ).status_code
                == 200
            )
            settings = {
                "MODEL_CLOUD_BASE_URLS": "https://fixture.example/v1",
                "MODEL_LOCAL_BASE_URLS": "",
                "MODEL_MAX_USD_PER_MILLION_TOKENS": 3,
            }
            assert client.put("/api/model-settings", json=settings).status_code == 200
            response = client.post(
                "/api/model-configs",
                json={
                    "name": "Persistence fixture",
                    "base_url": "https://fixture.example/v1",
                    "model": "synthetic",
                    "api_key": "synthetic-persistence-key",
                    "local": False,
                },
            )
            assert response.status_code == 200, response.text
            assert (
                response.json()["has_api_key"]
                and "encrypted_key" not in response.json()
            )
            return {
                "ok": True,
                "roles": ["api", "gateway", "model", "worker"],
                "frontend": True,
                "ownership_proof": True,
                "requests": 2,
                "out_of_scope_rejected": True,
                "redirect_blocked": True,
                "revocation_enforced": True,
                "report_export": True,
                "task_details": True,
                "interface_discovery": True,
                "http_evidence": True,
            }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def check_persistence(runtime):
    """Verify saved data and protected credential after all services restart."""
    from app.security import decrypt
    from app.service import all_of
    from app.store import Session

    with httpx.Client(
        base_url=runtime.origin,
        headers={"X-API-Key": runtime.environment["APP_TOKEN"]},
        trust_env=False,
    ) as client:
        state = client.get("/api/state").json()
        assert len(state["target"]) == 1 and len(state["job"]) == 1
        assert len(state["model"]) == 1 and state["model"][0]["has_api_key"]
        assert "encrypted_key" not in state["model"][0]
        saved_detail = client.get(f"/api/jobs/{state['job'][0]['id']}").json()
        assert any(
            "synthetic-only"
            in e.get("http_exchange", {}).get("response", {}).get("body", "")
            for e in saved_detail["evidence"]
        )
        assert (
            client.get("/api/model-settings").json()["MODEL_CLOUD_BASE_URLS"]
            == "https://fixture.example/v1"
        )
    with Session() as session:
        assert (
            decrypt(all_of(session, "model")[0]["encrypted_key"])
            == "synthetic-persistence-key"
        )
