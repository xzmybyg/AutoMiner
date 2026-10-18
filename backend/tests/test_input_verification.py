import html
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from app.input_verification import MODES, evaluate, run
from app.main import app
from app.policy import Denied
from app.service import all_of, create, execute, get, locked, process_job, save
from app.store import Session
from test_reporting_and_checks import seed_job


def setup(mode):
    target, endpoint, job = seed_job()
    with locked() as s:
        job.update(endpoint_test_types={endpoint["id"]: mode}, input_probe_rules={endpoint["id"]: {"parameter": "q", "read_only_confirmed": True, "synthetic_data_only": True}})
        save(s, job)
    return target, endpoint, job


def responder(monkeypatch, mode, behavior="vulnerable", after=None):
    calls = []
    def request(target, url, headers, before_send, **kwargs):
        before_send()
        calls.append(url)
        value = parse_qs(urlsplit(url).query)["q"][0]
        is_probe = len(calls) == 2
        body = "normal"
        response_headers = {"Content-Type": "text/html"}
        status = 200
        if mode == "sql_error_verify" and (behavior == "baseline_error" or is_probe and behavior == "vulnerable"):
            body = "SQLSTATE[42000]: synthetic syntax failure"
            status = 500 if is_probe else 200
        if mode == "xss_reflection_verify":
            body = value if behavior == "vulnerable" else html.escape(value)
        if mode == "redirect_verify" and is_probe and behavior == "vulnerable":
            assert kwargs["expected_redirect"] == value
            response_headers["Location"] = value
            status = 302
        if behavior == "blocked" and is_probe:
            status = 403
        if behavior == "encoded":
            response_headers["Content-Encoding"] = "gzip"
        if after:
            after(len(calls))
        return {"status": status, "headers": response_headers, "body": body,
                "redirect_probe_match": mode == "redirect_verify" and is_probe and behavior == "vulnerable",
                "redirect_blocked": mode == "redirect_verify" and is_probe and behavior == "vulnerable",
                "truncated": behavior == "truncated", "request_headers": {}}
    monkeypatch.setattr("app.service.request", request)
    return calls


@pytest.mark.parametrize("mode", MODES)
def test_fixed_comparison_evidence_and_no_replay(monkeypatch, mode):
    _, endpoint, job = setup(mode)
    calls = responder(monkeypatch, mode)
    process_job(job["id"])
    assert len(calls) == 3
    assert all(urlsplit(u).hostname == urlsplit(endpoint["url"]).hostname and urlsplit(u).path == urlsplit(endpoint["url"]).path for u in calls)
    assert parse_qs(urlsplit(calls[0]).query) == parse_qs(urlsplit(calls[2]).query)
    with Session() as s:
        verification = all_of(s, "verification")[0]
        assert verification["status"] == "behavior_confirmed"
        assert len(verification["evidence_ids"]) == 3
        assert all_of(s, "finding")[0]["status"] == "pending"
        evidence = all_of(s, "evidence")
        assert all(e["input_observation"] for e in evidence)
        assert all(e["http_exchange"]["request"]["url"] for e in evidence)
        assert get(s, job["id"])["used"] == 3
    with locked() as s:
        current = get(s, job["id"])
        current["status"] = "running"
        save(s, current)
    run(job["id"], endpoint["id"], mode)
    assert len(calls) == 3


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("behavior", ["safe", "blocked", "truncated", "encoded"])
def test_controls_never_confirm(monkeypatch, mode, behavior):
    _, _, job = setup(mode)
    responder(monkeypatch, mode, behavior)
    process_job(job["id"])
    with Session() as s:
        assert all_of(s, "verification")[0]["status"] != "behavior_confirmed"
        assert not all_of(s, "finding")


def test_database_error_in_control_is_inconclusive(monkeypatch):
    _, _, job = setup("sql_error_verify")
    responder(monkeypatch, "sql_error_verify", "baseline_error")
    process_job(job["id"])
    with Session() as s:
        assert all_of(s, "verification")[0]["status"] == "inconclusive"


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("change", ["stop", "revoke", "version", "budget", "deadline"])
def test_live_lifecycle_blocks_later_probes(monkeypatch, mode, change):
    target, _, job = setup(mode)
    def after(number):
        if number != 1:
            return
        with locked() as s:
            current = get(s, job["id"])
            t = get(s, target["id"])
            if change == "stop": current["status"] = "stopped"
            if change == "revoke": t["revoked"] = True
            if change == "version": t["version"] += 1
            if change == "budget": current["request_budget"] = current["used"]
            if change == "deadline": current["deadline"] = 0
            save(s, current); save(s, t)
    calls = responder(monkeypatch, mode, after=after)
    process_job(job["id"])
    assert len(calls) == 1
    with Session() as s:
        assert all_of(s, "verification")[0]["status"] == "inconclusive"


@pytest.mark.parametrize("mutation", ["missing_rule", "extra_rule", "low_budget", "credential_parameter", "existing_query", "account", "no_confirmation"])
def test_job_boundary_rejects_invalid_inputs(mutation):
    target, endpoint, _ = setup("sql_error_verify")
    body = {"target_id": target["id"], "endpoint_ids": [endpoint["id"]], "endpoint_test_types": {endpoint["id"]: "sql_error_verify"},
            "input_probe_rules": {endpoint["id"]: {"parameter": "q", "read_only_confirmed": True, "synthetic_data_only": True}}, "request_budget": 3}
    if mutation == "missing_rule": body["input_probe_rules"] = {}
    if mutation == "extra_rule": body["input_probe_rules"]["foreign"] = body["input_probe_rules"][endpoint["id"]]
    if mutation == "low_budget": body["request_budget"] = 2
    if mutation == "credential_parameter": body["input_probe_rules"][endpoint["id"]]["parameter"] = "access_token"
    if mutation == "no_confirmation": body["input_probe_rules"][endpoint["id"]]["read_only_confirmed"] = False
    with locked() as s:
        if mutation == "existing_query":
            ep = get(s, endpoint["id"]); ep["url"] += "?q=old"; save(s, ep)
        if mutation == "account":
            account = create(s, "account", {"target_id": target["id"]})
            body["account_ids"] = [account["id"]]
    response = TestClient(app).post("/api/jobs", headers={"X-API-Key": "test-token"}, json=body)
    assert response.status_code in (403, 422), response.text


def test_baseline_cannot_forge_input_probe(monkeypatch):
    _, endpoint, job = seed_job()
    monkeypatch.setattr("app.service.request", lambda *a, **kw: pytest.fail("No traffic"))
    with pytest.raises(Denied):
        execute(job["id"], endpoint["id"], input_probe="input_probe")


@pytest.mark.parametrize("mode", MODES)
def test_api_accepts_explicit_rule_and_reserves_exact_cost(mode):
    target, endpoint, _ = setup(mode)
    body = {"target_id": target["id"], "endpoint_ids": [endpoint["id"]], "endpoint_test_types": {endpoint["id"]: mode},
            "input_probe_rules": {endpoint["id"]: {"parameter": "q", "read_only_confirmed": True, "synthetic_data_only": True}}, "request_budget": 3}
    response = TestClient(app).post("/api/jobs", headers={"X-API-Key": "test-token"}, json=body)
    assert response.status_code == 200, response.text
    assert response.json()["input_probe_rules"] == body["input_probe_rules"]
    assert response.json()["used"] == 0


def test_transport_rejects_arbitrary_redirect_marker_before_network(monkeypatch):
    from app.policy import request
    target, endpoint, _ = seed_job()
    monkeypatch.setattr("app.policy.resolve", lambda *a: pytest.fail("No DNS permitted"))
    with pytest.raises(Denied):
        request(target, endpoint["url"], expected_redirect="http://169.254.169.254/")


@pytest.mark.parametrize("wrapper", ['<script>const value="{}";</script>', '<textarea>{}</textarea>', '<template>{}</template>', '<!-- {} -->', '<input value=\'{}\'>'])
def test_inert_xss_contexts_do_not_confirm(wrapper):
    from app.input_verification import observe
    nonce = "a" * 32
    marker = f'<autominer-probe data-marker="{nonce}">autominer_{nonce}</autominer-probe>'
    result = observe("xss_reflection_verify", nonce, {"headers": {"Content-Type": "text/html"}, "body": wrapper.format(marker)})
    assert not result["html_marker"]


@pytest.mark.parametrize("mode", MODES)
def test_real_loopback_transport_known_fixture(monkeypatch, mode):
    hits = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            hits.append(self.path)
            value = parse_qs(urlsplit(self.path).query)["q"][0]
            status = 200
            body = value
            location = None
            if mode == "sql_error_verify" and "'" in value:
                body = "SQLSTATE[42000]: synthetic parser failure"; status = 500
            if mode == "redirect_verify" and value.startswith("https://autominer-"):
                location = value; status = 302
            self.send_response(status)
            self.send_header("Content-Type", "text/html")
            if location: self.send_header("Location", location)
            self.end_headers(); self.wfile.write(body.encode())
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        monkeypatch.setenv("DESKTOP_LOCAL_TARGETS", "1")
        target, endpoint, job = setup(mode)
        with locked() as s:
            target.update(kind="local", host="127.0.0.1", port=server.server_port, scheme="http", bound_ips=["127.0.0.1"])
            endpoint["url"] = f"http://127.0.0.1:{server.server_port}/probe"
            save(s, target); save(s, endpoint)
        process_job(job["id"])
        assert len(hits) == 3  # No redirect follow-up or extra requests.
        with Session() as s:
            assert all_of(s, "verification")[0]["status"] == "behavior_confirmed"
            if mode == "redirect_verify":
                probe = next(e for e in all_of(s, "evidence") if e["probe_label"] == "input_probe")
                assert probe["redirect_blocked"] and probe["input_observation"]["redirect_marker"]
                assert ".invalid/" in json.dumps(probe["http_exchange"])
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)
