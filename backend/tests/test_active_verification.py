import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from app.active_verification import evaluate, run_verification
from app.main import app
from app.policy import Denied
from app.security import encrypt
from app.service import all_of, create, execute, get, locked, process_job, save
from app.store import Session
from test_reporting_and_checks import seed_job


def setup(mode):
    target, endpoint, job = seed_job()
    with locked() as s:
        job["endpoint_test_types"] = {endpoint["id"]: mode}
        if mode == "access_verify":
            account = create(s, "account", {"target_id": target["id"], "role": "owner", "encrypted_headers": encrypt({"X-Test-Account": "owner"})})
            job["account_ids"] = [account["id"]]
            job["verification_rules"] = {endpoint["id"]: {"allowed_account_id": account["id"], "denied_account_id": None, "json_field": "canary", "expected_value_sha256": hashlib.sha256(b"synthetic-marker").hexdigest()}}
        save(s, job)
    return target, endpoint, job


def responder(monkeypatch, *, marker="synthetic-marker", truncate=False, stop_after=None):
    calls = []
    def request(target, url, headers, before_send, **kw):
        before_send()
        calls.append((url, dict(headers), kw))
        label = kw.get("probe_label")
        response_headers = {"Content-Type": "application/json"}
        request_headers = dict(headers)
        if label in ("probe_a", "probe_b"):
            origin = "https://autominer-" + ("a" if label == "probe_a" else "b") + ".invalid"
            response_headers.update({"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"})
            request_headers["Origin"] = origin
        if stop_after == len(calls):
            with locked() as s:
                job = all_of(s, "job")[0]
                job["status"] = "stopped"
                save(s, job)
        return {"status": 200, "headers": response_headers, "body": json.dumps({"canary": marker}), "truncated": truncate, "request_headers": request_headers}
    monkeypatch.setattr("app.service.request", request)
    return calls


def test_cors_fixed_requests_evidence_pending_and_no_replay(monkeypatch):
    _, endpoint, job = setup("cors_verify")
    calls = responder(monkeypatch)
    process_job(job["id"])
    with locked() as s:
        current = get(s, job["id"])
        current["status"] = "running"
        save(s, current)
    run_verification(job["id"], endpoint["id"], "cors_verify")
    assert len(calls) == 3
    assert all(c[0] == endpoint["url"] and not c[1] for c in calls)
    assert [c[2]["probe_label"] for c in calls] == ["baseline", "probe_a", "probe_b"]
    with Session() as s:
        verification = all_of(s, "verification")[0]
        assert verification["status"] == "behavior_confirmed"
        assert len(verification["evidence_ids"]) == 3
        assert all_of(s, "finding")[0]["status"] == "pending"
        assert get(s, job["id"])["used"] == 3


def test_access_requires_marker_control_and_redacts_marker(monkeypatch):
    _, _, job = setup("access_verify")
    calls = responder(monkeypatch)
    process_job(job["id"])
    assert len(calls) == 2 and calls[0][1] and calls[1][1] == {}
    with Session() as s:
        assert all_of(s, "verification")[0]["status"] == "behavior_confirmed"
        assert "synthetic-marker" not in json.dumps(all_of(s, "evidence"))
        assert all_of(s, "finding")[0]["status"] == "pending"


@pytest.mark.parametrize("mode", ["cors_verify", "access_verify"])
def test_truncated_responses_never_confirm(monkeypatch, mode):
    _, _, job = setup(mode)
    responder(monkeypatch, truncate=True)
    process_job(job["id"])
    with Session() as s:
        assert all_of(s, "verification")[0]["status"] == "inconclusive"
        assert not all_of(s, "finding")


def test_equal_bodies_without_declared_marker_do_not_confirm(monkeypatch):
    _, _, job = setup("access_verify")
    responder(monkeypatch, marker="public")
    process_job(job["id"])
    with Session() as s:
        assert all_of(s, "verification")[0]["status"] == "inconclusive"
        assert not all_of(s, "finding")


def test_stop_between_probes_blocks_later_requests_and_replay(monkeypatch):
    _, endpoint, job = setup("cors_verify")
    calls = responder(monkeypatch, stop_after=1)
    process_job(job["id"])
    assert len(calls) == 1
    with Session() as s:
        assert all_of(s, "verification")[0]["status"] == "inconclusive"
        assert get(s, job["id"])["status"] == "stopped"
    with pytest.raises(Denied):
        run_verification(job["id"], endpoint["id"], "cors_verify")


def test_non_cors_mode_cannot_request_probe(monkeypatch):
    _, endpoint, job = setup("baseline")
    calls = responder(monkeypatch)
    with pytest.raises(Denied):
        execute(job["id"], endpoint["id"], probe_label="probe_a")
    assert not calls


@pytest.mark.parametrize("mutation", ["revoked", "version", "budget", "deadline"])
def test_live_changes_block_remaining_probes(monkeypatch, mutation):
    target, endpoint, job = setup("cors_verify")
    calls = []
    def request(t, url, headers, before_send, **kw):
        before_send()
        calls.append(url)
        with locked() as s:
            current_target = get(s, target["id"])
            current_job = get(s, job["id"])
            if mutation == "revoked": current_target["revoked"] = True
            if mutation == "version": current_target["version"] += 1
            if mutation == "budget": current_job["request_budget"] = current_job["used"]
            if mutation == "deadline": current_job["deadline"] = 0
            save(s, current_target)
            save(s, current_job)
        return {"status": 200, "headers": {}, "body": "ok", "truncated": False}
    monkeypatch.setattr("app.service.request", request)
    process_job(job["id"])
    assert len(calls) == 1
    with Session() as s:
        assert all_of(s, "verification")[0]["status"] == "inconclusive"
        assert get(s, job["id"])["status"] == "blocked"


def test_access_denied_control_and_indeterminate_responses():
    allowed = {"state": "complete", "status": 200, "probe_label": "allowed", "verification_marker_match": True}
    denied = dict(allowed, probe_label="denied", status=403, verification_marker_match=None)
    assert evaluate("access_verify", [allowed, denied])[0] == "not_reproduced"
    denied.update(status=200, verification_marker_match=False)
    assert evaluate("access_verify", [allowed, denied])[0] == "not_reproduced"
    denied["verification_marker_match"] = None
    assert evaluate("access_verify", [allowed, denied])[0] == "inconclusive"
    denied.update(status=302, verification_marker_match=True)
    assert evaluate("access_verify", [allowed, denied])[0] == "inconclusive"


def test_dispatch_recheck_blocks_after_dns_change(monkeypatch):
    target, endpoint, job = setup("cors_verify")
    sent = []
    def request(t, url, headers, before_send, **kw):
        with locked() as s:
            current = get(s, target["id"])
            current["revoked"] = True
            save(s, current)
        before_send()
        sent.append(url)
    monkeypatch.setattr("app.service.request", request)
    process_job(job["id"])
    assert not sent
    with Session() as s:
        assert all_of(s, "verification")[0]["status"] == "inconclusive"


@pytest.mark.parametrize("change", ["budget", "duplicate", "outside", "wrong_rule", "nonexecutable"])
def test_job_rejects_invalid_active_config(change):
    _, endpoint, job = setup("access_verify")
    body = {k: job[k] for k in ("target_id", "endpoint_ids", "account_ids", "request_budget", "endpoint_test_types", "verification_rules")}
    if change == "budget": body["request_budget"] = 1
    if change == "duplicate": body["account_ids"] *= 2
    if change == "outside": body["verification_rules"][endpoint["id"]]["allowed_account_id"] = "not-bound"
    if change == "wrong_rule": body["endpoint_test_types"] = {endpoint["id"]: "cors_verify"}
    if change == "nonexecutable":
        with locked() as s:
            endpoint["executable"] = False
            save(s, endpoint)
    response = TestClient(app).post("/api/jobs", headers={"X-API-Key": "test-token"}, json=body)
    assert response.status_code == 403


def test_policy_origin_is_only_fixed_and_target_stays_pinned(monkeypatch):
    from app.policy import request
    from test_policy import target
    calls = []
    class Response:
        status = 200
        def read1(self, n): return b""
        def getheaders(self): return []
        def getheader(self, k): return None
    class Connection:
        sock = None
        def __init__(self, *args, **kw): calls.append(args)
        def request(self, method, path, headers): calls.append(headers)
        def getresponse(self): return Response()
        def close(self): pass
    monkeypatch.setattr("app.policy.resolve", lambda t: ["93.184.216.34"])
    monkeypatch.setattr("app.policy.PinnedHTTPS", Connection)
    request(target(), "https://app.example.com/api", probe_label="probe_a")
    assert calls[0][-1] == "93.184.216.34" and calls[1]["Origin"] == "https://autominer-a.invalid"
    with pytest.raises(Denied): request(target(), "https://app.example.com/api", probe_label="https://evil.example")
    with pytest.raises(Denied): request(target(), "https://app.example.com/api", {"Origin": "https://evil.example"})
    with pytest.raises(Denied): request(target(), "https://outside.example/api", probe_label="probe_a")
