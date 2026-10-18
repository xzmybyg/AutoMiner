import pytest

from app.service import PASSIVE_CHECKS, all_of, get, locked, process_job, save
from test_app import make_job, setup_target

MODES = ["xss_passive", "csrf_passive", "ssrf_passive", "xxe_passive", "file_passive", "deserialization_passive", "auth_session_passive", "disclosure_passive", "configuration_passive", "crypto_passive", "supply_chain_passive", "business_logic_review", "other_web_passive", "race_condition_review", "memory_safety_passive", "dos_passive"]


@pytest.mark.parametrize("mode", MODES)
def test_passive_checks_reuse_one_scoped_get_and_link_pending_evidence(monkeypatch, mode):
    target, endpoint = setup_target()
    job = make_job(target, endpoint, endpoint_test_types={endpoint["id"]: mode})
    sent = []

    def response(target, url, headers, before_send):
        before_send()
        sent.append((url, headers))
        return {"status": 200, "headers": {"Content-Type": "text/html"},
                "body": "<html>synthetic response</html>", "truncated": False}

    def inspect(body, headers):
        assert body == "<html>synthetic response</html>"
        assert headers["Content-Type"] == "text/html"
        return ([{"id": mode, "name": "合成检查", "status": "hit", "detail": "待确认"}],
                [{"root": mode, "title": "合成线索，待人工确认"}])

    monkeypatch.setattr("app.service.request", response)
    monkeypatch.setitem(PASSIVE_CHECKS, mode, inspect)
    process_job(job["id"])
    assert sent == [(endpoint["url"], {})]
    with locked() as s:
        assert get(s, job["id"])["used"] == 1
        evidence = all_of(s, "evidence")
        findings = all_of(s, "finding")
        assert len(evidence) == len(findings) == 1
        assert evidence[0]["checks"][0]["id"] == mode
        assert evidence[0]["http_exchange"]["request"]["url"] == endpoint["url"]
        assert findings[0]["status"] == "pending"
        assert findings[0]["evidence_ids"] == [evidence[0]["id"]]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("change", ["revoked", "stopped", "budget"])
def test_passive_templates_cannot_bypass_execution_controls(monkeypatch, mode, change):
    target, endpoint = setup_target()
    job = make_job(target, endpoint, endpoint_test_types={endpoint["id"]: mode})
    with locked() as s:
        if change == "revoked":
            target["revoked"] = True
            save(s, target)
        else:
            job["used"] = job["request_budget"] if change == "budget" else 0
            if change == "stopped":
                job["status"] = "stopped"
            save(s, job)
    def forbidden(*args, **kwargs):
        pytest.fail("execution controls must reject before sending")
    monkeypatch.setattr("app.service.request", forbidden)
    process_job(job["id"])
    with locked() as s:
        assert not all_of(s, "evidence")
        assert not all_of(s, "finding")
