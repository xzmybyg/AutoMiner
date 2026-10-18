from app.job_management import job_detail
from app.service import all_of, create, locked, process_job, report
from app.store import Session
from test_active_verification import responder, setup


def test_replay_and_report_expose_behavior_without_promoting_finding(monkeypatch):
    target, endpoint, job = setup("cors_verify")
    responder(monkeypatch)
    process_job(job["id"])
    detail = job_detail(job["id"])
    assert detail["coverage"]["sent_requests"] == 3
    assert detail["coverage"]["completed_requests"] == 3
    assert detail["coverage"]["verification_count"] == 1
    assert detail["coverage"]["requested_endpoints"] == 1
    assert [r["probe_label"] for r in detail["endpoints"][0]["requests"]] == ["baseline", "probe_a", "probe_b"]
    assert detail["verifications"][0]["status"] == "behavior_confirmed"
    with Session() as s:
        assert all(f["status"] == "pending" for f in all_of(s, "finding"))
        content = report(s, target["id"], "md", job_id=job["id"])[0].decode()
        assert "主动验证与回放记录" in content
        assert "影响待人工确认" in content
        for evidence in detail["evidence"]:
            assert evidence["id"] in content


def test_verifications_are_task_scoped_and_reservation_is_not_counted_as_sent():
    _, endpoint, job = setup("cors_verify")
    with locked() as s:
        create(s, "evidence", {"job_id": job["id"], "endpoint_id": endpoint["id"], "state": "reserved", "at": 1})
        create(s, "verification", {"job_id": "another-job", "plugin_id": "cors_verify", "status": "behavior_confirmed"})
    detail = job_detail(job["id"])
    assert detail["verifications"] == []
    assert detail["coverage"]["requested_endpoints"] == 0
    assert detail["coverage"]["endpoints_with_evidence"] == 1
    assert detail["coverage"]["sent_requests"] == 0
