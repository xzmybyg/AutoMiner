from app.job_management import job_detail, list_jobs
from app.service import all_of, audit, create, locked


def seed():
    with locked() as s:
        target = create(s, "target", {"name": "本地测试", "encrypted_key": "NEVER"})
        first = create(
            s,
            "endpoint",
            {
                "target_id": target["id"],
                "method": "GET",
                "url": "http://localhost:5177/",
            },
        )
        second = create(
            s,
            "endpoint",
            {
                "target_id": target["id"],
                "method": "GET",
                "url": "http://localhost:5177/api/test",
            },
        )
        job = create(
            s,
            "job",
            {
                "target_id": target["id"],
                "endpoint_ids": [first["id"], second["id"]],
                "status": "completed",
                "used": 1,
                "request_budget": 20,
            },
        )
        old = create(
            s,
            "job",
            {
                "target_id": target["id"],
                "endpoint_ids": [],
                "status": "completed",
                "created_at": 1,
            },
        )
        ev = create(
            s,
            "evidence",
            {
                "job_id": job["id"],
                "endpoint_id": first["id"],
                "url": first["url"],
                "method": "GET",
                "role": "anonymous",
                "state": "complete",
                "status": 200,
                "at": 5,
                "headers": {"Cookie": "NEVER"},
                "body": "NEVER",
                "signals": [],
            },
        )
        other = create(
            s,
            "evidence",
            {"job_id": old["id"], "endpoint_id": first["id"], "state": "complete"},
        )
        for subject, action, at in [
            (job["id"], "job_created", 2),
            (ev["id"], "request_finished", 6),
            (target["id"], "unrelated_target_log", 7),
            (other["id"], "other_job_log", 8),
        ]:
            create(
                s,
                "audit",
                {"subject": subject, "action": action, "at": at, "detail": ""},
            )
        linked = create(
            s,
            "finding",
            {
                "job_id": old["id"],
                "target_id": target["id"],
                "title": "去重后的发现",
                "evidence_ids": [other["id"], ev["id"]],
            },
        )
        create(
            s,
            "finding",
            {
                "job_id": old["id"],
                "target_id": target["id"],
                "evidence_ids": [other["id"]],
            },
        )
    return job, ev, linked


def test_detail_distinguishes_planned_and_executed_and_filters_logs():
    job, ev, linked = seed()
    result = job_detail(job["id"])
    assert [e["state"] for e in result["endpoints"]] == ["recorded", "not_requested"]
    assert result["endpoints"][1]["requests"] == []
    assert [a["action"] for a in result["logs"]] == ["job_created", "request_finished"]
    assert result["findings"][0]["id"] == linked["id"]
    assert result["findings"][0]["evidence_ids"] == [ev["id"]]
    assert len(result["findings"]) == 1
    assert "NEVER" not in str(result)


def test_audit_records_task_links_and_keeps_other_tasks_out():
    job, ev, _ = seed()
    with locked() as s:
        audit(s, "job_pause", job["id"])
        audit(s, "request_finished", ev["id"], "complete")
        audit(s, "unrelated", "missing-subject")
        linked = [a for a in all_of(s, "audit") if a.get("job_id") == job["id"]]
        assert len(linked) == 2
    logs = job_detail(job["id"])["logs"]
    assert all(a["job_id"] == job["id"] for a in logs)
    assert "unrelated" not in [a["action"] for a in logs]


def test_historical_evidence_does_not_invent_passed_checks():
    job, _, _ = seed()
    result = job_detail(job["id"])
    assert "checks" not in result["evidence"][0]
    assert result["job_checks"] == []
    assert "不推断" in result["coverage_note"]
    assert result["job"]["created_at"] == 2
    assert list_jobs()[0]["id"] == job["id"]


def test_new_recorded_checks_are_returned_for_the_task_only():
    job, ev, _ = seed()
    with locked() as s:
        create(
            s,
            "check",
            {
                "job_id": job["id"],
                "endpoint_id": ev["endpoint_id"],
                "status": "not_applicable",
                "name": "身份对比",
            },
        )
        create(s, "check", {"job_id": "other", "status": "hit", "name": "无关"})
    result = job_detail(job["id"])
    assert [c["status"] for c in result["job_checks"]] == ["not_applicable"]


def test_job_history_routes_require_authentication():
    from app.main import app
    from fastapi.testclient import TestClient

    job, _, _ = seed()
    with TestClient(app) as client:
        assert client.get("/api/jobs").status_code == 401
        assert client.get(f"/api/jobs/{job['id']}").status_code == 401
        response = client.get(
            f"/api/jobs/{job['id']}", headers={"X-API-Key": "test-token"}
        )
        assert response.status_code == 200
        assert response.json()["job"]["id"] == job["id"]
