import pytest
from app import auto_scan
from app.main import emergency_stop, revoke, tick
from fastapi import HTTPException
from app.policy import Denied
from app.service import all_of, create, get, locked, save
from app.store import Session, now
from test_discovery import fixture


def setup(monkeypatch):
    monkeypatch.setenv("MODEL_GATEWAY_URL", "http://model-outlet")
    target = fixture()
    with locked() as s:
        model = create(s, "model", dict(name="DeepSeek", model="test", local=False,
            base_url="https://models.example/v1", encrypted_key="unused", max_output_tokens=800))
    row = auto_scan.start(auto_scan.AutoInput(target_id=target["id"], model_id=model["id"],
        request_budget=6, discovery_budget=2))
    return target, row


def ready(monkeypatch):
    target, row = setup(monkeypatch)
    with locked() as s:
        discovery = get(s, row["discovery_id"])
        discovery.update(status="completed", used=2)
        save(s, discovery)
        endpoint = create(s, "endpoint", dict(target_id=target["id"], method="GET",
            url="https://app.example/api/read", executable=True))
    return target, row, endpoint


class Reply:
    def __init__(self, proposals):
        self.proposals = proposals

    def raise_for_status(self):
        pass

    def json(self):
        return {"proposals": self.proposals}


def plan(endpoint_id, **extra):
    return dict(endpoint_id=endpoint_id, test_type="baseline", risk="low",
        expected_evidence="Response headers", request_budget=1, **extra)


def test_background_tick_full_flow_and_report(monkeypatch):
    import app.main as main
    target, row = setup(monkeypatch)
    monkeypatch.setattr(main, "ROLE", "gateway")
    sent, contexts = [], []

    def transport(target, url, *args, before_send):
        before_send()
        sent.append(url)
        return dict(status=200, headers={"Content-Type": "text/html"},
            body='<a href="/api/read">read</a>', truncated=False,
            request_headers={"Host": "app.example"})

    def model(url, **kwargs):
        contexts.append(kwargs["json"]["context"])
        return Reply([plan(e["endpoint_id"]) for e in contexts[-1]["endpoints"]])

    monkeypatch.setattr("app.discovery.request", transport)
    monkeypatch.setattr("app.service.request", transport)
    monkeypatch.setattr(auto_scan.httpx, "post", model)
    tick()  # discovery, then one paid planning call
    tick()  # normal worker executes job, then snapshots report
    with Session() as s:
        current = get(s, row["id"])
        job = get(s, current["job_id"])
        snapshot = get(s, current["report_id"], "report")
        assert current["status"] == "completed"
        assert current["used"] == 3 <= current["request_budget"]
        assert job["request_budget"] == 1
        assert job["auto_deadline"] == row["deadline"]
        assert snapshot["job_id"] == job["id"]
        assert "任务执行摘要" in snapshot["content"]
    assert len(sent) == 3
    assert len(contexts) == 1
    assert all(set(e) == {"endpoint_id", "method"} for e in contexts[0]["endpoints"])
    assert "app.example" not in str(contexts)


@pytest.mark.parametrize("interrupt", ["stop", "pause", "emergency", "revoke", "deadline", "version"])
def test_model_return_cannot_schedule_after_interruption(monkeypatch, interrupt):
    target, row, endpoint = ready(monkeypatch)

    def model(*args, **kwargs):
        # This function performs a DB mutation, proving model calls hold no lock.
        if interrupt in ("stop", "pause"):
            auto_scan.control(row["id"], interrupt)
        elif interrupt == "emergency":
            emergency_stop()
        elif interrupt == "revoke":
            revoke(target["id"])
        else:
            with locked() as s:
                current = get(s, row["id"] if interrupt == "deadline" else target["id"])
                current["deadline" if interrupt == "deadline" else "version"] = 0 if interrupt == "deadline" else 2
                save(s, current)
        return Reply([plan(endpoint["id"])])

    monkeypatch.setattr(auto_scan.httpx, "post", model)
    auto_scan.advance()
    with Session() as s:
        assert not all_of(s, "job")
        assert get(s, row["id"])["status"] not in auto_scan.LIVE


@pytest.mark.parametrize("kind", ["outside", "write", "role", "over_budget"])
def test_rejects_model_plan_outside_whitelist(monkeypatch, kind):
    _, row, endpoint = ready(monkeypatch)
    proposal = plan(endpoint["id"])
    if kind == "outside":
        proposal["endpoint_id"] = "other-target"
    elif kind == "write":
        proposal["test_type"] = "arbitrary_command"
    elif kind == "role":
        proposal["test_type"] = "role_compare"
    else:
        proposal["request_budget"] = 4
    monkeypatch.setattr(auto_scan.httpx, "post", lambda *a, **k: Reply([proposal]))
    auto_scan.advance()
    with Session() as s:
        assert not all_of(s, "job")
        assert get(s, row["id"])["status"] == "blocked"


def test_recovery_never_retries_billable_planning(monkeypatch):
    _, row, _ = ready(monkeypatch)
    with locked() as s:
        current = get(s, row["id"])
        current.update(status="running", phase="planning")
        save(s, current)
    monkeypatch.setattr(auto_scan.httpx, "post", lambda *a, **k: pytest.fail("Paid call retried"))
    auto_scan.recover()
    auto_scan.advance()
    with Session() as s:
        assert get(s, row["id"])["status"] == "blocked"


def test_combined_budget_skips_model(monkeypatch):
    _, row, endpoint = ready(monkeypatch)
    with locked() as s:
        current = get(s, row["id"])
        current["request_budget"] = 2
        save(s, current)
    monkeypatch.setattr(auto_scan.httpx, "post", lambda *a, **k: pytest.fail("Budget exhausted"))
    auto_scan.advance()
    with Session() as s:
        assert get(s, row["id"])["status"] == "blocked"
        assert not all_of(s, "job")


@pytest.mark.parametrize("change", [{"executable": False}, {"method": "POST"},
    {"url": "https://app.example/api/read?secret=value"}])
def test_no_eligible_endpoint_skips_model(monkeypatch, change):
    _, row, endpoint = ready(monkeypatch)
    with locked() as s:
        current = get(s, endpoint["id"])
        current.update(change)
        save(s, current)
    monkeypatch.setattr(auto_scan.httpx, "post", lambda *a, **k: pytest.fail("No eligible endpoints"))
    auto_scan.advance()
    with Session() as s:
        assert get(s, row["id"])["status"] == "blocked"
        assert not all_of(s, "job")


def test_start_requires_valid_authorization_and_split_budget(monkeypatch):
    target, row = setup(monkeypatch)
    with pytest.raises(HTTPException):
        auto_scan.start(auto_scan.AutoInput(target_id=target["id"], model_id=row["model_id"],
            request_budget=2, discovery_budget=2))
    revoke(target["id"])
    with pytest.raises(Denied):
        auto_scan.start(auto_scan.AutoInput(target_id=target["id"], model_id=row["model_id"]))
