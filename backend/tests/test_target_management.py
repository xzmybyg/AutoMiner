import hashlib

import pytest
from app.main import add_target
from app.policy import Denied
from app.schemas import TargetInput
from app.service import active, create, get, locked, save
from app.store import Session, now
from app.target_management import delete_target, target_details, update_target
from fastapi import HTTPException


def target():
    return add_target(
        TargetInput(
            name="本机项目",
            kind="local",
            scheme="http",
            host="localhost",
            port=5177,
            statement="本人开发并授权测试的本机应用",
            expires_at=now() + 86400,
            ownership_declared=True,
        )
    )


def payload(row, **changes):
    data = {key: row[key] for key in TargetInput.model_fields}
    data.update(changes)
    return TargetInput(**data)


def test_target_persists_and_name_edit_preserves_authorization():
    original = target()
    with locked() as session:
        row = get(session, original["id"])
        row.update(verified=True, used=9)
        save(session, row)
    updated = update_target(original["id"], payload(original, name="新名称"))
    assert updated["verified"] and updated["version"] == 1
    assert updated["challenge"] == original["challenge"] and updated["used"] == 9
    with Session() as session:
        assert get(session, original["id"])["name"] == "新名称"
    assert target_details(original["id"])["used"] == 9
    assert target_details(original["id"])["hash"] == original["hash"]


def test_target_hash_distinguishes_same_address_and_backfills_old_records():
    first, second = target(), target()
    assert len(first["hash"]) == 64
    assert first["hash"] != second["hash"]
    assert first["hash"] == hashlib.sha256(first["id"].encode()).hexdigest()
    # Legacy records have no persisted hash; responses still derive the same identity.
    with Session() as session:
        assert "hash" not in get(session, first["id"])
    from app.main import state

    listed = next(t for t in state()["target"] if t["id"] == first["id"])
    assert listed["hash"] == target_details(first["id"])["hash"] == first["hash"]


def test_scope_edit_invalidates_and_stops_tasks_without_resetting_budget():
    original = target()
    with locked() as session:
        row = get(session, original["id"])
        row.update(verified=True, used=10)
        save(session, row)
        jobs = [
            create(session, "job", {"target_id": row["id"], "status": status})
            for status in ("queued", "running", "paused", "completed")
        ]
    updated = update_target(original["id"], payload(original, port=5178))
    assert updated["version"] == 2 and not updated["verified"]
    assert updated["challenge"] != original["challenge"] and updated["used"] == 10
    with Session() as session:
        assert [get(session, j["id"])["status"] for j in jobs] == [
            "stopped",
            "stopped",
            "stopped",
            "completed",
        ]
    with pytest.raises(HTTPException):
        update_target(original["id"], payload(updated, request_budget=5))


def test_soft_delete_preserves_history_and_cannot_be_reenabled():
    original = target()
    with locked() as session:
        job = create(session, "job", {"target_id": original["id"], "status": "running"})
        evidence = create(
            session,
            "evidence",
            {"target_id": original["id"], "job_id": job["id"], "state": "complete"},
        )
        report = create(
            session, "report", {"target_id": original["id"], "format": "md"}
        )
    assert delete_target(original["id"])["ok"]
    deleted = target_details(original["id"])
    assert deleted["deleted"] and deleted["revoked"] and not deleted["verified"]
    with pytest.raises(Denied):
        active(deleted)
    with pytest.raises(HTTPException) as exc:
        update_target(original["id"], payload(original))
    assert exc.value.status_code == 409
    assert delete_target(original["id"])["ok"]
    assert target_details(original["id"])["version"] == deleted["version"]
    with Session() as session:
        assert get(session, job["id"])["status"] == "stopped"
        assert get(session, evidence["id"])["state"] == "complete"
        assert get(session, report["id"])["format"] == "md"
