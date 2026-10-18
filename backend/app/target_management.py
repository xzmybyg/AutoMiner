"""Persisted target management; deletion preserves the research audit trail."""

import secrets

from fastapi import APIRouter, Depends, Header, HTTPException

from .schemas import TargetInput
from .service import all_of, audit, create, get, locked, public_target, save
from .store import Session, now


def authenticated(x_api_key: str = Header(default="")):
    from .main import auth

    return auth(x_api_key)


router = APIRouter(prefix="/api/targets", dependencies=[Depends(authenticated)])


def stop_target_jobs(session, target_id):
    for job in all_of(session, "job") + all_of(session, "discovery") + all_of(session, "auto_scan"):
        if job["target_id"] == target_id and job["status"] in (
            "queued",
            "running",
            "paused",
        ):
            job.update(status="stopped", error="目标授权已修改或目标已删除")
            save(session, job)


def update_target(target_id: str, body: TargetInput):
    with locked() as session:
        target = get(session, target_id, "target")
        if target.get("deleted"):
            raise HTTPException(409, "已删除目标不能编辑或恢复，请重新登记")
        incoming = body.model_dump()
        authorization_changed = any(
            target.get(key) != value for key, value in incoming.items() if key != "name"
        )
        if authorization_changed:
            if body.expires_at <= now():
                raise HTTPException(400, "授权有效期必须在未来")
            if body.request_budget < target.get("used", 0):
                raise HTTPException(400, "总请求预算不能低于已使用次数")
            create(session, "authorization", dict(target, target_id=target_id))
            target.update(
                incoming,
                version=target["version"] + 1,
                verified=False,
                revoked=False,
                challenge=secrets.token_urlsafe(24),
            )
            stop_target_jobs(session, target_id)
            audit(session, "authorization_changed", target_id)
        else:
            target["name"] = body.name
            audit(session, "target_renamed", target_id)
        save(session, target)
        return target


@router.get("/{target_id}")
def target_details(target_id: str):
    with Session() as session:
        return public_target(get(session, target_id, "target"))


@router.delete("/{target_id}")
def delete_target(target_id: str):
    with locked() as session:
        target = get(session, target_id, "target")
        if not target.get("deleted"):
            create(session, "authorization", dict(target, target_id=target_id))
            target.update(
                deleted=True,
                deleted_at=now(),
                revoked=True,
                verified=False,
                version=target["version"] + 1,
            )
            save(session, target)
            stop_target_jobs(session, target_id)
            audit(session, "target_deleted", target_id, "保留任务、证据与报告历史")
        return {"ok": True}
