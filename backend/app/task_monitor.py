"""Independent, read-only task observer; never receives execution tools."""
import hashlib
import json
import os
import threading
from uuid import uuid4

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .job_management import authenticate
from .scan_runs import scope
from .security import redact
from .service import all_of, audit, create, get, locked, save
from .store import Session, now

router = APIRouter(dependencies=[Depends(authenticate)])
TERMINAL = {"completed", "blocked", "stopped", "failed", "interrupted"}


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool
    model_id: str | None = None
    max_cost_usd: float = Field(default=0.10, ge=0.001, le=1)


class Interpretation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    summary: str = Field(min_length=1, max_length=800)


def find(s, job_id):
    return next((r for r in all_of(s, "task_monitor") if r["job_id"] == job_id), None)


@router.get("/api/jobs/{job_id}/monitor")
def read(job_id: str):
    with Session() as s:
        scope(s, job_id)
        return find(s, job_id) or {"enabled": False, "entries": [], "calls": 0, "reserved_usd": 0}


@router.put("/api/jobs/{job_id}/monitor")
def configure(job_id: str, body: Settings):
    with locked() as s:
        scope(s, job_id)
        row = find(s, job_id)
        if body.enabled:
            if not body.model_id:
                raise HTTPException(400, "请先选择已保存的模型")
            get(s, body.model_id, "model")
            if not os.getenv("MODEL_GATEWAY_URL"):
                raise HTTPException(400, "模型出口尚未启动")
            if row and (row["calls"] >= 3 or row["reserved_usd"] >= body.max_cost_usd):
                raise HTTPException(400, "本任务监测额度已用尽；关闭再开启不会重置额度")
        if not row:
            row = create(s, "task_monitor", {"job_id": job_id, "entries": [], "calls": 0, "reserved_usd": 0})
        row.update(body.model_dump(), generation=uuid4().hex, state="watching" if body.enabled else "off", error=None)
        save(s, row)
        audit(s, "monitor_enabled" if body.enabled else "monitor_disabled", job_id)
        return row


def snapshot(s, job_id):
    job, jobs, discoveries = scope(s, job_id)
    evidence = [e for e in all_of(s, "evidence") if e.get("job_id") in jobs]
    subjects = set(jobs + discoveries + [job_id] + [e["id"] for e in evidence])
    # Never send URLs, arbitrary log details, credentials, bodies, names or headers.
    allowed = {"job_created", "job_started", "job_completed", "job_blocked", "job_pause", "job_stop",
               "request_reserved", "request_dispatched", "request_finished", "check_completed"}
    events = [a for a in all_of(s, "audit") if a.get("action") in allowed and
              (a.get("job_id") in jobs or a.get("subject") in subjects)]
    recent = sorted(events, key=lambda e: e.get("at", 0))[-20:]
    status = job.get("status")
    if status not in TERMINAL | {"running", "queued", "paused"}:
        status = "unknown"
    return {"status": status, "reserved_requests": job.get("used", 0),
            "request_budget": job.get("request_budget", 0), "event_count": len(events),
            "completed_requests": sum(e.get("state") == "complete" for e in evidence),
            "failed_requests": sum(e.get("state") == "failed" for e in evidence),
            "events": [{"id": a["id"], "at": a.get("at"), "type": a["action"]} for a in recent]}


def observe(ident):
    with locked() as s:
        row = get(s, ident, "task_monitor")
        if not row["enabled"]:
            return
        context = snapshot(s, row["job_id"])
        fingerprint = hashlib.sha256(json.dumps(context, sort_keys=True).encode()).hexdigest()
        terminal = context["status"] in TERMINAL
        # Reservations persist across crashes; never repeat a paid call automatically.
        if row["calls"] >= 3 or row["reserved_usd"] >= row["max_cost_usd"]:
            row.update(enabled=False, state="limit")
            save(s, row)
            return
        if row.get("fingerprint") == fingerprint:
            if terminal:
                row.update(enabled=False, state="finished")
                save(s, row)
            return
        if not terminal and now() - row.get("last_call_at", 0) < 30:
            return
        budget = min(row["max_cost_usd"] / 3, row["max_cost_usd"] - row["reserved_usd"])
        row.update(calls=row["calls"] + 1, reserved_usd=row["reserved_usd"] + budget,
                   last_call_at=now(), fingerprint=fingerprint, state="analyzing", snapshot=context)
        save(s, row)
        generation = row["generation"]
    try:
        response = httpx.post(os.environ["MODEL_GATEWAY_URL"] + "/internal/model",
            json={"model_id": row["model_id"], "planning_mode": "task_monitor", "context": context, "budget": budget},
            headers={"X-Internal-Token": os.environ["INTERNAL_TOKEN"]}, timeout=45, trust_env=False)
        response.raise_for_status()
        interpretation = Interpretation.model_validate(response.json())
        text = redact(interpretation.summary)
        error = None
    except Exception:
        text = "监测解读失败。请检查模型连接或费用上限；原检查任务继续运行。"
        error = "模型调用失败或返回格式无效"
    with locked() as s:
        current = get(s, ident, "task_monitor")
        if not current["enabled"] or current["generation"] != generation:
            return
        current["entries"] = (current["entries"] + [{"at": now(), "summary": text, "snapshot": context, "error": error}])[-3:]
        current.update(error=error, state="error" if error else "finished" if terminal else "watching")
        if terminal or error:
            current["enabled"] = False
        save(s, current)
        audit(s, "monitor_observed", row["job_id"], current["state"])


def start():
    stop = threading.Event()

    def loop():
        while not stop.wait(5):
            try:
                with Session() as s:
                    identifiers = [r["id"] for r in all_of(s, "task_monitor") if r.get("enabled")]
                for ident in identifiers:
                    if stop.is_set():
                        break
                    try:
                        observe(ident)
                    except Exception:
                        # A deleted task must not prevent other observers from running.
                        with locked() as s:
                            row = get(s, ident, "task_monitor")
                            row.update(enabled=False, state="error", error="任务不可用，监测已停止")
                            save(s, row)
            except Exception:
                # DB startup/shutdown can temporarily be unavailable.
                continue

    thread = threading.Thread(target=loop, name="task-event-agent", daemon=True)
    thread.start()
    return stop, thread
