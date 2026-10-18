"""Bounded static discovery, executed exclusively by the request gateway."""

import json
import re
from collections import deque
from html.parser import HTMLParser
from http.client import HTTPException as TransportError
from typing import Annotated
from urllib.parse import urljoin, urlsplit, urlunsplit
from uuid import uuid4

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .policy import Denied, check_url, request
from .security import redact
from .service import active, all_of, audit, create, get, locked, origin, save
from .store import Session, now


def authenticated(x_api_key: str = Header(default="")):
    from .main import auth

    return auth(x_api_key)


router = APIRouter(prefix="/api", dependencies=[Depends(authenticated)])


class DiscoveryInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    seeds: list[Annotated[str, Field(min_length=1, max_length=2048)]] = Field(
        default_factory=list, max_length=10
    )
    automatic: bool = False
    request_budget: int = Field(default=5, ge=1, le=20)
    max_depth: int = Field(default=1, ge=0, le=2)


class Selection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    candidate_ids: list[str] = Field(min_length=1, max_length=300)


def candidate(target, base, value, method, source, source_type):
    # Fragments are navigation hints; query values are never retained or sent.
    url = "<无法解析的地址>"
    try:
        parsed = urlsplit(urljoin(base, value))
        url = urlunsplit(
            (
                parsed.scheme,
                parsed.netloc.rsplit("@", 1)[-1],
                parsed.path or "/",
                "",
                "",
            )
        )
        reason = ""
        if parsed.username or parsed.password:
            raise Denied("地址包含凭证，不能导入")
        check_url(target, url)
        if parsed.query:
            reason = "含查询参数，需手工整理后导入"
        elif any(c in parsed.path for c in ("{", "}", "$", "*", ":")):
            reason = "动态路径，需填写合成测试参数"
    except (ValueError, UnicodeError) as exc:
        reason = str(exc) if isinstance(exc, Denied) else "无法解析 URL"
    return {
        "id": uuid4().hex,
        "url": redact(url),
        "method": method,
        "source": redact(source),
        "source_type": source_type,
        "in_scope": not reason,
        "reason": reason,
        "importable": not reason
        and method in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"),
    }


def extract(target, url, body, content_type):
    """Return static candidates and crawl hints, never execute untrusted content."""
    rows, hints = [], []

    def add(value, method="GET", kind="页面链接", crawl=False):
        if (
            not isinstance(value, str)
            or not value
            or len(value) > 2048
            or len(rows) >= 300
        ):
            return
        if value.startswith(("#", "data:", "mailto:", "javascript:")):
            return
        row = candidate(target, url, value, method, url, kind)
        rows.append(row)
        if crawl and row["importable"] and method == "GET":
            hints.append(row["url"])

    class Page(HTMLParser):
        def handle_starttag(self, tag, attrs):
            a = dict(attrs)
            if tag == "a":
                add(a.get("href"), crawl=True)
            elif tag == "script":
                add(a.get("src"), kind="页面脚本", crawl=True)
            elif tag == "form":
                add(a.get("action", url), a.get("method", "GET").upper(), "表单")
            elif tag == "link" and a.get("rel") == "modulepreload":
                add(a.get("href"), kind="页面脚本", crawl=True)

    if "html" in content_type:
        Page().feed(body)
    if (
        "javascript" in content_type
        or urlsplit(url).path.endswith((".js", ".mjs", ".ts", ".tsx", ".jsx"))
        or "html" in content_type
    ):
        for match in re.finditer(
            r"""\bfetch\s*\(\s*['"]([^'"\r\n]+)['"]([^)]{0,300})""", body
        ):
            method = re.search(r"""\bmethod\s*:\s*['"]([A-Za-z]+)['"]""", match[2])
            add(
                match[1],
                method[1].upper() if method else "GET",
                "JavaScript fetch（静态推断）",
            )
        for match in re.finditer(
            r"""\b(?:axios|\w*api\w*)\.(get|post|put|patch|delete|head|options)\s*\(\s*['"]([^'"\r\n]+)['"]""",
            body,
            re.IGNORECASE,
        ):
            add(match[2], match[1].upper(), "JavaScript 请求（静态推断）")
        for match in re.finditer(
            r"""['"]((?:https?://[^'"\s]+)?/api/[^'"\s]*)['"]""", body
        ):
            add(match[1], "UNKNOWN", "JavaScript 路径线索（方法未知）")
        # Vite and module builds use relative/static imports. Do not evaluate expressions.
        for match in re.finditer(
            r"""\b(?:from\s*|import\s*\(?\s*)['"]([^'"\r\n]+)['"]""", body
        ):
            if match[1].startswith(("/", "./", "../")):
                add(match[1], kind="模块引用", crawl=True)
    if "json" in content_type or urlsplit(url).path.endswith(".json"):
        try:
            document = json.loads(body)
        except (ValueError, RecursionError):
            document = None
        if isinstance(document, dict) and (
            "openapi" in document or "swagger" in document
        ):
            base = origin(target)
            servers = document.get("servers")
            if isinstance(servers, list) and servers and isinstance(servers[0], dict):
                base = urljoin(url, str(servers[0].get("url", "/")))
            elif document.get("swagger"):
                base = origin(target) + str(document.get("basePath", ""))
                if document.get("host"):
                    schemes = document.get("schemes", [target["scheme"]])
                    scheme = (
                        schemes[0]
                        if isinstance(schemes, list) and schemes
                        else target["scheme"]
                    )
                    base = f"{scheme}://{document['host']}" + str(
                        document.get("basePath", "")
                    )
            paths = document.get("paths", {})
            if isinstance(paths, dict):
                for path, operations in list(paths.items())[:300]:
                    if not isinstance(operations, dict):
                        continue
                    for method in operations:
                        if method.upper() in (
                            "GET",
                            "POST",
                            "PUT",
                            "PATCH",
                            "DELETE",
                            "HEAD",
                            "OPTIONS",
                        ):
                            rows.append(
                                candidate(
                                    target,
                                    base.rstrip("/") + "/",
                                    base.rstrip("/") + "/" + path.lstrip("/"),
                                    method.upper(),
                                    url,
                                    "OpenAPI 文档",
                                )
                            )
    return rows[:300], hints[:100]


@router.post("/targets/{target_id}/discoveries")
def start(target_id: str, body: DiscoveryInput):
    with locked() as s:
        target = get(s, target_id, "target")
        active(target)
        seeds = []
        entries = target["paths"][:10] if body.automatic else body.seeds
        if not entries:
            raise HTTPException(400, "请提供至少一个发现入口")
        for value in entries:
            row = candidate(
                target, origin(target) + "/", value.strip(), "GET", "手工入口", "入口"
            )
            if not row["importable"]:
                raise HTTPException(400, row["reason"])
            seeds.append(row["url"])
        if body.request_budget > target["request_budget"] - target["used"]:
            raise Denied("超过目标剩余请求预算")
        if any(
            d["target_id"] == target_id and d["status"] in ("queued", "running")
            for d in all_of(s, "discovery")
        ):
            raise HTTPException(409, "该目标已有接口发现任务")
        row = create(
            s,
            "discovery",
            {
                **body.model_dump(),
                "target_id": target_id,
                "seeds": list(dict.fromkeys(seeds)),
                "version": target["version"],
                "status": "queued",
                "used": 0,
                "created_at": now(),
                "duration_seconds": 120,
                "requests": [],
                "candidates": [],
            },
        )
        audit(s, "discovery_created", row["id"])
        return row


@router.get("/targets/{target_id}/discoveries")
def history(target_id: str):
    with Session() as s:
        get(s, target_id, "target")
        return sorted(
            [d for d in all_of(s, "discovery") if d["target_id"] == target_id],
            key=lambda d: d["created_at"],
            reverse=True,
        )


@router.post("/discoveries/{ident}/stop")
def stop(ident: str):
    with locked() as s:
        row = get(s, ident, "discovery")
        row.update(status="stopped")
        save(s, row)
        audit(s, "discovery_stopped", ident)
    return {"ok": True}


@router.post("/discoveries/{ident}/import")
def import_selected(ident: str, body: Selection):
    with locked() as s:
        row = get(s, ident, "discovery")
        target = get(s, row["target_id"], "target")
        active(target)
        if row["version"] != target["version"]:
            raise Denied("授权已变化，请重新发现")
        chosen = [c for c in row["candidates"] if c["id"] in body.candidate_ids]
        if len(chosen) != len(set(body.candidate_ids)) or any(
            not c["importable"] for c in chosen
        ):
            raise HTTPException(400, "选择包含无效或不可导入候选项")
        imported = register_candidates(s, row, target, chosen)
        audit(s, "discovery_imported", ident, str(len(imported)))
        return {"imported": imported}


def register_candidates(s, row, target, chosen):
    existing = {
        (e["method"], e["url"])
        for e in all_of(s, "endpoint")
        if e["target_id"] == target["id"]
    }
    imported = []
    for c in chosen:
        check_url(target, c["url"])
        if (c["method"], c["url"]) not in existing:
            imported.append(
                create(
                    s,
                    "endpoint",
                    {
                        "target_id": target["id"],
                        "method": c["method"],
                        "url": c["url"],
                        "executable": c["method"] == "GET",
                        "source": c["source"],
                        "discovery_id": row["id"],
                    },
                )
            )
            existing.add((c["method"], c["url"]))
    return imported


def finish_automatic(s, row, target):
    if not row.get("automatic"):
        return
    active(target)
    if row["version"] != target["version"]:
        raise Denied("授权已变化，请重新扫描")
    chosen = [
        c
        for c in row["candidates"]
        if c["importable"]
        and c["source_type"] not in ("页面脚本", "模块引用")
        and not re.search(
            r"/(?:src|node_modules|assets|@vite|@react-refresh|@fs)(?:/|$)|\.(?:[cm]?js|tsx?|jsx|css|scss)$",
            urlsplit(c["url"]).path,
        )
    ]
    imported = register_candidates(s, row, target, chosen)
    row["auto_imported"] = len(imported)
    audit(s, "discovery_auto_imported", row["id"], str(len(imported)))


def live(s, ident):
    row = get(s, ident, "discovery")
    target = get(s, row["target_id"], "target")
    active(target)
    if (
        row["status"] != "running"
        or row["version"] != target["version"]
        or row["deadline"] <= now()
    ):
        raise Denied("接口发现或授权已失效")
    return row, target


def process(ident):
    with Session() as s:
        row = get(s, ident, "discovery")
    queue = deque((url, 0) for url in row["seeds"])
    visited, keys = set(), set()
    try:
        while queue:
            url, depth = queue.popleft()
            if url in visited:
                continue
            with locked() as s:
                row, target = live(s, ident)
                if (
                    row["used"] >= row["request_budget"]
                    or target["used"] >= target["request_budget"]
                ):
                    finish_automatic(s, row, target)
                    row.update(
                        status="completed",
                        note="已达到请求预算，部分引用未访问",
                        completed_at=now(),
                    )
                    save(s, row)
                    return
                check_url(target, url)
                entry = {
                    "id": uuid4().hex,
                    "url": url,
                    "method": "GET",
                    "state": "reserved",
                    "at": now(),
                }
                row["requests"].append(entry)
                row["used"] += 1
                target["used"] += 1
                save(s, row)
                save(s, target)
            visited.add(url)

            def before_send(entry=entry):
                with locked() as s:
                    current, _ = live(s, ident)
                    entry.update(state="in_flight", sent_at=now())
                    current["requests"][-1] = entry
                    save(s, current)

            rows, hints = [], []
            try:
                result = request(target, url, before_send=before_send)
                entry.update(
                    state="complete",
                    status=result["status"],
                    truncated=result["truncated"],
                    redirect_blocked=result.get("redirect_blocked", False),
                )
                content_type = next(
                    (
                        v
                        for k, v in result["headers"].items()
                        if k.lower() == "content-type"
                    ),
                    "",
                ).lower()
                if 200 <= result["status"] < 300:
                    rows, hints = extract(target, url, result["body"], content_type)
            except (OSError, ValueError, TransportError) as exc:
                entry.update(state="failed", error=type(exc).__name__)
            entry["completed_at"] = now()
            with locked() as s:
                current = get(s, ident, "discovery")
                current["requests"][-1] = entry
                for c in rows:
                    key = (c["method"], c["url"], c["source"])
                    if key not in keys and len(current["candidates"]) < 300:
                        current["candidates"].append(c)
                        keys.add(key)
                save(s, current)
                audit(
                    s,
                    "discovery_response",
                    ident,
                    f"{entry['state']} HTTP {entry.get('status', '—')}",
                )
            if depth < row["max_depth"]:
                queue.extend((hint, depth + 1) for hint in hints if hint not in visited)
        with locked() as s:
            row, target = live(s, ident)
            finish_automatic(s, row, target)
            row.update(
                status="completed",
                completed_at=now(),
                note="静态发现完成；候选引用不证明接口存在，未执行候选业务请求",
            )
            save(s, row)
    except (Denied, HTTPException) as exc:
        with locked() as s:
            row = get(s, ident, "discovery")
            if row["status"] == "running":
                row.update(status="blocked", error=str(exc), completed_at=now())
                save(s, row)
