"""Bounded local material review. No filesystem reads, execution or target traffic."""
import hashlib
import re
from collections import Counter, defaultdict
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from .job_management import authenticate
from .security import redact
from .service import all_of, audit, create, get, locked, save
from .store import Session, now

router = APIRouter(dependencies=[Depends(authenticate)])
CATEGORIES = {"xss": "XSS", "configuration": "配置错误", "weak_password": "弱口令",
    "incident": "入侵事件", "integrity": "疑似被黑／文件完整性", "upload": "文件上传",
    "disclosure": "信息泄露", "backdoor": "存在后门", "logic": "逻辑漏洞",
    "code_execution": "代码执行", "command_execution": "命令执行", "sql": "SQL 注入", "parser": "解析漏洞"}
LIMITATION = "仅覆盖提交的材料与有限规则；线索需人工确认，未发现线索不代表安全。未执行代码、上传文件、尝试登录或向目标发出请求。"


class Source(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = Field(min_length=1, max_length=240)
    content: str = Field(max_length=262144)


class Manifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = Field(min_length=1, max_length=240)
    sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")


class Event(BaseModel):
    model_config = ConfigDict(extra="forbid")
    at: float = Field(ge=0, allow_inf_nan=False)
    kind: Literal["login_failed", "login_success", "http_request", "admin_change"]
    actor: str = Field(default="", max_length=100)
    path: str = Field(default="", max_length=1000)
    status: int = Field(default=0, ge=0, le=599)


class ReviewInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sources: list[Source] = Field(default_factory=list, max_length=32)
    events: list[Event] = Field(default_factory=list, max_length=2000)
    baseline: list[Manifest] = Field(default_factory=list, max_length=1000)
    current: list[Manifest] = Field(default_factory=list, max_length=1000)
    known_bad_sha256: list[str] = Field(default_factory=list, max_length=100)
    passwords: list[str] = Field(default_factory=list, max_length=50, repr=False)
    materials_owned: Literal[True]

    @model_validator(mode="after")
    def bounded(self):
        if not (self.sources or self.events or self.current or self.passwords):
            raise ValueError("请提供源码、结构化日志、文件清单或测试口令")
        sizes = [len(f.content.encode("utf-8")) for f in self.sources]
        if any(size > 262144 for size in sizes):
            raise ValueError("单个源码文本不能超过 256 KB")
        if sum(sizes) > 2_000_000:
            raise ValueError("源码总大小不能超过 2 MB")
        if any(not p or len(p) > 256 for p in self.passwords):
            raise ValueError("测试口令须为 1 至 256 字符")
        for group in (self.sources, self.baseline, self.current):
            paths = []
            for f in group:
                f.path = f.path.replace("\\", "/")
                if f.path.startswith("/") or ":" in f.path or any(p in ("", ".", "..") for p in f.path.split("/")) or any(ord(c) < 32 for c in f.path):
                    raise ValueError("文件名必须是无父级跳转的相对路径")
                paths.append(f.path)
            if len(paths) != len(set(paths)):
                raise ValueError("同组文件路径不能重复")
        if any(not re.fullmatch(r"[a-fA-F0-9]{64}", h) for h in self.known_bad_sha256):
            raise ValueError("已知异常摘要必须为 SHA-256")
        return self


# Patterns identify review sites, not a proven source-to-sink data flow.
RULES = [
    ("xss", "raw-html", r"dangerouslySetInnerHTML|\.innerHTML\s*=|document\.write\s*\(|\bv-html\s*=", "不安全 HTML 写入入口", "核对数据来源，采用文本输出或合适的 HTML 净化。"),
    ("configuration", "debug", r"\bDEBUG\s*[:=]\s*(?:True|true|1)\b|app\.run\([^\n]*debug\s*=\s*True", "调试配置开启", "核实部署环境，生产环境关闭调试。"),
    ("upload", "raw-upload-path", r"(?:\.save|move_uploaded_file)\s*\([^\n]*(?:filename|\$_FILES)|(?:writeFile|createWriteStream)\s*\([^\n]*(?:originalname|filename)", "上传文件名参与存储路径", "服务端生成文件名，限制路径、大小与文件类型，存储于不可执行目录。"),
    ("disclosure", "hardcoded-secret", r"(?:password|api_key|secret_key|access_token)\s*[:=]\s*['\"][^'\"\n]{8,}", "疑似硬编码凭证", "确认是否为真实凭证；如已暴露，撤销轮换并改用安全配置。"),
    ("backdoor", "request-execution", r"(?:eval|assert|system|exec|shell_exec)\s*\([^\n]*(?:\$_(?:GET|POST|REQUEST)|request\.(?:args|form|values)|req\.(?:query|body))", "外部输入紧邻动态执行入口", "核查代码来源及数据流；该模式不等同于后门，需结合变更历史调查。"),
    ("logic", "client-price", r"(?:price|amount|is_admin|role)\s*=\s*(?:request\.(?:args|form|values)|req\.(?:body|query))", "业务敏感值来自客户端", "结合业务规则核对金额重算、角色授权及状态转换，不能只信任客户端。"),
    ("code_execution", "dynamic-eval", r"\b(?:eval|exec|Function)\s*\(", "动态代码执行入口", "确认输入可控性；优先使用受限解析器替代动态代码执行。"),
    ("command_execution", "process-shell", r"\b(?:os\.system|shell_exec|child_process\.exec)\s*\(|\bsubprocess\.(?:run|Popen|call|check_output)\([^\n]*shell\s*=\s*True", "系统命令／Shell 执行入口", "使用固定程序与参数数组，避免将外部输入拼接为 Shell 命令。"),
    ("sql", "sql-concatenation", r"\b(?:execute|query|raw)\s*\(\s*f['\"]|\b(?:execute|query|raw)\s*\([^\n]*\+|['\"][^'\"\n]*\b(?:SELECT|UPDATE|INSERT|DELETE)\b[^\n]*\.format\s*\(", "动态拼接 SQL 入口", "核查查询构造，使用驱动提供的参数绑定；表名等标识符另行白名单校验。"),
    ("parser", "unsafe-deserialization", r"\b(?:pickle\.loads?|yaml\.load|unserialize|readObject)\s*\(|resolve_entities\s*=\s*True|DtdProcessing\s*=\s*DtdProcessing\.Parse", "危险反序列化／实体解析配置", "不解析不可信对象；核实安全加载器，禁用外部实体和网络解析。"),
]
COMPILED = [(category, ident, re.compile(pattern, re.I), title, fix) for category, ident, pattern, title, fix in RULES]
COMMON = {"123456", "12345678", "123456789", "1234567890", "password", "password123", "admin", "admin123", "qwerty", "qwerty123", "111111", "000000", "abc123", "letmein", "welcome", "changeme", "test123", "root"}


def analyze(body: ReviewInput):
    items = []
    counts = Counter()
    def add(category, rule, location, title, reason, fix):
        counts[category] += 1
        if len(items) < 200:
            items.append(dict(category=category, rule=rule, location=redact(location), title=title, reason=reason, fix=fix, status="lead"))
    for source in body.sources:
        for number, line in enumerate(source.content.splitlines(), 1):
            if line.lstrip().startswith(("#", "//", "*", "<!--")):
                continue
            for category, ident, pattern, title, fix in COMPILED:
                if pattern.search(line[:8192]):
                    add(category, ident, f"{source.path}:{number}", title, "命中有限文本规则，尚未证明输入可控、可达或可利用；不保存源码片段。", fix)
    for index, password in enumerate(body.passwords, 1):
        lower = password.casefold()
        if lower in COMMON or len(password) < 8 or len(set(lower)) <= 2 or (password.isdigit() and len(password) < 12):
            add("weak_password", "offline-password", f"测试口令 #{index}", "测试口令命中弱口令规则", "仅做离线字典与长度／重复模式检查，不尝试登录，不保存口令或口令摘要；未命中不代表足够强。", "改用长且唯一的随机口令，配合多因素认证与登录限速。")
    failures = defaultdict(list)
    for index, event in sorted(enumerate(body.events, 1), key=lambda pair: pair[1].at):
        # An empty actor cannot establish that two events share an identity.
        if event.actor:
            failures[event.actor] = [t for t in failures[event.actor] if event.at - t <= 600]
            if event.kind == "login_failed":
                failures[event.actor].append(event.at)
                if len(failures[event.actor]) == 5:
                    add("incident", "login-failure-burst", f"日志事件 #{index}", "10 分钟内同一来源至少 5 次登录失败", "可能是口令猜测、误配置或用户输错，不证明已被入侵。", "关联登录审计及账号活动，核查限速和多因素认证。")
            elif event.kind == "login_success" and len(failures[event.actor]) >= 5:
                add("incident", "success-after-failures", f"日志事件 #{index}", "连续失败后出现登录成功", "相同 actor 在 10 分钟内至少失败 5 次后成功，需核对是否本人操作；不保存 actor。", "关联设备、时间及账号行为核实，发现异常时撤销相关会话。")
        if event.kind == "http_request" and re.search(r"/(?:\.env|\.git(?:/|$)|wp-config\.php)(?:[/?]|$)", event.path, re.I):
            add("incident", "sensitive-path-request", f"日志事件 #{index}", "日志中出现敏感路径探测", "仅证明收到探测请求；即使返回 200 也可能是前端回退页面，不证明泄露。", "核查对应响应及访问来源，禁止公开部署敏感文件。")
    old = {f.path: f.sha256.lower() for f in body.baseline}
    current = {f.path: f.sha256.lower() for f in body.current}
    if old and current:
        for path in sorted(old.keys() | current.keys()):
            if old.get(path) != current.get(path):
                change = "新增" if path not in old else "缺失" if path not in current else "内容变化"
                add("integrity", "manifest-difference", path, f"文件清单对比：{change}", "仅比较用户提交的摘要；正常发布、清单不完整和文件篡改均可能产生差异。", "对照可信发布版本与变更记录，核实清单是否覆盖相同范围。")
    bad = {h.lower() for h in body.known_bad_sha256}
    for path, digest in current.items():
        if digest in bad:
            add("backdoor", "user-indicator-match", path, "命中用户提供的异常文件摘要", "摘要精确匹配用户输入的指标；指标来源未验证，不自动认定恶意或后门。", "在隔离环境复核指标来源及文件，结合日志与可信版本调查。")
    covered = {r[0] for r in RULES} if body.sources else set()
    if body.passwords: covered.add("weak_password")
    if body.events: covered.add("incident")
    if old and current: covered.add("integrity")
    if current and bad: covered.add("backdoor")
    return {"items": items, "coverage": [{"category": key, "name": name,
        "status": "lead" if counts[key] else "reviewed" if key in covered else "not_run", "count": counts[key]} for key, name in CATEGORIES.items()],
        "limitations": LIMITATION + f"源码为逐行启发式检查，不跟踪跨文件数据流，不覆盖全部语言与漏洞变体。最多保存 200 条线索；本次省略 {sum(counts.values()) - len(items)} 条明细，可缩小材料范围复查。文件摘要基线须由用户确认可信。",
        "materials": {"sources": [{"path": redact(f.path), "sha256": hashlib.sha256(f.content.encode()).hexdigest()} for f in body.sources],
                      "event_count": len(body.events), "baseline_count": len(old), "current_count": len(current), "password_count": len(body.passwords)}}


def parse_input(body: dict):
    try:
        return ReviewInput.model_validate(body)
    except ValidationError:
        # Never echo the original request, which can contain test passwords.
        raise HTTPException(422, "材料格式或大小不符合要求，请核对字段、文件路径和数量限制") from None


@router.post("/api/targets/{target_id}/offline-reviews")
def review(target_id: str, body: ReviewInput = Depends(parse_input)):
    # This API deliberately does not require active network authorization: no traffic is sent.
    with Session() as s:
        target = get(s, target_id, "target")
        if target.get("deleted"):
            raise HTTPException(409, "已删除目标不能添加审查")
    result = analyze(body)
    with locked() as s:
        target = get(s, target_id, "target")
        if target.get("deleted"):
            raise HTTPException(409, "已删除目标不能添加审查")
        job = create(s, "job", {"target_id": target_id, "name": "离线专项审查", "status": "completed", "created_at": now(),
            "completed_at": now(), "used": 0, "request_budget": 0, "endpoint_ids": [], "account_ids": [], "version": target.get("version"), "offline_review": result})
        evidence = create(s, "evidence", {"job_id": job["id"], "target_id": target_id, "source": "offline_review", "state": "offline",
            "method": "OFFLINE", "url": "", "at": now(), "observation": result["limitations"], "review": result})
        for item in result["items"]:
            fingerprint = hashlib.sha256(f'{target_id}:offline:{item["rule"]}:{item["location"]}'.encode()).hexdigest()
            existing = next((f for f in all_of(s, "finding") if f.get("fingerprint") == fingerprint and f["status"] != "false_positive"), None)
            if existing:
                existing["evidence_ids"] = list(dict.fromkeys(existing["evidence_ids"] + [evidence["id"]]))
                existing["status"] = "pending"
                save(s, existing)
            else:
                create(s, "finding", {"job_id": job["id"], "target_id": target_id, "endpoint_id": "offline", "fingerprint": fingerprint,
                    "title": item["title"], "status": "lead", "evidence_ids": [evidence["id"]], "detail": item["location"] + "：" + item["reason"],
                    "impact": "离线线索，实际可利用性及影响需结合部署与业务确认", "fix": item["fix"], "explanation": ""})
        audit(s, "offline_review_completed", job["id"], f'离线审查，{len(result["items"])} 条线索，0 次目标请求')
        return {"job_id": job["id"], **result}
