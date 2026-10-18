"""User-edited SRC drafts. No external submission or invented exploit claims."""
import html
from typing import Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .job_management import authenticate
from .security import capture_text
from .service import all_of, audit, create, get, locked, save
from .store import Session, now

router = APIRouter(dependencies=[Depends(authenticate)])
TYPES = ["XSS", "配置错误", "弱口令", "入侵事件", "疑似被黑", "文件上传", "信息泄露", "存在后门", "逻辑漏洞", "代码执行", "命令执行", "SQL注入", "解析漏洞"]


class Draft(BaseModel):
    model_config = ConfigDict(extra="forbid")
    vendor: str = Field(default="", max_length=150)
    exclusive_src: bool = False
    asset_scope: str = Field(default="", max_length=1000)
    domain: str = Field(default="", max_length=253)
    category: Literal["Web漏洞", "IoT漏洞", "工控漏洞", "操作系统及通用软件漏洞"] = "Web漏洞"
    title: str = Field(default="", max_length=200)
    urls: list[str] = Field(default_factory=list, max_length=20)
    kind: str = Field(default="事件型", max_length=60)
    subtype: str = Field(default="", max_length=60)
    weight: Literal["", "0", "≥1"] = ""
    severity: Literal["", "低危", "中危", "高危", "严重"] = ""
    activity: str = Field(default="", max_length=150)
    task: str = Field(default="", max_length=150)
    summary: str = Field(default="", max_length=2000)
    details: str = Field(default="", max_length=20000)
    fix: str = Field(default="", max_length=4000)
    industry: str = Field(default="", max_length=100)
    industry_class: str = Field(default="", max_length=100)
    province: str = Field(default="", max_length=60)
    city: str = Field(default="", max_length=60)
    district: str = Field(default="", max_length=60)
    contact: str = Field(default="", max_length=300)
    anonymous: bool = False
    binary_location: str = Field(default="", max_length=1000)
    target_config: str = Field(default="", max_length=2000)
    research_environment: str = Field(default="", max_length=2000)
    components: str = Field(default="", max_length=2000)
    screenshots: str = Field(default="", max_length=2000)
    poc: str = Field(default="", max_length=5000)
    attachments: str = Field(default="", max_length=2000)

    @model_validator(mode="after")
    def validate_fields(self):
        if self.exclusive_src:
            self.category = "Web漏洞"
        if self.subtype and self.subtype not in TYPES:
            raise ValueError("请选择已有漏洞类型")
        if self.domain and (any(c.isspace() for c in self.domain) or any(c in self.domain for c in "/?#@")):
            raise ValueError("域名或 IP 不应填写完整 URL")
        for url in self.urls:
            if len(url) > 2000:
                raise ValueError("URL 过长")
            parsed = urlsplit(url)
            if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password or any(ord(c) < 32 for c in url):
                raise ValueError("漏洞 URL 仅支持无凭证的 HTTP(S) 地址")
        return self


def initial(s, finding):
    target = get(s, finding["target_id"], "target")
    evidence = [get(s, ident, "evidence") for ident in finding.get("evidence_ids", [])]
    if any(e.get("target_id") != finding["target_id"] for e in evidence):
        raise HTTPException(409, "证据不属于当前目标")
    urls = list(dict.fromkeys(capture_text(e["url"]) for e in evidence if e.get("url", "").startswith(("http://", "https://"))))[:20]
    steps = "\n".join(capture_text(e.get("steps", "")) for e in evidence if e.get("steps"))
    return Draft(title=capture_text(finding["title"]), domain=target.get("host", ""), urls=urls,
        summary="请简述漏洞现象及已验证影响；不要在此填写具体漏洞 URL。",
        details="## 基础信息\n" + capture_text(finding.get("detail", "")) + "\n\n## 前置条件与权限\n[请填写专用测试账号角色及必要环境]\n\n## 完整复现过程\n" + (steps or "[请逐步填写实际执行的操作、请求及观察]") + "\n\n## 证据\n" + "\n".join("- 证据编号：" + e["id"] for e in evidence) + "\n\n## 影响与验证局限\n" + capture_text(finding.get("impact", "")),
        fix=capture_text(finding.get("fix", ""))).model_dump()


def missing(draft, finding):
    required = {"vendor": "厂商名称", "domain": "主域名或 IP", "title": "漏洞标题", "subtype": "漏洞类型",
        "weight": "漏洞权重", "severity": "漏洞等级", "summary": "简要描述", "details": "详细细节", "fix": "修复方案",
        "industry": "所属行业", "industry_class": "行业分类", "province": "所属地区（省）", "city": "所属地区（市）", "district": "所属地区（区／县）",
        "screenshots": "复现与归属截图说明", "poc": "PoC／最小复现说明", "components": "组件及下载说明（未使用请注明）"}
    issues = [name for key, name in required.items() if not draft.get(key, "").strip()]
    if not draft.get("urls"):
        issues.append("漏洞 URL")
    for key in ("summary", "details", "poc"):
        if "[请" in draft.get(key, "") or draft.get(key, "").startswith("请简述"):
            issues.append("替换" + required[key] + "中的待填内容")
    if draft["category"] == "IoT漏洞":
        issues += [name for key, name in {"binary_location": "触发对应二进制位置", "target_config": "目标配置", "research_environment": "研究环境／硬件购买或仿真搭建说明"}.items() if not draft.get(key)]
    if finding.get("status") != "verified":
        issues.append("当前发现尚未人工确认，只能作为待验证草稿")
    if not finding.get("evidence_ids"):
        issues.append("缺少关联证据")
    return issues


def response_data(s, finding_id):
    finding = get(s, finding_id, "finding")
    row = next((d for d in all_of(s, "submission_draft") if d["finding_id"] == finding_id), None)
    draft = row["fields"] if row else initial(s, finding)
    return {"fields": draft, "saved_at": row.get("saved_at") if row else None, "missing": missing(draft, finding), "finding_status": finding["status"], "types": TYPES}


@router.get("/api/findings/{finding_id}/submission-draft")
def read(finding_id: str):
    with Session() as s:
        return response_data(s, finding_id)


@router.put("/api/findings/{finding_id}/submission-draft")
def write(finding_id: str, body: Draft):
    with locked() as s:
        finding = get(s, finding_id, "finding")
        fields = body.model_dump()
        # All content is a local draft; credentials and personal data in prose are redacted.
        fields = {key: capture_text(value) if isinstance(value, str) and key not in ("contact", "domain") else value for key, value in fields.items()}
        fields["urls"] = [capture_text(url) for url in fields["urls"]]
        row = next((d for d in all_of(s, "submission_draft") if d["finding_id"] == finding_id), None)
        if not row:
            row = create(s, "submission_draft", {"finding_id": finding_id, "target_id": finding["target_id"]})
        row.update(fields=fields, saved_at=now())
        save(s, row)
        audit(s, "submission_draft_saved", finding_id)
        return response_data(s, finding_id)


def markdown(data):
    f = data["fields"]
    text = ["# 平台提交草稿", "此文件未提交平台；请按平台当前规则复核。应用不会代选协议或自动提交。",
        "发现状态：" + data["finding_status"], "## 待补充与复核", *("- " + issue for issue in data["missing"])]
    if not data["missing"]:
        text.append("字段已填写，仍需人工核对证据、分类、平台规则与附件。")
    names = {"vendor":"厂商名称", "asset_scope":"厂商资产范围", "domain":"域名或 IP", "category":"漏洞类别", "title":"漏洞标题", "kind":"漏洞类型分组", "subtype":"漏洞类型", "weight":"漏洞权重", "severity":"漏洞等级", "activity":"参与活动", "task":"参与任务", "summary":"简要描述"}
    text += ["## 基础字段", *(f"- {name}：{f[key] or '未填写'}" for key, name in names.items()), "- 专属 SRC：" + ("是" if f["exclusive_src"] else "否"), "### 漏洞 URL", *f["urls"],
        "## 详细细节（填写到平台细节字段）", f["details"], "### 截图／视频及厂商归属证明", f["screenshots"], "### PoC／最小复现", f["poc"], "### 使用组件与下载链接", f["components"]]
    if f["category"] == "IoT漏洞":
        text += ["### 触发二进制位置", f["binary_location"], "### 目标配置", f["target_config"], "### 研究环境", f["research_environment"]]
    text += ["## 修复方案", f["fix"], "## 附件清单", f["attachments"], "附件请在平台手动上传。按用户提供的规则：ZIP/RAR，不超过 50 MB；大文件在详细细节提供链接。漏洞详情不能仅放在附件里。",
        "## 厂商补充信息", f"行业：{f['industry']} / {f['industry_class']}", f"地区：{f['province']} / {f['city']} / {f['district']}", "厂商联系方式：" + f["contact"], "匿名提交：" + ("是" if f["anonymous"] else "否"),
        "提交前由本人阅读并确认平台用户协议和隐私政策；草稿不表示已同意协议。"]
    return "\n\n".join(text)


@router.get("/api/findings/{finding_id}/submission-export")
def export(finding_id: str, format: Literal["md", "html"] = "md"):
    with Session() as s:
        text = markdown(response_data(s, finding_id))
    if format == "html":
        text = '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>平台提交草稿</title><style>body{max-width:960px;margin:32px auto;padding:24px;font:16px/1.8 sans-serif}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:inherit}</style><pre>' + html.escape(text) + '</pre></html>'
    return Response(text, media_type="text/html" if format == "html" else "text/markdown",
        headers={"Content-Disposition": f'attachment; filename="submission-draft.{format}"'})
