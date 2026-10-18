import json

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.main import app
from app.submission_report import Draft, export, read, write
from app.service import create, get, locked


def seed():
    with locked() as s:
        target = create(s, "target", {"name": "test", "host": "www.example.test"})
        evidence = create(s, "evidence", {"target_id": target["id"], "state": "complete", "url": "https://www.example.test/test?token=private-token", "steps": "实际观察"})
        finding = create(s, "finding", {"target_id": target["id"], "status": "lead", "title": "可疑线索", "detail": "有限观察", "impact": "待验证", "fix": "复核", "evidence_ids": [evidence["id"]]})
    return finding


def test_initial_is_draft_not_invented_verified_vulnerability():
    finding = seed()
    result = read(finding["id"])
    assert result["finding_status"] == "lead"
    assert "private-token" not in json.dumps(result)
    assert result["fields"]["severity"] == ""
    assert any("人工确认" in i for i in result["missing"])
    assert any("待填" in i for i in result["missing"])
    assert len(result["types"]) == 13


def test_save_persistence_iot_and_exclusive_src():
    finding = seed()
    fields = read(finding["id"])["fields"]
    fields.update(category="IoT漏洞", vendor="测试厂商", subtype="解析漏洞", details="实际复现记录")
    result = write(finding["id"], Draft(**fields))
    assert "触发对应二进制位置" in result["missing"]
    assert read(finding["id"])["fields"]["vendor"] == "测试厂商"
    fields.update(exclusive_src=True)
    result = write(finding["id"], Draft(**fields))
    assert result["fields"]["category"] == "Web漏洞"
    assert "触发对应二进制位置" not in result["missing"]
    with locked() as s:
        assert get(s, finding["id"])["status"] == "lead"


def test_export_embeds_full_details_and_escapes_html():
    finding = seed()
    fields = read(finding["id"])["fields"]
    fields.update(details="实际复现 <script>alert(1)</script>", poc="最小复现说明", binary_location="test.bin:12", category="IoT漏洞", screenshots="归属与过程截图说明", components="未使用组件", attachments="video.zip，1 MB")
    write(finding["id"], Draft(**fields))
    markdown = export(finding["id"], "md").body.decode()
    assert "实际复现" in markdown and "test.bin:12" in markdown and "video.zip" in markdown
    assert "50 MB" in markdown and "未提交平台" in markdown
    html = export(finding["id"], "html").body.decode()
    assert "<script>" not in html and "&lt;script&gt;" in html


@pytest.mark.parametrize("fields", [{"urls": ["file:///etc/passwd"]}, {"urls": ["https://user:password@example.test/"]}, {"subtype": "unknown"}, {"category": "unknown"}, {"domain": "https://example.test"}, {"severity": "自动确认"}])
def test_invalid_fields(fields):
    with pytest.raises(ValidationError):
        Draft(**fields)


def test_credentials_redacted_before_save_and_api_auth():
    finding = seed()
    fields = read(finding["id"])["fields"]
    fields.update(details="Authorization: Bearer private-api-secret", urls=["https://example.test/?api_key=private-query-secret"])
    result = write(finding["id"], Draft(**fields))
    text = json.dumps(result)
    assert "private-api-secret" not in text and "private-query-secret" not in text
    client = TestClient(app)
    assert client.get(f'/api/findings/{finding["id"]}/submission-draft').status_code == 401
    assert client.get(f'/api/findings/{finding["id"]}/submission-export', headers={"X-API-Key":"test-token"}).status_code == 200
