"""Bounded response-only diagnosis; no additional requests or triggering inputs."""

import re
from html.parser import HTMLParser

_MAX_TEXT = 1024 * 1024
_DOCUMENT = re.compile(r"\b(?:example|documentation|tutorial|sample\s+code)\b|示例|教程|文档", re.I)
_ERROR = re.compile('\\b(?:DeadlockDetected|SerializationFailure)\\b|\\bSQLSTATE\\s*(?:\\[|:)?\\s*(?:40001|40P01)\\b|\\bdeadlock detected\\b|\\bcould not serialize access due to concurrent update\\b|\\b(?:OptimisticLockException|StaleObjectStateException)\\b', re.I)
_LIMIT = '仅分析已有响应，不发送并发操作；需专项验证，未命中不代表安全。'


class _VisibleText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hidden = []
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "pre", "code", "template"}:
            self.hidden.append(tag)

    def handle_endtag(self, tag):
        if tag in self.hidden:
            del self.hidden[self.hidden.index(tag):]

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def inspect_response(body: str, headers: dict):
    check = {"id": 'race-condition-error', "name": '事务与并发冲突线索', "status": "not_detected", "detail": ""}
    if not isinstance(body, str) or not isinstance(headers, dict):
        check.update(status="inconclusive", detail="响应数据格式不完整，无法分析。" + _LIMIT)
        return [check], []
    mime = next((str(v) for k, v in headers.items() if str(k).lower() == "content-type"), "").split(";", 1)[0].strip().lower()
    textual = mime.startswith("text/") or mime in {"application/json", "application/xml", "application/xhtml+xml"} or mime.endswith(("+json", "+xml"))
    if not textual:
        check.update(status="not_applicable", detail="响应类型不适用文本分析。" + _LIMIT)
        return [check], []
    truncated = len(body) > _MAX_TEXT
    text = body[:_MAX_TEXT]
    if mime in {"text/html", "application/xhtml+xml"}:
        page = _VisibleText()
        page.feed(text)
        text = " ".join(page.parts)
    # Ignore fenced examples as well as explicit documentation pages.
    text = re.sub(r"```[\s\S]*?(?:```|$)|`[^`\r\n]*`", "", text)
    document = bool(_DOCUMENT.search(text))
    hit = bool(_ERROR.search(text)) and not document
    check.update(
        status="hit" if hit else ("inconclusive" if truncated else "not_detected"),
        detail=('已有响应出现事务或并发冲突异常，正常并发控制也可能产生这些错误；缺少操作时序、并发执行及业务不变量证据，不能确认竞争条件漏洞。' if hit else "未识别明确诊断；现有响应不足以判断此类漏洞。") + ("识别到文档或示例，不生成漏洞线索。" if document else "") + ("仅分析响应前 1 MiB。" if truncated else "") + _LIMIT,
    )
    signals = [{"root": 'race-condition-error', "title": '事务与并发冲突线索' + "，待人工确认"}] if hit else []
    return [check], signals
