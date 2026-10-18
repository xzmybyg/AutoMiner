"""Detect serialization error text only; never decode or instantiate objects."""

import re
from html.parser import HTMLParser


class _Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hidden = []
        self.text = []

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "pre", "code"}:
            self.hidden.append(tag)

    def handle_endtag(self, tag):
        if tag in self.hidden:
            self.hidden = self.hidden[:self.hidden.index(tag)]

    def handle_data(self, data):
        if not self.hidden:
            self.text.append(data)


_ERROR = re.compile(
    r"\bjava\.io\.(?:InvalidClassException|StreamCorruptedException|InvalidObjectException|OptionalDataException):|"
    r"\bcom\.fasterxml\.jackson\.databind\.exc\.(?:InvalidTypeIdException|MismatchedInputException):|"
    r"\bunserialize\(\):\s*(?:Error at offset|Unexpected end of serialized data)|"
    r"\b(?:_pickle|pickle)\.(?:UnpicklingError|UnpicklingWarning):|"
    r"\bSystem\.Runtime\.Serialization\.SerializationException:|"
    r"\b(?:Newtonsoft\.Json\.JsonSerializationException|java\.io\.ObjectStreamException):",
    re.I,
)
_DOCUMENT = re.compile(r"\b(?:example|documentation|tutorial|sample code)\b|示例|教程|文档", re.I)
_LIMIT = "仅分析已有响应，不构造、解码或加载序列化对象。异常不能证明不安全反序列化或代码执行；未命中不代表安全。"


def inspect_response(body: str, headers: dict):
    content_type = next((str(v) for k, v in headers.items() if k.lower() == "content-type"), "")
    mime = content_type.split(";", 1)[0].strip().lower()
    textual = mime.startswith("text/") or mime in {"application/json", "application/xml", "application/xhtml+xml", "application/problem+json"} or mime.endswith(("+json", "+xml"))
    if not textual:
        return [{"id": "deserialization-error", "name": "反序列化异常线索", "status": "not_applicable", "detail": "响应类型不适用文本分析。" + _LIMIT}], []
    if mime in {"text/html", "application/xhtml+xml"}:
        page = _Page()
        page.feed(body)
        text = " ".join(page.text)
    else:
        text = body
    document = bool(_DOCUMENT.search(text))
    hit = bool(_ERROR.search(text)) and not document
    checks = [{"id": "deserialization-error", "name": "反序列化异常线索", "status": "hit" if hit else "not_detected", "detail": "检查 Java、PHP、Python 与 .NET 的明确对象还原或数据绑定异常；普通格式校验失败也可能触发，需人工审查数据来源和类型限制。" + ("已识别文档或示例，不生成漏洞线索。" if document else "") + _LIMIT}]
    signals = [{"root": "deserialization-error", "title": "反序列化异常线索，待人工确认反序列化漏洞"}] if hit else []
    return checks, signals
