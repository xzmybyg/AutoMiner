"""Review existing text for file-operation errors; never perform file operations."""

import re
from html.parser import HTMLParser


class _Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hidden = []
        self.text = []
        self.file_input = False

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "pre", "code"}:
            self.hidden.append(tag)
        if tag == "input" and not self.hidden:
            fields = dict(attrs)
            self.file_input |= (fields.get("type") or "").lower() == "file" or bool(
                re.fullmatch(r"(?:file|filename|file_path|download|download_path|filepath)", fields.get("name") or "", re.I)
            )

    def handle_endtag(self, tag):
        if tag in self.hidden:
            self.hidden = self.hidden[:self.hidden.index(tag)]

    def handle_data(self, data):
        if not self.hidden:
            self.text.append(data)


_ERROR = re.compile(
    r"\b(?:FileNotFoundError|PermissionError|IsADirectoryError|NotADirectoryError):|"
    r"\bjava\.io\.(?:FileNotFoundException|IOException):|"
    r"\bSystem\.IO\.(?:FileNotFoundException|DirectoryNotFoundException|PathTooLongException):|"
    r"\b(?:include|include_once|require|require_once)\([^\r\n]{0,200}\):\s*(?:Failed to open stream|failed opening)|"
    r"\b(?:include|require)(?:_once)?\([^\r\n]{0,200}\):\s*Failed opening|"
    r"\b(?:ENOENT|EACCES):[^\r\n]{0,100}\b(?:open|scandir|stat|readdir)\b",
    re.I,
)
_DOCUMENT = re.compile(r"\b(?:example|documentation|tutorial|sample code)\b|示例|教程|文档", re.I)
_LIMIT = "仅分析已有响应，不上传文件、不提交路径、不读取文件。错误线索不能证明文件漏洞；未命中不代表安全。"


def inspect_response(body: str, headers: dict):
    content_type = next((str(v) for k, v in headers.items() if k.lower() == "content-type"), "")
    mime = content_type.split(";", 1)[0].strip().lower()
    textual = mime.startswith("text/") or mime in {"application/json", "application/xml", "application/xhtml+xml", "application/problem+json"} or mime.endswith(("+json", "+xml"))
    if not textual:
        return [{"id": key, "name": name, "status": "not_applicable", "detail": "响应类型不适用文本分析。" + _LIMIT} for key, name in [("file-operation-error", "文件操作异常线索"), ("file-input-review", "文件输入入口审查")]], []
    page = _Page()
    is_html = mime in {"text/html", "application/xhtml+xml"}
    if is_html:
        page.feed(body)
        text = " ".join(page.text)
    else:
        text = body
    document = bool(_DOCUMENT.search(text))
    hit = bool(_ERROR.search(text)) and not document
    checks = [
        {"id": "file-operation-error", "name": "文件操作异常线索", "status": "hit" if hit else "not_detected", "detail": "检查明确文件读取、包含或路径解析异常；合法文件操作失败也会产生相同错误，需人工确认输入可控性与授权边界。" + ("已识别文档或示例，不生成漏洞线索。" if document else "") + _LIMIT},
        {"id": "file-input-review", "name": "文件输入入口审查", "status": "inconclusive" if page.file_input else ("not_detected" if is_html else "not_applicable"), "detail": ("发现文件上传或下载类表单字段，仅提示人工审查；入口存在不代表漏洞。" if page.file_input else "未识别文件类表单字段；不覆盖脚本生成表单或 API 参数。") + _LIMIT},
    ]
    signals = [{"root": "file-operation-error", "title": "文件操作异常线索，待人工确认文件相关漏洞"}] if hit else []
    return checks, signals
