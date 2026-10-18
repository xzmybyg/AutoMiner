"""Review existing HTML dependency references without fetching or executing them."""

import re
import base64
import binascii
from html.parser import HTMLParser
from urllib.parse import urlsplit


_LIMIT = "仅分析已有响应，不下载资源、不执行脚本、不查询外部漏洞库；SRI 不保证组件安全，版本线索不证明存在 CVE，未命中不代表安全。"
_MAX = 1024 * 1024


def _valid_sri(integrity):
    for token in integrity.split():
        algorithm, separator, digest = token.partition("-")
        size = {"sha256": 32, "sha384": 48, "sha512": 64}.get(algorithm)
        if not separator or not size:
            continue
        try:
            if len(base64.b64decode(digest, validate=True)) == size:
                return True
        except (ValueError, binascii.Error):
            pass
    return False


class _Resources(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.inert = 0
        self.external = self.unpinned = self.plain = self.version = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in {"template", "pre", "code"}:
            self.inert += 1
        if self.inert:
            return
        if tag == "meta" and (attrs.get("name") or "").lower() == "generator":
            self.version |= bool(re.search(r"\b\d+\.\d+(?:\.\d+)?\b", attrs.get("content") or ""))
        if tag != "script" or not attrs.get("src"):
            return
        src = attrs["src"].strip()
        try:
            url = urlsplit(src)
        except ValueError:
            return
        # Origin is unavailable here: absolute references may still be same-origin.
        remote = bool(url.netloc) and url.scheme in {"", "http", "https"}
        self.external |= remote
        integrity = attrs.get("integrity") or ""
        valid_sri = _valid_sri(integrity)
        self.unpinned |= remote and not valid_sri
        self.plain |= remote and url.scheme == "http"
        self.version |= bool(re.search(r"(?:[.@/_-]|version=|v=)v?\d+\.\d+(?:\.\d+)?(?:[./?&#_-]|$)", src))

    def handle_endtag(self, tag):
        if tag in {"template", "pre", "code"} and self.inert:
            self.inert -= 1


def inspect_response(body: str, headers: dict):
    definitions = [("supply-script-integrity", "脚本资源完整性审查"), ("supply-http-script", "HTTP 脚本资源审查"), ("supply-component-version", "组件版本线索审查")]
    checks = [{"id": key, "name": name, "status": "not_detected", "detail": ""} for key, name in definitions]
    if not isinstance(body, str) or not isinstance(headers, dict):
        for c in checks:
            c.update(status="inconclusive", detail="响应格式不完整。" + _LIMIT)
        return checks, []
    h = {str(k).lower(): str(v) for k, v in headers.items()}
    if h.get("content-type", "").split(";", 1)[0].strip().lower() not in {"text/html", "application/xhtml+xml"}:
        for c in checks:
            c.update(status="not_applicable", detail="响应不是 HTML。" + _LIMIT)
        return checks, []
    parser = _Resources()
    parser.feed(body[:_MAX])
    flags = [parser.unpinned, parser.plain, parser.version]
    details = ["绝对脚本地址未包含可识别 SRI；缺少页面来源，不能确定是否跨源，需审查来源与完整性策略。", "发现显式 HTTP 脚本引用；需结合页面协议及浏览器混合内容阻断核实。", "发现组件版本格式，仅用于依赖清单核对，需可信组件身份及漏洞公告后另行确认。"]
    for c, flag, detail in zip(checks, flags, details):
        c.update(status="inconclusive" if flag or len(body) > _MAX else "not_detected", detail=(detail if flag else "未识别相关资源线索。") + ("仅分析前 1 MiB。" if len(body) > _MAX else "") + _LIMIT)
    return checks, []
