"""Passive crypto configuration clues, without TLS negotiation or code execution."""

import re

_DOCUMENT = re.compile(r"\b(?:example|documentation|tutorial|sample code)\b|示例|教程|文档", re.I)
_WEAK = re.compile(r'''(?:password|passwd|secret)[^\r\n]{0,60}(?:hashlib\.(?:md5|sha1)\s*\(|(?:md5|sha1)\s*\()|(?:hashlib\.(?:md5|sha1)\s*\(|(?:md5|sha1)\s*\()[^\r\n]{0,60}(?:password|passwd|secret)|(?:DES|ARC4)\.new\s*\(|(?:AES\.new\([^\r\n]{0,100}MODE_ECB)''', re.I)
_DISABLED = re.compile(r'''(?:requests\.(?:get|post|request)\s*\([^\r\n]{0,180}verify\s*=\s*False)|(?:CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)\b)|(?:rejectUnauthorized\s*:\s*false\b)|(?:ssl\._create_unverified_context\s*\()''', re.I)
_ERROR = re.compile(r"CERTIFICATE_VERIFY_FAILED|unable to verify the first certificate|certificate has expired", re.I)
_LIMIT = "仅分析已有响应，不执行代码、不协商 TLS、不获取或校验证书；不能确认代码被运行、实际使用的密码算法或证书状态，待人工确认。未命中不代表安全。"


def inspect_response(body: str, headers: dict):
    mime = next((v for k, v in headers.items() if isinstance(k, str) and k.lower() == "content-type" and isinstance(v, str)), "").split(";", 1)[0].strip().lower()
    applicable = mime.startswith("text/") or mime in {"application/json", "application/xml", "application/xhtml+xml", "application/javascript"} or mime.endswith(("+json", "+xml"))
    valid = isinstance(body, str)
    document = valid and bool(_DOCUMENT.search(body))
    checks, signals = [], []
    for key, name, pattern in [("crypto-weak-usage", "弱算法相关代码线索", _WEAK), ("crypto-verification-disabled", "证书验证禁用代码线索", _DISABLED), ("crypto-certificate-error", "证书验证异常线索", _ERROR)]:
        hit = applicable and valid and not document and bool(pattern.search(body))
        status = "not_applicable" if not applicable else "inconclusive" if not valid or hit else "not_detected"
        checks.append({"id": key, "name": name, "status": status, "detail": ("文档或示例已忽略。" if document else "仅识别明确调用上下文或错误标记，算法名称本身不构成线索。") + _LIMIT})
        if hit:
            signals.append({"root": key, "title": name + "，待人工确认"})
    return checks, signals
