"""Collect narrowly scoped form review hints; never assert a business rule violation."""

from html.parser import HTMLParser


_LIMIT = "仅分析已有 HTML，不提交表单或修改业务状态；缺少业务规则、资源归属、角色权限及状态约束，不能判断逻辑漏洞。"
_FIELDS = {"price", "unit_price", "total_price", "amount", "discount", "role", "role_id", "is_admin", "user_id", "owner_id", "account_id", "step", "workflow_step", "order_status", "payment_status"}


class _Forms(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.inert = 0
        self.form = False
        self.hint = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in {"template", "pre", "code"}:
            self.inert += 1
        if self.inert:
            return
        if tag == "form":
            self.form = True
        if tag == "input" and self.form and (attrs.get("type") or "").lower() == "hidden":
            self.hint |= (attrs.get("name") or "").lower() in _FIELDS

    def handle_endtag(self, tag):
        if tag in {"template", "pre", "code"} and self.inert:
            self.inert -= 1
        if tag == "form" and not self.inert:
            self.form = False


def inspect_response(body: str, headers: dict):
    check = {"id": "logic-client-fields", "name": "业务敏感隐藏字段审查", "status": "not_detected", "detail": ""}
    if not isinstance(body, str) or not isinstance(headers, dict):
        check.update(status="inconclusive", detail="响应格式不完整。" + _LIMIT)
        return [check], []
    h = {str(k).lower(): str(v) for k, v in headers.items()}
    if h.get("content-type", "").split(";", 1)[0].strip().lower() not in {"text/html", "application/xhtml+xml"}:
        check.update(status="not_applicable", detail="响应不是 HTML 表单。" + _LIMIT)
        return [check], []
    page = _Forms()
    page.feed(body[:1024 * 1024])
    check.update(status="inconclusive" if page.hint or len(body) > 1024 * 1024 else "not_detected", detail=("表单含价格、身份或流程相关隐藏字段；字段存在是正常实现也可能具有的特征，需核对服务端独立计算、资源归属与状态校验。" if page.hint else "未识别指定业务隐藏字段；不推断其他业务流程安全性。") + ("仅分析前 1 MiB。" if len(body) > 1024 * 1024 else "") + _LIMIT)
    return [check], []
