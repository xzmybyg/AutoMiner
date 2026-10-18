"""Display-only test coverage metadata; never grants execution permissions."""

from copy import deepcopy

_CATEGORIES = [
    ("injection", "注入漏洞", "被动错误线索及固定引号的 SQL 错误差异对照；不读取数据或验证盲注", "partial"),
    ("xss", "XSS 跨站脚本", "静态线索及惰性 HTML 标记的反射上下文对照，不执行脚本", "partial"),
    ("csrf", "CSRF 跨站请求伪造", "仅分析表单及 Cookie 防护线索，不验证服务端校验", "partial"),
    ("ssrf", "SSRF 服务端请求伪造", "仅分析已有响应中的请求错误与输入线索，不发送探测地址", "partial"),
    ("xxe", "XXE 外部实体注入", "仅分析外部实体解析异常与声明线索，不解析实体", "partial"),
    ("file", "文件相关漏洞", "仅分析文件操作错误与输入线索，不上传或读取文件", "partial"),
    ("deserialization", "反序列化漏洞", "仅分析反序列化错误，不加载对象或验证可利用性", "partial"),
    (
        "access_control",
        "越权漏洞",
        "逐对比较匿名与专用账号的成功响应，不自动确认越权",
        "partial",
    ),
    ("authentication", "认证/会话漏洞", "仅分析会话 Cookie 与认证配置线索，不测试登录或破解凭证", "partial"),
    (
        "information_disclosure",
        "敏感信息泄露",
        "分析已有响应中的敏感格式、凭证、源码与调试线索，不确认泄露影响",
        "partial",
    ),
    ("configuration", "配置错误", "仅分析响应策略、目录和调试配置线索", "partial"),
    ("supply_chain", "组件/供应链漏洞", "仅审查资源引用与组件线索，不进行依赖漏洞库验证", "partial"),
    ("business_logic", "逻辑漏洞", "仅审查业务输入，缺少规则与状态证据时需专项验证", "partial"),
    ("race_condition", "竞争条件", "仅分析已有并发冲突诊断，不进行并发测试，需时序证据", "partial"),
    ("memory_safety", "内存安全漏洞", "仅分析已有内存诊断，不触发崩溃或验证可利用性", "partial"),
    ("denial_of_service", "拒绝服务 DoS", "仅分析已有资源耗尽诊断，不压测或验证拒绝服务", "partial"),
    ("cryptography", "加密问题", "仅分析已有加密配置线索，不验证 TLS 或破解密文", "partial"),
    ("other_web", "其他 Web 漏洞", "仅分析已有 CORS、框架嵌入及重定向配置线索", "partial"),
]

_TEMPLATES = [
    {"id": "sql_error_verify", "title": "SQL 错误差异对照（主动只读）", "description": "用户指定 GET 参数，前后控制与单引号探针共 3 次匿名请求；只确认错误差异。", "category_ids": ["injection"]},
    {"id": "xss_reflection_verify", "title": "HTML 输入反射对照（主动只读）", "description": "惰性自定义标签与两次控制，共 3 次匿名 GET；不执行脚本，不判定 XSS 可利用。", "category_ids": ["xss"]},
    {"id": "redirect_verify", "title": "开放重定向对照（主动只读）", "description": "固定 .invalid 标记与两次控制，共 3 次匿名 GET；不跟随跳转。", "category_ids": ["other_web"]},
    {"id": "cors_verify", "title": "CORS 来源对照验证（主动只读）",
     "description": "同一授权接口进行基线与两个固定 Origin 的三次匿名 GET 对照；确认配置行为，敏感数据影响仍需人工确认。",
     "category_ids": ["other_web", "configuration"]},
    {"id": "access_verify", "title": "权限规则对照验证（主动只读）",
     "description": "基于明确的允许/禁止身份及合成 JSON 标记，对同一接口进行两次 GET；不枚举资源，行为复现仍需人工确认影响。",
     "category_ids": ["access_control"]},
    {"id": "disclosure_passive", "title": "敏感信息泄露线索（被动）",
     "description": "检查已有响应中的敏感格式与调试/源码线索，固定脱敏详情，需人工确认影响。",
     "category_ids": ["information_disclosure"]},
    {"id": "configuration_passive", "title": "配置错误线索（被动）",
     "description": "分析已有响应头、目录索引和调试配置线索，不确认可利用性。",
     "category_ids": ["configuration"]},
    {"id": "supply_chain_passive", "title": "组件/供应链线索（被动）",
     "description": "审查资源引用完整性和组件信息，不加载资源或查询漏洞库，不判断 CVE。",
     "category_ids": ["supply_chain"]},
    {"id": "business_logic_review", "title": "业务逻辑输入审查（需专项验证）",
     "description": "审查业务相关输入线索，不变更业务状态；需要业务规则与流程证据。",
     "category_ids": ["business_logic"]},
    {"id": "race_condition_review", "title": "竞争条件诊断线索（需专项验证）",
     "description": "分析已有并发冲突诊断，不并发请求或写入，无法确认竞态漏洞。",
     "category_ids": ["race_condition"]},
    {"id": "memory_safety_passive", "title": "内存安全诊断线索（被动）",
     "description": "分析已有内存诊断信息，不构造触发数据，不确认输入可控性。",
     "category_ids": ["memory_safety"]},
    {"id": "dos_passive", "title": "资源耗尽诊断线索（被动）",
     "description": "分析已有资源耗尽错误，不压测、不发送超大请求，无法确认 DoS。",
     "category_ids": ["denial_of_service"]},
    {"id": "crypto_passive", "title": "加密配置线索（被动）",
     "description": "审查已有加密使用或验证配置线索，不破解密文或进行 TLS 协商测试。",
     "category_ids": ["cryptography"]},
    {"id": "other_web_passive", "title": "其他 Web 配置线索（被动）",
     "description": "分析已有跨域、框架嵌入与重定向头，缺少上下文需人工复核。",
     "category_ids": ["other_web"]},
    {
        "id": "xxe_passive", "title": "XXE 外部实体线索（被动）",
        "description": "分析已有响应中的实体解析异常与声明；不解析实体、不读文件、不发起回连。",
        "category_ids": ["xxe"],
    },
    {
        "id": "file_passive", "title": "文件操作线索（被动）",
        "description": "分析文件操作异常及输入线索；不上传文件、不修改路径或读取额外内容。",
        "category_ids": ["file"],
    },
    {
        "id": "deserialization_passive", "title": "反序列化错误线索（被动）",
        "description": "分析已有反序列化异常；不加载对象或执行载荷，需人工确认。",
        "category_ids": ["deserialization"],
    },
    {
        "id": "auth_session_passive", "title": "认证/会话配置线索（被动）",
        "description": "检查疑似会话 Cookie 与认证配置，不尝试登录、破解或修改会话。",
        "category_ids": ["authentication"],
    },
    {
        "id": "xss_passive",
        "title": "XSS 静态线索（被动）",
        "description": "分析已有响应中的不可信来源与危险脚本操作；不执行脚本，结果需人工确认。",
        "category_ids": ["xss"],
    },
    {
        "id": "csrf_passive",
        "title": "CSRF 防护线索（被动）",
        "description": "分析表单和 Cookie 防护线索；不提交业务操作，无法据此确认服务端防护。",
        "category_ids": ["csrf"],
    },
    {
        "id": "ssrf_passive",
        "title": "SSRF 错误与输入线索（被动）",
        "description": "分析已有响应中的服务端请求错误与地址输入线索；不探测内网或发起回连。",
        "category_ids": ["ssrf"],
    },
    {
        "id": "injection_errors",
        "title": "注入错误线索（被动）",
        "description": "只读取原有 GET 响应的 SQL、模板和命令解析错误，不修改参数、不发送载荷，结果待人工确认。",
        "category_ids": ["injection"],
    },
    {
        "id": "baseline",
        "title": "响应基线检查",
        "description": "读取范围内 GET 响应，检查响应策略与敏感格式标记；不注入测试载荷。",
        "category_ids": ["configuration", "information_disclosure"],
    },
    {
        "id": "role_compare",
        "title": "越权线索：身份响应逐对比较",
        "description": "使用匿名与专用账号逐对比较成功响应；同角色不同账号也比较，结果需资源归属与权限矩阵人工确认。",
        "category_ids": ["access_control"],
    },
    {
        "id": "both",
        "title": "基线与身份对比",
        "description": "组合当前两种检查，仍遵守相同授权范围与任务请求预算。",
        "category_ids": ["configuration", "information_disclosure", "access_control"],
    },
]


def catalog():
    """Return an independent snapshot; planned categories have no executable tests."""
    active = ("cors_verify", "access_verify", "sql_error_verify", "xss_reflection_verify", "redirect_verify")
    return {
        "categories": [
            {"id": ident, "name": name, "description": description, "status": status}
            for ident, name, description, status in _CATEGORIES
        ],
        "templates": [dict(deepcopy(t),
            requests_per_endpoint=2 if t["id"] == "access_verify" else 3 if t["id"] in active else None if t["id"] in ("role_compare", "both") else 1,
            execution="active_verification" if t["id"] in active else "comparison" if t["id"] in ("role_compare", "both") else "passive",
            risk="low" if t["id"] in active else "read_only") for t in _TEMPLATES],
    }
