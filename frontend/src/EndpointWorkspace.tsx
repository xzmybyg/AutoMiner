import { useEffect, useState } from "react";
import DiscoveryManager from "./DiscoveryManager";
import AccountManager from "./AccountManager";

const passiveModes = ["injection_errors", "xss_passive", "csrf_passive", "ssrf_passive", "xxe_passive", "file_passive", "deserialization_passive", "auth_session_passive", "disclosure_passive", "configuration_passive", "crypto_passive", "supply_chain_passive", "business_logic_review", "other_web_passive", "race_condition_review", "memory_safety_passive", "dos_passive"];
const inputModes = ["sql_error_verify", "xss_reflection_verify", "redirect_verify"];

type Props = {
  target: any;
  state: Record<string, any[]>;
  api: (path: string, body?: unknown, method?: string) => Promise<any>;
  run: (fn: () => Promise<unknown>) => Promise<void>;
  busy: boolean;
  onCreated: (jobId: string) => void;
};

export default function EndpointWorkspace({
  target,
  state,
  api,
  run,
  busy,
  onCreated,
}: Props) {
  const [view, setView] = useState("list");
  const [query, setQuery] = useState("");
  const [method, setMethod] = useState("all");
  const [page, setPage] = useState(0);
  const [picked, setPicked] = useState<string[]>([]);
  const [configure, setConfigure] = useState(false);
  const [document, setDocument] = useState("");
  const [importResult, setImportResult] = useState<any>(null);
  const [useAccounts, setUseAccounts] = useState(false);
  const [testMode, setTestMode] = useState("both");
  const [allowedIdentity, setAllowedIdentity] = useState("");
  const [deniedIdentity, setDeniedIdentity] = useState("");
  const [catalog, setCatalog] = useState<any>(null);
  const [catalogError, setCatalogError] = useState("");
  useEffect(() => { setAllowedIdentity(""); setDeniedIdentity(""); }, [target?.id]);
  useEffect(() => {
    if (configure)
      void api("/test-catalog")
        .then(setCatalog)
        .catch((e) => setCatalogError(String(e)));
  }, [configure]);
  const endpoints = state.endpoint.filter((e) => e.target_id === target?.id);
  const targetAccounts = state.account.filter(a => a.target_id === target?.id);
  const accounts = targetAccounts.filter(a => !a.credential_recovery_required).slice(0, 3);
  const filtered = endpoints.filter(
    (e) =>
      (method === "all" || e.method === method) &&
      e.url.toLowerCase().includes(query.toLowerCase()),
  );
  const lastPage = Math.max(0, Math.ceil(filtered.length / 15) - 1);
  const currentPage = Math.min(page, lastPage);
  const visible = filtered.slice(currentPage * 15, currentPage * 15 + 15);
  const selected = endpoints.filter(
    (e) => picked.includes(e.id) && e.executable && e.method === "GET",
  );
  const remaining = target
    ? Math.max(0, target.request_budget - target.used)
    : 0;
  const allowed =
    target?.verified &&
    !target.revoked &&
    !target.deleted &&
    target.kind !== "src" &&
    target.expires_at > Date.now() / 1000 &&
    remaining > 0;
  if (!target)
    return (
      <section className="empty">
        <h2>先选择一个目标</h2>
        <p>在上方选择目标，再发现接口或创建测试。</p>
      </section>
    );
  return (
    <>
      <div className="section-tabs" aria-label="接口工作区">
        {[
          ["list", `接口列表 · ${endpoints.length}`],
          ["discover", "发现与导入"],
          ["accounts", `账号与规则 · ${targetAccounts.length}`],
        ].map(([key, label]) => (
          <button
            key={key}
            aria-pressed={view === key}
            className={view === key ? "active" : "secondary"}
            onClick={() => setView(key)}
          >
            {label}
          </button>
        ))}
      </div>
      {view === "list" && (
        <section className="panel">
          <div className="row spread">
            <div>
              <h2>已登记接口</h2>
              <p className="muted">勾选需要测试的 GET 接口，其他方法仅记录。</p>
            </div>
            <div className="row">
              <button
                disabled={busy || !allowed}
                onClick={() => void run(async () => {
                  await api(`/targets/${target.id}/discoveries`, {
                    automatic: true,
                    request_budget: Math.min(20, remaining),
                    max_depth: 2,
                  });
                  setView("discover");
                })}
              >
                自动扫描接口
              </button>
              <button className="secondary" onClick={() => setView("discover")}>
                手工发现 / 导入
              </button>
            </div>
          </div>
          <div className="filter-bar">
            <label>
              搜索接口
              <input
                type="search"
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                  setPage(0);
                }}
                placeholder="输入路径或地址"
              />
            </label>
            <label>
              请求方法
              <select
                value={method}
                onChange={(e) => {
                  setMethod(e.target.value);
                  setPage(0);
                }}
              >
                <option value="all">全部方法</option>
                {[...new Set(endpoints.map((e) => e.method))]
                  .sort()
                  .map((m) => (
                    <option key={m}>{m}</option>
                  ))}
              </select>
            </label>
          </div>
          <div className="selection-bar">
            <span>
              已选 <strong>{selected.length}</strong> 个接口
            </span>
            <button
              className="secondary"
              disabled={
                !visible.some((e) => e.executable && e.method === "GET")
              }
              onClick={() =>
                setPicked((old) => [
                  ...new Set([
                    ...old,
                    ...visible
                      .filter((e) => e.executable && e.method === "GET")
                      .map((e) => e.id),
                  ]),
                ])
              }
            >
              选择本页 GET
            </button>
            <button
              className="secondary"
              disabled={!picked.length}
              onClick={() => {
                setPicked([]);
                setConfigure(false);
              }}
            >
              清空选择
            </button>
            <button
              disabled={busy || !allowed || !selected.length}
              onClick={() => setConfigure(true)}
            >
              配置并测试（{selected.length}）
            </button>
          </div>
          {!endpoints.length ? (
            <div className="empty">
              <p>还没有接口。从页面发现，或导入 OpenAPI / HAR 文件。</p>
              <button onClick={() => setView("discover")}>
                发现或导入接口
              </button>
            </div>
          ) : (
            <div className="table-scroll">
              <table className="compact-table">
                <thead>
                  <tr>
                    <th>选择</th>
                    <th>方法</th>
                    <th>接口地址</th>
                    <th>用途</th>
                  </tr>
                </thead>
                <tbody>
                  {visible.map((e) => (
                    <tr key={e.id}>
                      <td>
                        <input
                          type="checkbox"
                          aria-label={`选择 ${e.method} ${e.url}`}
                          disabled={!e.executable || e.method !== "GET"}
                          checked={picked.includes(e.id)}
                          onChange={(event) =>
                            setPicked((old) =>
                              event.target.checked
                                ? [...old, e.id]
                                : old.filter((id) => id !== e.id),
                            )
                          }
                        />
                      </td>
                      <td>
                        <span className="method-badge">{e.method}</span>
                      </td>
                      <td className="url-cell">{e.url}</td>
                      <td>
                        {e.executable && e.method === "GET"
                          ? "可测试"
                          : "仅记录"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!visible.length && <p className="empty">没有匹配的接口。</p>}
            </div>
          )}
          {!!endpoints.length && (
            <div className="pagination">
              <span>
                匹配 {filtered.length} 条 · 第 {currentPage + 1}/{lastPage + 1}{" "}
                页
              </span>
              <button
                className="secondary"
                disabled={!currentPage}
                onClick={() => setPage(currentPage - 1)}
              >
                上一页
              </button>
              <button
                className="secondary"
                disabled={currentPage >= lastPage}
                onClick={() => setPage(currentPage + 1)}
              >
                下一页
              </button>
            </div>
          )}
          {configure && (
            <section className="inset-panel" aria-label="测试配置">
              <div className="row spread">
                <h3>创建测试 · {selected.length} 个接口</h3>
                <button
                  className="secondary"
                  onClick={() => setConfigure(false)}
                >
                  收起
                </button>
              </div>
              <p className="muted">
                请仅选择只读接口及合成测试数据。新任务会在本机保存脱敏后的 HTTP
                请求与响应，正文有大小上限；云模型不接收这些正文。
              </p>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  const d = new FormData(e.currentTarget);
                  void run(async () => {
                    const verificationRules: Record<string, unknown> = {};
                    if (testMode === "access_verify") {
                      if (selected.length !== 1 || !allowedIdentity || allowedIdentity === deniedIdentity)
                        throw new Error("请选择一个接口，并指定两个不同身份。");
                      const bytes = new TextEncoder().encode(String(d.get("synthetic_value") || ""));
                      const digest = await crypto.subtle.digest("SHA-256", bytes);
                      const hash = Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("");
                      verificationRules[selected[0].id] = {
                        allowed_account_id: allowedIdentity, denied_account_id: deniedIdentity || null,
                        json_field: d.get("json_field"), expected_value_sha256: hash,
                      };
                    }
                    const job = await api("/jobs", {
                      target_id: target.id,
                      endpoint_ids: selected.map((e) => e.id),
                      endpoint_test_types: Object.fromEntries(
                        selected.map((e) => [e.id, testMode]),
                      ),
                      account_ids: testMode === "access_verify" ? [allowedIdentity, deniedIdentity].filter(Boolean)
                        : testMode === "cors_verify" || inputModes.includes(testMode) ? [] : useAccounts ? accounts.map((a) => a.id) : [],
                      verification_rules: verificationRules,
                      input_probe_rules: inputModes.includes(testMode) ? Object.fromEntries(selected.map(e => [e.id, { parameter: String(d.get("input_parameter") || ""), read_only_confirmed: d.get("input_readonly") === "on", synthetic_data_only: d.get("input_synthetic") === "on" }])) : {},
                      request_budget: Number(d.get("budget")),
                      duration_seconds: Number(d.get("duration")),
                    });
                    onCreated(job.id);
                  });
                }}
              >
                <div className="two">
                  <label>
                    测试内容
                    <select
                      value={testMode}
                      onChange={(e) => {
                        setTestMode(e.target.value);
                        if (e.target.value === "role_compare")
                          setUseAccounts(true);
                        if (passiveModes.includes(e.target.value) || ["cors_verify", "access_verify", ...inputModes].includes(e.target.value))
                          setUseAccounts(false);
                      }}
                    >
                      <option value="cors_verify">CORS 行为验证（主动 · 固定 3 次 GET）</option>
                      <option value="sql_error_verify">SQL 错误差异（主动 · 每接口 3 次 GET）</option>
                      <option value="xss_reflection_verify">XSS 输入反射／HTML 上下文（主动 · 每接口 3 次 GET）</option>
                      <option value="redirect_verify">开放重定向对照（主动 · 每接口 3 次 GET）</option>
                      <option value="access_verify" disabled={!accounts.length || selected.length !== 1}>权限规则验证（主动 · 单接口 2 次 GET）</option>
                      <option value="both">响应检查 + 身份响应对比</option>
                      <option value="baseline">响应安全配置与敏感标记</option>
                      <option value="injection_errors">
                        注入错误线索（仅已有响应，不发送载荷）
                      </option>
                      <option value="xss_passive">XSS 静态线索（被动）</option>
                      <option value="csrf_passive">CSRF 防护线索（被动）</option>
                      <option value="ssrf_passive">SSRF 错误与输入线索（被动）</option>
                      <option value="xxe_passive">XXE 外部实体线索（被动）</option>
                      <option value="file_passive">文件操作线索（被动）</option>
                      <option value="deserialization_passive">反序列化错误线索（被动）</option>
                      <option value="auth_session_passive">认证/会话配置线索（被动）</option>
                      <option value="disclosure_passive">敏感信息泄露线索（被动）</option>
                      <option value="configuration_passive">配置错误线索（被动）</option>
                      <option value="supply_chain_passive">组件/供应链线索（被动）</option>
                      <option value="business_logic_review">业务逻辑输入审查（需专项验证）</option>
                      <option value="race_condition_review">竞争条件诊断线索（需专项验证）</option>
                      <option value="memory_safety_passive">内存安全诊断线索（被动）</option>
                      <option value="dos_passive">资源耗尽诊断线索（被动）</option>
                      <option value="crypto_passive">加密配置线索（被动）</option>
                      <option value="other_web_passive">其他 Web 配置线索（被动）</option>
                      <option value="role_compare" disabled={!accounts.length}>
                        越权线索：身份响应逐对比较（需测试账号）
                      </option>
                    </select>
                  </label>
                </div>
                {testMode === "cors_verify" && <p className="muted">固定发送一次匿名基线请求与两次携带固定 Origin 标记的匿名 GET，只访问所选接口；不向其他地址发请求。不执行浏览器脚本，行为复现仍需人工判断实际影响。</p>}
                {inputModes.includes(testMode) && <fieldset className="inset-panel"><legend>固定输入对照配置</legend>
                  <p>前控制、固定探针、后控制，共 3 次匿名 GET。只向当前接口添加一个参数，不允许已有查询参数的接口，不修改主机、端口或路径。</p>
                  <label>只读测试参数名<input name="input_parameter" required pattern="[A-Za-z][A-Za-z0-9_]{0,63}" maxLength={64} placeholder={testMode === "redirect_verify" ? "例如：next" : "例如：q"} /></label>
                  {testMode === "sql_error_verify" && <p className="muted">使用随机合成标记与一个固定单引号进行错误对照。不查询数据、不做盲注；错误差异不能直接证明 SQL 注入可利用。</p>}
                  {testMode === "xss_reflection_verify" && <p className="muted">探针是无脚本、无事件处理器的自定义 HTML 标签。检查编码与反射上下文，不执行 JavaScript，不验证存储型或 DOM XSS。</p>}
                  {testMode === "redirect_verify" && <p className="muted">使用随机 .invalid 地址对照 Location；执行器不会跟随跳转，也不会解析或访问标记域名。</p>}
                  <label className="check"><input type="checkbox" name="input_readonly" required />我确认所选接口及参数为只读，不触发业务写入</label>
                  <label className="check"><input type="checkbox" name="input_synthetic" required />只使用专用测试环境和合成测试数据</label>
                </fieldset>}
                {testMode === "access_verify" && <fieldset className="inset-panel">
                  <legend>单接口权限规则与合成数据</legend>
                  <p className="muted">仅比较两个身份对当前接口的 GET 响应，不修改资源编号。预期字符串仅在本机转为 SHA-256 摘要后提交，不保存原值。请使用专用账号与合成数据。</p>
                  <div className="two">
                    <label>应允许访问的测试账号<select required value={allowedIdentity} onChange={e => setAllowedIdentity(e.target.value)}><option value="">请选择</option>{accounts.map(a => <option key={a.id} value={a.id}>{a.name || a.role || a.id.slice(0, 12)}</option>)}</select></label>
                    <label>应禁止访问的身份<select value={deniedIdentity} onChange={e => setDeniedIdentity(e.target.value)}><option value="">匿名身份</option>{accounts.map(a => <option key={a.id} value={a.id} disabled={a.id === allowedIdentity}>{a.name || a.role || a.id.slice(0, 12)}</option>)}</select></label>
                    <label>顶层 JSON 字段名<input name="json_field" required pattern="[A-Za-z][A-Za-z0-9_]{0,63}" placeholder="例如：test_marker" /></label>
                    <label>预期合成字符串<input name="synthetic_value" required autoComplete="off" placeholder="仅使用合成测试标记" /></label>
                  </div>
                  {allowedIdentity && deniedIdentity === allowedIdentity && <p role="alert">允许与禁止身份不能是同一账号。</p>}
                  {selected.length !== 1 && <p role="alert">权限规则验证仅支持单个接口，请调整勾选。</p>}
                </fieldset>}
                {testMode === "injection_errors" && (
                  <p className="muted">
                    仅检查现有匿名 GET 响应中的 SQL、模板和命令解析错误文本；
                    不修改参数，不验证注入可利用性。命中需人工确认，未命中不代表安全。
                  </p>
                )}
                {passiveModes.includes(testMode) && testMode !== "injection_errors" && (
                  <p className="muted">
                    仅分析现有匿名 GET 响应；不执行脚本、不提交表单、不读取额外文件、不加载序列化对象、不发起回连探测。
                    静态线索不能证明存在漏洞，未命中也不代表安全，结果需人工确认。
                  </p>
                )}
                {["business_logic_review", "race_condition_review", "memory_safety_passive", "dos_passive"].includes(testMode) && <p className="muted">此项仅审查已有输入或运行诊断，无法通过单次响应确认业务逻辑、竞争条件、内存安全或 DoS 漏洞。缺少业务规则、时序或运行证据时标为需专项验证，不执行并发写入、压测或破坏性测试。</p>}
                {testMode === "role_compare" && <p className="muted">使用匿名身份与专用账号逐对比较成功响应，也比较同角色的不同账号。相同摘要仅为线索；公开资源也可能相同，仍需资源归属与业务权限矩阵人工确认。不会修改资源标识或枚举用户数据。</p>}
                <div className="two">
                  <label>
                    请求预算（剩余 {remaining} 次）
                    <input
                      name="budget"
                      type="number"
                      min={1}
                      max={Math.min(500, remaining) || 1}
                      defaultValue={Math.min(20, remaining) || 1}
                      required
                    />
                  </label>
                  <label>
                    最长时间（秒）
                    <input
                      name="duration"
                      type="number"
                      min={10}
                      max={1800}
                      defaultValue={120}
                      required
                    />
                  </label>
                </div>
                <label className="check">
                  <input
                    type="checkbox"
                    checked={useAccounts}
                    disabled={!accounts.length || !["both", "role_compare"].includes(testMode)}
                    onChange={(e) => setUseAccounts(e.target.checked)}
                  />
                  使用已保存的测试账号（{accounts.length} 个）
                </label>
                <p className="muted">
                  计划最多{" "}
                  {selected.length * (testMode === "cors_verify" || inputModes.includes(testMode) ? 3 : testMode === "access_verify" ? 2 : 1 + (useAccounts && ["both", "role_compare"].includes(testMode) ? accounts.length : 0))}{" "}
                  次请求；达到预算会停止。不会自动扩大预算。
                </p>
                <button
                  disabled={
                    busy ||
                    !allowed ||
                    !selected.length ||
                    (testMode === "role_compare" && !useAccounts) ||
                    (testMode === "access_verify" && (selected.length !== 1 || !allowedIdentity || allowedIdentity === deniedIdentity))
                  }
                >
                  创建任务并查看进度
                </button>
              </form>
              <details className="disclosure">
                <summary>测试覆盖与后续分类</summary>
                <p className="muted">
                  当前只开放固定只读模板。分类目录用于后续扩展，不表示已支持对应漏洞的检测或利用。
                </p>
                {catalogError && (
                  <p role="alert">分类目录加载失败：{catalogError}</p>
                )}
                {catalog?.categories?.map((c: any) => (
                  <p key={c.id}>
                    <strong>{c.name}</strong> ·{" "}
                    {c.status === "planned" ? "规划中" : "部分覆盖"}
                    <br />
                    <span className="muted">{c.description}</span>
                  </p>
                ))}
              </details>
            </section>
          )}
          {!allowed && (
            <p className="muted">
              当前目标尚未通过有效授权验证，或请求预算已用尽。
            </p>
          )}
        </section>
      )}
      {view === "discover" && (
        <>
          <DiscoveryManager target={target} api={api} run={run} busy={busy} onViewList={() => setView("list")} />
          <details className="panel disclosure">
            <summary>从文件或文本导入接口</summary>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                const d = new FormData(e.currentTarget);
                void run(async () => {
                  const result = await api(`/targets/${target.id}/imports`, {
                    format: d.get("format"),
                    document: JSON.parse(document),
                  });
                  setImportResult(result);
                });
              }}
            >
              <div className="two">
                <label>
                  格式
                  <select name="format">
                    <option value="openapi">OpenAPI JSON</option>
                    <option value="har">浏览器 HAR</option>
                    <option value="manual">手工请求 JSON</option>
                  </select>
                </label>
                <label>
                  读取本地 JSON / HAR 文件
                  <input
                    type="file"
                    accept=".json,.har"
                    onChange={(e) => {
                      const file = e.target.files?.[0];
                      if (file)
                        void run(async () => {
                          if (file.size > 2_000_000)
                            throw new Error("文件不能超过 2MB");
                          setDocument(await file.text());
                        });
                    }}
                  />
                </label>
              </div>
              <label>
                文件内容或手工粘贴
                <textarea
                  rows={6}
                  value={document}
                  onChange={(e) => setDocument(e.target.value)}
                  required
                  placeholder={
                    '{"requests":[{"method":"GET","url":"http://localhost:5177/"}]}'
                  }
                />
              </label>
              <button disabled={busy}>检查范围并导入</button>
            </form>
            {importResult && (
              <div role="status">
                <p>
                  新增 {importResult.imported.length} 个接口，拒绝{" "}
                  {importResult.rejected.length} 个；已存在的接口自动跳过。
                </p>
                <button className="secondary" onClick={() => setView("list")}>
                  返回接口列表
                </button>
                {!!importResult.rejected.length && (
                  <details>
                    <summary>查看拒绝原因</summary>
                    {importResult.rejected.map((r: any, i: number) => (
                      <p key={i} className="url-cell">
                        {r.url} · {r.reason}
                      </p>
                    ))}
                  </details>
                )}
              </div>
            )}
          </details>
        </>
      )}
      {view === "accounts" && (
        <section className="panel">
          <AccountManager target={target} accounts={targetAccounts} api={api} run={run} busy={busy} />
          <details className="disclosure">
            <summary>业务流程 / SRC 规则存档</summary>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                const d = new FormData(e.currentTarget);
                void run(() =>
                  api(
                    `/targets/${target.id}/workflow`,
                    JSON.parse(String(d.get("rules"))),
                  ),
                );
              }}
            >
              <label>
                角色权限、流程与合成数据约束 JSON
                <textarea
                  name="rules"
                  rows={5}
                  required
                  defaultValue={
                    '{"roles":{"reader":["public"]},"steps":["login","read"],"synthetic_data_only":true}'
                  }
                />
              </label>
              <button disabled={busy}>保存规则版本</button>
            </form>
          </details>
        </section>
      )}
    </>
  );
}
