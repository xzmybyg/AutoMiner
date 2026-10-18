import { useEffect, useRef, useState } from "react";
import "./task-detail.css";
import TaskMonitor from "./TaskMonitor";
import { OfflineResults } from "./OfflineReview";

type Props = {
  state: Record<string, any[]>;
  api: (path: string, body?: unknown, method?: string) => Promise<any>;
  run: (fn: () => Promise<unknown>) => Promise<void>;
  busy: boolean;
  onReport: (targetId: string, jobId: string) => void;
  initialJobId?: string;
  targetId?: string;
};
const labels: Record<string, string> = {
  queued: "排队中",
  running: "运行中",
  completed: "已完成",
  blocked: "已阻断",
  stopped: "已停止",
  paused: "已暂停",
  reserved: "已预留，尚未发送",
  in_flight: "请求处理中",
  complete: "请求完成",
  failed: "请求失败",
  interrupted: "已中断",
  hit: "命中线索",
  not_detected: "未命中",
  not_applicable: "不适用",
  not_run: "未执行",
  inconclusive: "无法确定",
  baseline: "响应配置及敏感标记",
  cors_verify: "CORS 行为验证",
  sql_error_verify: "SQL 错误差异对照",
  xss_reflection_verify: "HTML 输入反射对照",
  redirect_verify: "开放重定向对照",
  control_a: "前控制请求",
  input_probe: "固定输入探针",
  control_b: "后控制请求",
  access_verify: "权限规则验证",
  behavior_confirmed: "行为已复现（待人工确认影响）",
  not_reproduced: "未复现",
  injection_errors: "注入错误线索（被动检查）",
  xss_passive: "XSS 静态线索（被动）",
  csrf_passive: "CSRF 防护线索（被动）",
  ssrf_passive: "SSRF 错误与输入线索（被动）",
  xxe_passive: "XXE 外部实体线索（被动）",
  file_passive: "文件操作线索（被动）",
  deserialization_passive: "反序列化错误线索（被动）",
  auth_session_passive: "认证/会话配置线索（被动）",
  disclosure_passive: "敏感信息泄露线索（被动）",
  configuration_passive: "配置错误线索（被动）",
  crypto_passive: "加密配置线索（被动）",
  supply_chain_passive: "组件/供应链线索（被动）",
  business_logic_review: "业务逻辑输入审查（需专项验证）",
  other_web_passive: "其他 Web 配置线索（被动）",
  race_condition_review: "竞争条件诊断线索（需专项验证）",
  memory_safety_passive: "内存安全诊断线索（被动）",
  dos_passive: "资源耗尽诊断线索（被动）",
  role_compare: "身份响应对比",
  both: "响应检查与身份对比",
  multiple: "多种检测",
  anonymous: "匿名",
  probe_a: "来源标记 A",
  probe_b: "来源标记 B",
  allowed: "应允许身份",
  denied: "应禁止身份",
  job_created: "任务已创建",
  job_started: "任务开始执行",
  job_completed: "任务执行结束",
  job_blocked: "任务被阻断",
  job_pause: "任务已暂停",
  job_stop: "任务已停止",
  request_reserved: "请求预算已预留",
  request_dispatched: "请求已发送",
  request_finished: "请求处理结束",
  check_completed: "检查结果已记录",
  monitor_enabled: "任务事件监测已开启",
  monitor_disabled: "任务事件监测已关闭",
  monitor_observed: "任务事件解读已保存",
  offline_review_completed: "离线专项审查完成",
  watching: "继续观察",
  finished: "监测结束",
};
const label = (value: string) => labels[value] || value;
const time = (value?: number) =>
  value ? new Date(value * 1000).toLocaleString() : "未记录";
function logDetail(entry: any) {
  if (entry.action === "check_completed") {
    try {
      const rows = JSON.parse(entry.detail);
      if (Array.isArray(rows))
        return rows.map((c) => `${c.name}：${label(c.status)}`).join("；");
    } catch {
      /* Older logs contain plain text. */
    }
  }
  return label(entry.detail);
}

const bodyStates: Record<string, string> = {
  empty: "空内容",
  absent: "无请求体",
  omitted_non_text: "非文本内容未保存",
  omitted_encoded: "压缩内容未解码保存",
  not_captured: "未采集",
  captured: "已保存脱敏内容",
  text: "已保存脱敏文本",
  omitted_binary: "二进制内容未保存",
  binary: "二进制内容未保存",
  not_sent: "请求未发送",
  unavailable: "未获取到内容",
  not_received: "未收到响应",
};
function ExchangePart({ title, part }: { title: string; part: any }) {
  if (!part) return <p className="muted">{title}信息未获取。</p>;
  const headers =
    typeof part.headers === "string"
      ? part.headers
      : Object.entries(part.headers || {})
          .map(([key, value]) => `${key}: ${String(value)}`)
          .join("\n");
  return (
    <section className="http-exchange-part" aria-label={title}>
      <h4>{title}</h4>
      <p className="http-start-line mono">
        {part.method
          ? `${part.method} ${part.url || ""}`
          : `HTTP ${part.status ?? "—"}`}
        {part.url_truncated && <span className="muted">（地址已截断）</span>}
      </p>
      <details className="http-content" open>
        <summary>
          {title}头
          {part.headers_truncated && <span className="muted"> · 已截断</span>}
          {part.headers_state === "not_captured" && (
            <span className="muted"> · 未采集</span>
          )}
        </summary>
        <pre>{headers || "无已记录的头信息"}</pre>
      </details>
      <details className="http-content" open>
        <summary>
          {title}体{" "}
          <span className="muted">
            · {bodyStates[part.body_state] || part.body_state || "未记录状态"}
            {typeof part.body_bytes === "number"
              ? ` · ${part.body_bytes} 字节`
              : ""}
            {part.truncated ? " · 已截断" : ""}
          </span>
        </summary>
        {typeof part.body === "string" && part.body.length > 0 ? (
          <pre>{part.body}</pre>
        ) : (
          <p className="muted">
            {part.body_state === "empty" || part.body_state === "absent"
              ? "（空）"
              : "没有可展示的文本内容。"}
          </p>
        )}
      </details>
    </section>
  );
}
function HttpExchange({ evidence }: { evidence: any }) {
  const exchange = evidence.http_exchange;
  if (!exchange)
    return (
      <p className="http-unavailable muted">
        此条历史证据未保存 HTTP
        请求与响应明细，无法补回当时的内容；新执行的请求会保存脱敏明细。
      </p>
    );
  return (
    <details className="http-exchange">
      <summary>查看 HTTP 请求与响应明细</summary>
      <p className="muted">
        本地保存的脱敏内容；文本正文最多{" "}
        {Math.round((exchange.capture_limit_bytes || 65536) / 1024)}{" "}
        KB，头信息另有上限。敏感字段已隐藏，截断或非文本内容会单独标记。
      </p>
      <div className="http-exchange-grid">
        <ExchangePart title="请求" part={exchange.request} />
        <ExchangePart title="响应" part={exchange.response} />
      </div>
    </details>
  );
}

export function TaskManager({
  state,
  api,
  run,
  busy,
  onReport,
  initialJobId,
  targetId,
}: Props) {
  const [jobs, setJobs] = useState<any[]>([]);
  const [selected, setSelected] = useState(initialJobId || "");
  const [scope, setScope] = useState(targetId ? "current" : "all");
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [page, setPage] = useState(0);
  const [detailView, setDetailView] = useState("overview");
  const filtered = jobs.filter(
    (j) =>
      (scope !== "current" || !targetId || j.target_id === targetId) &&
      (statusFilter === "all" || j.status === statusFilter) &&
      `${j.id} ${j.target_name}`.toLowerCase().includes(query.toLowerCase()),
  );
  const lastPage = Math.max(0, Math.ceil(filtered.length / 10) - 1);
  const currentPage = Math.min(page, lastPage);
  const [detail, setDetail] = useState<any>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [follow, setFollow] = useState(true);
  const bottom = useRef<HTMLDivElement>(null);
  // Keep polling independent of the parent's freshly-created api function.
  const apiRef = useRef(api);
  apiRef.current = api;
  useEffect(() => {
    let alive = true;
    async function refresh() {
      try {
        const rows = await apiRef.current("/jobs");
        if (alive) {
          setJobs(rows);
          setError("");
        }
      } catch (e) {
        if (alive) setError(String(e));
      }
    }
    void refresh();
    const timer = window.setInterval(refresh, 2500);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, [state.job]);
  useEffect(() => {
    if (!selected) {
      setDetail(null);
      setLoading(false);
      return;
    }
    let alive = true;
    setLoading(true);
    setDetail(null);
    async function refresh() {
      try {
        const value = await apiRef.current(`/jobs/${selected}`);
        if (alive) {
          setDetail(value);
          setError("");
        }
      } catch (e) {
        if (alive) setError(String(e));
      } finally {
        if (alive) setLoading(false);
      }
    }
    void refresh();
    const timer = window.setInterval(refresh, 2000);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, [selected]);
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [selected]);
  useEffect(() => {
    if (follow && detailView === "logs" && detail?.job?.status === "running")
      bottom.current?.scrollIntoView({ block: "nearest" });
  }, [detail?.logs?.length, follow, detailView]);
  async function refresh() {
    setJobs(await api("/jobs"));
    if (selected) setDetail(await api(`/jobs/${selected}`));
  }
  function checks(items: any[]) {
    return (
      <ul>
        {items.map((check, i) => (
          <li key={`${check.id}-${i}`}>
            <strong>{check.name}</strong> · {label(check.status)}
            <br />
            <span className="muted">{check.detail}</span>
          </li>
        ))}
      </ul>
    );
  }
  return (
    <>
      {selected && (
        <div className="task-detail-navigation" aria-label="任务详情导航">
          <button
            className="secondary"
            onClick={() => {
              setSelected("");
              setError("");
            }}
          >
            ← 返回任务列表
          </button>
          <button
            className="secondary"
            disabled={busy}
            onClick={() => void run(refresh)}
          >
            刷新详情
          </button>
        </div>
      )}
      {error && <p role="alert">加载失败：{error}</p>}
      {!selected && (
        <section className="panel">
          <div className="row">
            <h2>执行任务列表</h2>
            <button
              className="secondary"
              disabled={busy}
              onClick={() => void run(refresh)}
            >
              刷新任务列表
            </button>
          </div>
          {!jobs.length && (
            <p className="muted">暂无任务。先导入接口并创建测试任务。</p>
          )}
          <div className="filter-bar">
            <label>
              搜索任务
              <input
                type="search"
                placeholder="任务编号或目标名称"
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                  setPage(0);
                }}
              />
            </label>
            <label>
              目标
              <select
                value={scope}
                onChange={(e) => {
                  setScope(e.target.value);
                  setPage(0);
                }}
              >
                <option value="all">全部目标（含历史）</option>
                {targetId && <option value="current">当前目标</option>}
              </select>
            </label>
            <label>
              状态
              <select
                value={statusFilter}
                onChange={(e) => {
                  setStatusFilter(e.target.value);
                  setPage(0);
                }}
              >
                <option value="all">全部状态</option>
                {[
                  "queued",
                  "running",
                  "completed",
                  "blocked",
                  "stopped",
                  "paused",
                ].map((s) => (
                  <option key={s} value={s}>
                    {label(s)}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <div style={{ overflowX: "auto" }}>
            <table
              className="task-table"
              style={{ width: "100%", textAlign: "left" }}
            >
              <thead>
                <tr>
                  <th>任务 / 目标</th>
                  <th>创建时间</th>
                  <th>状态</th>
                  <th>请求预算</th>
                  <th>计划接口</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {filtered
                  .slice(currentPage * 10, currentPage * 10 + 10)
                  .map((job) => (
                    <tr key={job.id} aria-selected={selected === job.id}>
                      <td>
                        {job.name || job.id.slice(0, 12)}
                        {job.is_run && <small> · 一次检查</small>}
                        <br />
                        {job.target_name}
                      </td>
                      <td>{time(job.created_at)}</td>
                      <td>{label(job.status)}</td>
                      <td>
                        {job.used} / {job.request_budget}
                      </td>
                      <td>{job.interface_count}</td>
                      <td>
                        <button
                          className="secondary"
                          onClick={() => {
                            setDetailView("overview");
                            setSelected(job.id);
                          }}
                        >
                          查看详情
                        </button>
                        <button
                          className="secondary"
                          onClick={() => onReport(job.target_id, job.id)}
                        >
                          查看报告
                        </button>
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
          {!filtered.length && !!jobs.length && (
            <p className="empty">没有匹配的任务。</p>
          )}
          <div className="pagination">
            <span>
              共 {filtered.length} 项 · 第 {currentPage + 1}/{lastPage + 1} 页
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
        </section>
      )}
      {selected && loading && <p role="status">正在加载任务详情…</p>}
      {selected && detail && detail.job.id === selected && (
        <section className="panel task-detail-panel">
          <h2>{detail.job.name || "任务详情"} · {detail.job.id.slice(0, 12)}</h2>
          <p>
            {detail.job.target_name} · {label(detail.job.status)} · 已预留请求{" "}
            {detail.job.used} / {detail.job.request_budget}
          </p>
          {detail.job.is_run && <p className="muted">本次检查包含 {detail.steps?.length || 0} 个内部检测步骤，统一展示接口、日志、证据与报告。接口发现预留了 {detail.job.discovery_used || 0} 次请求，另行计入上方预算。</p>}
          <p className="muted">
            {detail.coverage_note} 下方日志每 2
            秒刷新。预算预留不等于请求已发送。
          </p>
          {detail.coverage && <div className="task-coverage" aria-label="任务覆盖情况">
            <span>计划接口 <strong>{detail.coverage.planned_endpoints}</strong></span>
            <span>已发请求接口 <strong>{detail.coverage.requested_endpoints}</strong></span>
            <span>未请求接口 <strong>{detail.coverage.not_requested_endpoints}</strong></span>
            <span>已发送 <strong>{detail.coverage.sent_requests}</strong> 次</span>
            <span>已完成 / 失败 <strong>{detail.coverage.completed_requests} / {detail.coverage.failed_requests}</strong></span>
            <span>待确认线索 <strong>{detail.findings.filter((f:any)=>f.status!=="verified"&&f.status!=="false_positive").length}</strong></span>
          </div>}
          {detail.job.error && <p role="alert">停止原因：{detail.job.error}</p>}
          {detail.job.offline_review && <details className="disclosure"><summary>专项审查结果与 13 类覆盖情况（{detail.job.offline_review.items.length} 条线索）</summary><OfflineResults result={detail.job.offline_review} /></details>}
          <TaskMonitor key={selected} jobId={selected} models={state.model || []} api={api} />
          {detail.job.is_run && <details className="task-endpoint">
            <summary>查看检测步骤明细（{detail.steps?.length || 0}）</summary>
            {(detail.steps || []).map((step: any) => <p key={step.id}>
              {step.test_types.map(label).join("、") || "已记录步骤"} · {label(step.status)} · 已预留 {step.used} 次请求
              <small className="muted"> · 步骤 {step.id.slice(0, 12)}</small>
            </p>)}
          </details>}
          <div className="task-detail-actions">
            <div className="task-control-actions">
              {["queued", "running"].includes(detail.job.status) && (
                <>
                  <button
                    className="secondary"
                    disabled={busy}
                    onClick={() =>
                      void run(async () => {
                        await api(`/jobs/${selected}/pause`, {});
                        await refresh();
                      })
                    }
                  >
                    暂停
                  </button>
                  <button
                    className="danger"
                    disabled={busy}
                    onClick={() =>
                      void run(async () => {
                        await api(`/jobs/${selected}/stop`, {});
                        await refresh();
                      })
                    }
                  >
                    停止任务
                  </button>
                </>
              )}
            </div>
            <button onClick={() => onReport(detail.job.target_id, selected)}>
              查看本任务报告（{detail.findings.length} 条发现）
            </button>
          </div>
          <div
            className="section-tabs task-detail-tabs"
            aria-label="任务详情视图"
          >
            <button className={detailView === "overview" ? "active" : "secondary"} aria-pressed={detailView === "overview"} onClick={()=>setDetailView("overview")}>检查概览</button>
            <button
              className={detailView === "interfaces" ? "active" : "secondary"}
              aria-pressed={detailView === "interfaces"}
              onClick={() => setDetailView("interfaces")}
            >
              接口与检查（{detail.endpoints.length}）
            </button>
            <button className={detailView === "verification" ? "active" : "secondary"} aria-pressed={detailView === "verification"} onClick={() => setDetailView("verification")}>
              验证与回放（{detail.verifications?.length || 0}）
            </button>
            <button
              className={detailView === "logs" ? "active" : "secondary"}
              aria-pressed={detailView === "logs"}
              onClick={() => setDetailView("logs")}
            >
              执行日志（{detail.logs.length}）
            </button>
            <button
              className={detailView === "audit" ? "active" : "secondary"}
              aria-pressed={detailView === "audit"}
              onClick={() => setDetailView("audit")}
            >
              审计记录（{detail.logs.length}）
            </button>
          </div>
          {detailView === "overview" && <>
            <h3>这次检查得到了什么？</h3>
            <p>{detail.job.status === "completed" ? "本次执行已结束，请结合覆盖范围查看结果。" : ["queued","running"].includes(detail.job.status) ? "检查正在进行，最近事件会自动更新。" : "本次检查未完整结束，请先查看停止原因和已保存证据。"}</p>
            <div className="task-coverage"><span>已确认发现 <strong>{detail.findings.filter((f:any)=>f.status==="verified").length}</strong></span><span>待确认线索 <strong>{detail.findings.filter((f:any)=>!["verified","false_positive"].includes(f.status)).length}</strong></span><span>未请求接口 <strong>{detail.coverage?.not_requested_endpoints || 0}</strong></span><span>失败请求 <strong>{detail.coverage?.failed_requests || 0}</strong></span></div>
            <p className="muted">检查结束不代表应用没有漏洞。被动线索与响应相同均需进一步确认；只读检查不覆盖业务写入、压力测试或所有漏洞类型。</p>
            <h3>接下来怎么做？</h3><p>{detail.job.error ? "检查授权、预算或账号凭证，处理停止原因后新建检查；已有证据已保留。" : detail.findings.length ? "打开检查结果，先查看已确认发现，再逐项核实待确认线索。" : "查看已检查接口与未覆盖范围；需要检查登录后功能时，先验证测试账号。"}</p>
            <h3>最近发生的事</h3>{detail.logs.slice(-5).map((entry:any)=><p key={entry.id}><small className="muted">{time(entry.at)}</small> · {label(entry.action)}</p>)}
            <div className="actions"><button onClick={()=>setDetailView("interfaces")}>查看检查了哪些接口</button><button onClick={()=>setDetailView("logs")}>查看实时事件</button></div>
          </>}
          {detailView === "verification" && <>
            <h3>验证结论与证据回放</h3>
            <p className="muted">“行为已复现”仅表示满足本次规则的响应行为，发现仍待人工确认。未复现或没有验证记录不代表接口安全。</p>
            {!detail.verifications?.length && <p className="empty">本任务尚无独立验证记录；被动线索不会自动升级为漏洞。</p>}
            {(detail.verifications || []).map((verification: any, index: number) => <article key={verification.id || index} className="task-endpoint">
              <h4>{label(verification.plugin_id)} · {label(verification.status)}</h4>
              <p>{verification.reason}</p>
              <p className="muted">接口：{detail.endpoints.find((e: any) => e.id === verification.endpoint_id)?.url || verification.endpoint_id || "见下方证据"}</p>
              <h4>判定条件</h4>
              <pre className="verification-criteria">{typeof verification.criteria === "string" ? verification.criteria : JSON.stringify(verification.criteria || {}, null, 2)}</pre>
              {!!verification.steps?.length && <ol>{verification.steps.map((step: any, i: number) => <li key={i}>{typeof step === "string" ? step : step.description || step.label || `${label(step.probe_label || "anonymous")} · ${step.account_id ? `专用账号 ${step.account_id.slice(0, 12)}` : "匿名身份"} · ${label(step.state || "not_run")}`}</li>)}</ol>}
              <h4>请求与响应对照</h4>
              {(verification.evidence_ids || []).map((id: string) => {
                const evidence = detail.endpoints.flatMap((e: any) => e.requests || []).find((e: any) => e.id === id);
                return <details className="task-evidence" key={id}><summary>证据 {id.slice(0, 12)} · {label(evidence?.probe_label || evidence?.role || "anonymous")} · HTTP {evidence?.status ?? "—"}</summary>
                  {evidence ? <><p className="muted">发送：{time(evidence.sent_at)} · {label(evidence.state)}</p>{verification.plugin_id === "access_verify" && <p>合成标记对照：{evidence.verification_marker_match === true ? "符合指定摘要" : evidence.verification_marker_match === false ? "不符合指定摘要" : "无法判断"}</p>}<HttpExchange evidence={evidence} /></> : <p className="muted">尚未取得该证据明细。</p>}
                </details>;
              })}
              <h4>验证局限</h4>
              <p className="muted">{Array.isArray(verification.limitations) ? verification.limitations.join("；") : verification.limitations || "仅适用于本次账号、规则与响应；实际权限及业务影响需人工确认。"}</p>
            </article>)}
          </>}
          {detailView === "interfaces" && (
            <>
              <h3>计划接口与实际请求</h3>
              {detail.endpoints.map((endpoint: any) => (
                <details key={endpoint.id} className="task-endpoint">
                  <summary>
                    {endpoint.method} {endpoint.url}
                    <span className="muted">
                      {" "}
                      · {endpoint.requests.length} 次记录
                    </span>
                  </summary>
                  <p className="muted">
                    测试内容：{endpoint.test_modes?.length ? endpoint.test_modes.map(label).join("、") : label(endpoint.test_mode)} · 实际请求证据{" "}
                    {endpoint.requests.length} 条
                  </p>
                  {endpoint.rationale && <p className="muted">测试理由：{endpoint.rationale}</p>}
                  {!endpoint.requests.length && (
                    <p>未请求：没有执行证据，不能视为已验证。</p>
                  )}
                  {endpoint.requests.map((e: any) => (
                    <details
                      className="task-evidence"
                      key={e.id}
                      open={endpoint.requests.length === 1}
                    >
                      <summary>
                        {e.probe_label ? `${label(e.probe_label)} · ` : ""}{label(e.role)} · {label(e.state)} · HTTP{" "}
                        {e.status ?? "—"} · {time(e.sent_at || e.at)}
                      </summary>
                      <p>
                        证据：{e.id}
                        <br />
                        预留：{time(e.at)}；发送：{time(e.sent_at)}；结束：
                        {time(e.completed_at)}
                        <br />
                        {e.error ? `请求错误：${e.error}` : ""}
                        {e.redirect_blocked ? " 重定向已阻断。" : ""}
                        {e.truncated ? " 响应已截断，覆盖不完整。" : ""}
                      </p>
                      <HttpExchange evidence={e} />
                      {e.checks?.length ? (
                        checks(e.checks)
                      ) : (
                        <p className="muted">
                          历史证据未记录逐项检查结果；不推断检查已通过。已记录命中：
                          {e.signals?.map((s: any) => s.title).join("；") ||
                            "无"}
                        </p>
                      )}
                    </details>
                  ))}
                  {checks(
                    detail.job_checks.filter(
                      (c: any) => c.endpoint_id === endpoint.id,
                    ),
                  )}
                </details>
              ))}
            </>
          )}
          {(detailView === "logs" || detailView === "audit") && (
            <>
              <h3>{detailView === "audit" ? "本任务审计记录" : "实时执行日志"}</h3>
              {detailView === "audit" && <p className="muted">仅显示本任务及其请求证据关联的审计记录，不包含同目标的其他任务。</p>}
              {detailView === "logs" && (
              <label className="check">
                <input
                  type="checkbox"
                  checked={follow}
                  onChange={(e) => setFollow(e.target.checked)}
                />
                自动滚动到最新日志
              </label>
              )}
              <div
                role="log"
                aria-label={detailView === "audit" ? "任务审计记录" : "任务执行日志"}
                className="task-live-log"
              >
                {!detail.logs.length && (
                  <p className="muted">暂无任务关联日志。</p>
                )}
                {detail.logs.map((entry: any) => (
                  <p key={entry.id}>
                    <span className="muted">{time(entry.at)}</span> ·{" "}
                    {label(entry.action)}
                    <br />
                    <small>{entry.subject}</small>
                    {entry.detail && <span> · {logDetail(entry)}</span>}
                    {detailView === "audit" && <small><br />审计 ID：{entry.id}<br />任务 ID：{entry.job_id || selected}</small>}
                  </p>
                ))}
                <div ref={bottom} />
              </div>
            </>
          )}
        </section>
      )}
    </>
  );
}
