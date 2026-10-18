import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";
import "./report.css";
import ModelManager from "./ModelManager";
import AutoScanPanel from "./AutoScanPanel";
import TargetManager from "./TargetManager";
import { TaskManager } from "./TaskManager";
import EndpointWorkspace from "./EndpointWorkspace";
import AccountManager from "./AccountManager";
import GuidedCheck from "./GuidedCheck";
import OfflineReview from "./OfflineReview";
import SubmissionReport from "./SubmissionReport";
import { WorkspaceIcon } from "./WorkspaceIcon";
import ReadableReport from "./ReadableReport";

declare global {
  interface Window {
    pywebview?: { api: { session_token: () => Promise<string> } };
  }
}

type Row = { id: string; [key: string]: any };
type State = Record<string, Row[]>;
const empty: State = Object.fromEntries(
  [
    "target",
    "endpoint",
    "account",
    "job",
    "finding",
    "evidence",
    "model",
    "proposal",
    "workflow",
    "auto_scan",
    "scan_run",
    "audit",
  ].map((k) => [k, []]),
);
const labels: Record<string, string> = {
  queued: "排队中",
  running: "运行中",
  completed: "已完成",
  blocked: "已阻断",
  paused: "已暂停",
  stopped: "已停止",
  pending: "待验证",
  verified: "已验证",
  false_positive: "误报",
  lead: "线索",
  in_flight: "请求处理中",
  reserved: "预算已预留",
  interrupted: "执行已中断",
  complete: "证据完整",
  failed: "请求失败",
};
function ManualEvidence({
  selected,
  busy,
  submit,
}: {
  selected: string;
  busy: boolean;
  submit: (data: unknown) => void;
}) {
  return (
    <section className="panel">
      <h2>导入人工证据 / SRC 报告素材</h2>
      <p className="muted">
        仅整理已有证据，不向目标发送请求。请在提交前去除个人信息与业务秘密。
      </p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          submit(Object.fromEntries(new FormData(e.currentTarget).entries()));
        }}
      >
        <div className="two">
          <label>
            发现标题
            <input name="title" minLength={3} maxLength={200} required />
          </label>
          <label>
            根因标识（用于去重）
            <input name="root_cause" minLength={3} maxLength={200} required />
          </label>
        </div>
        <label>
          前置条件
          <textarea
            name="preconditions"
            minLength={5}
            maxLength={2000}
            required
          />
        </label>
        <label>
          最小复现步骤
          <textarea name="steps" minLength={10} maxLength={4000} required />
        </label>
        <label>
          已脱敏的观察结果
          <textarea
            name="observation"
            minLength={10}
            maxLength={4000}
            required
          />
        </label>
        <button disabled={busy || !selected}>保存为待验证发现</button>
      </form>
    </section>
  );
}
function App() {
  const [token, setToken] = useState(sessionStorage.getItem("token") || "");
  const [desktop, setDesktop] = useState(false);
  useEffect(() => {
    const connect = () => {
      if (window.pywebview)
        window.pywebview.api
          .session_token()
          .then((value) => {
            sessionStorage.setItem("token", value);
            setToken(value);
            setDesktop(true);
            fetch("/api/desktop-ready", {
              method: "POST",
              headers: { "X-API-Key": value },
            }).catch(() => {});
          })
          .catch(() => setError("桌面会话连接失败，请关闭应用后重新打开。"));
    };
    connect();
    window.addEventListener("pywebviewready", connect);
    return () => window.removeEventListener("pywebviewready", connect);
  }, []);
  const [state, setState] = useState<State>(empty),
    [tab, setTab] = useState("targets"),
    [selected, setSelected] = useState(""),
    [error, setError] = useState(""),
    [notice, setNotice] = useState(""),
    [busy, setBusy] = useState(false);
  const [storage, setStorage] = useState<any>(null);
  useEffect(() => { setStorage(null); if (token) void api("/health").then(setStorage).catch(() => {}); }, [token]);
  const [appsView, setAppsView] = useState("targets");
  const [advancedChecks, setAdvancedChecks] = useState(false);
  const [preview, setPreview] = useState("");
  const [taskView, setTaskView] = useState("tasks");
  const [focusJob, setFocusJob] = useState("");
  const [taskVisit, setTaskVisit] = useState(0);
  useEffect(() => {
    window.scrollTo(0, 0);
    setNotice("");
    setError("");
    setPreview("");
  }, [tab]);
  const [reportJob, setReportJob] = useState<string | null>(null);
  const [reportView, setReportView] = useState<"easy" | "technical" | "submission">("easy");
  const reportTask = [...state.job, ...state.scan_run, ...state.auto_scan].find((j) => j.id === reportJob);
  const reportTargetId = reportTask?.target_id || selected;
  const reportTarget = state.target.find((t) => t.id === reportTargetId);
  const reportEvidenceIds = new Set(
    state.evidence.filter((e) => (reportTask?.job_ids || [reportJob]).includes(e.job_id)).map((e) => e.id),
  );
  const visibleFindings = state.finding.filter(
    (f) =>
      (!reportTargetId || f.target_id === reportTargetId) &&
      (!reportJob ||
        f.evidence_ids.some((id: string) => reportEvidenceIds.has(id))),
  );
  function openJobReport(_targetId: string, jobId: string) {
    setReportJob(jobId);
    setTab("findings");
  }

  async function api(path: string, body?: unknown, method = "POST") {
    const response = await fetch("/api" + path, {
      method: body === undefined && method === "POST" ? "GET" : method,
      headers: { "X-API-Key": token, "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!response.ok) {
      const data = await response
        .json()
        .catch(() => ({ detail: response.statusText }));
      throw new Error(
        typeof data.detail === "string"
          ? data.detail
          : JSON.stringify(data.detail),
      );
    }
    return response.json();
  }
  async function refresh() {
    if (token) {
      const next: State = await api("/state");
      setState(next);
      setSelected((current) =>
        next.target.some((t) => t.id === current && !t.revoked && !t.deleted)
          ? current
          : "",
      );
    }
  }
  async function run(fn: () => Promise<unknown>) {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await fn();
      await refresh();
      setNotice("操作已完成");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }
  useEffect(() => {
    refresh().catch((e) => setError(String(e)));
    const timer = setInterval(() => refresh().catch(() => {}), 4000);
    return () => clearInterval(timer);
  }, [token]);
  const selectableTargets = state.target.filter(
    (t) => !t.revoked && !t.deleted,
  );
  const target = selectableTargets.find((t) => t.id === selected),
    endpoints = state.endpoint.filter((e) => e.target_id === selected);
  const fields = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    return Object.fromEntries(
      new FormData(
        event.currentTarget,
        (event.nativeEvent as SubmitEvent).submitter,
      ).entries(),
    ) as Record<string, string>;
  };
  const requestList = () =>
    endpoints.filter((e) => e.executable).map((e) => e.id);
  async function download(format: string) {
    const r = await fetch(
      `/api/targets/${reportTargetId}/report?format=${format}&audience=${reportView}${reportJob ? "&job_id=" + encodeURIComponent(reportJob) : ""}`,
      {
        headers: { "X-API-Key": token },
      },
    );
    if (!r.ok) throw new Error("导出失败");
    const url = URL.createObjectURL(await r.blob());
    const a = document.createElement("a");
    a.href = url;
    a.download = `report-${reportView}.` + format;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  async function downloadAutoReport(id: string) {
    const response = await fetch(`/api/auto-scans/${encodeURIComponent(id)}/report`, {
      headers: { "X-API-Key": token },
    });
    if (!response.ok) throw new Error("完整流程报告尚未生成或无法导出");
    const url = URL.createObjectURL(await response.blob());
    const link = document.createElement("a");
    link.href = url;
    link.download = `auto-flow-${id.slice(0, 12)}.md`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  return (
    <div className="shell">
      <aside>
        <a className="brand" href="#">
          <span className="brand-mark">
            <WorkspaceIcon name="shield" />
          </span>
          <span>
            AutoMiner<small>授权安全工作台</small>
          </span>
        </a>
        <nav>
          {[
            ["targets", "我的应用"],
            ["testing", "开始检查"],
            ["jobs", "检查记录"],
            ["findings", "检查结果"],
            ["models", "设置"],
          ].map(([key, title]) => (
            <button
              className={tab === key ? "active" : ""}
              onClick={() => {
                if (key === "jobs") {
                  setFocusJob("");
                  setTaskView("tasks");
                  setTaskVisit((value) => value + 1);
                }
                setTab(key);
              }}
              key={key}
            >
              <WorkspaceIcon name={key} />
              {title}
            </button>
          ))}
        </nav>
        <div className="aside-foot">
          <span className="dot" /> 本地单用户环境<p>所有测试受授权策略约束</p>
          <button
            onClick={() => run(() => api("/emergency-stop", {}))}
            className="danger"
            disabled={busy}
          >
            紧急停止全部任务
          </button>
        </div>
      </aside>
      <main>
        <header>
          <div>
            <p className="eyebrow">本地授权测试</p>
            <h1>
              {
                {
                  overview: "让每一次测试，都有明确边界。",
                  targets: "我的应用",
                  testing: "开始检查",
                  jobs: "检查记录",
                  models: "设置",
                  findings: "检查结果",
                  audit: "每一次执行，都有记录。",
                }[tab]
              }
            </h1>
          </div>
          <span className="badge">仅靶场 · 本人应用</span>
        </header>
        <section className="connection">
          {desktop ? (
            <span className="connection-status">
              <span className="dot" />
              本地服务已连接
            </span>
          ) : (
            <label>
              本地访问密钥
              <input
                type="password"
                value={token}
                onChange={(e) => {
                  setToken(e.target.value);
                  sessionStorage.setItem("token", e.target.value);
                }}
                placeholder="输入 APP_TOKEN"
                autoComplete="off"
              />
            </label>
          )}
          <label>
            当前目标
            <select
              value={selected}
              onChange={(e) => {
                setSelected(e.target.value);
                setReportJob(null);
                setPreview("");
              }}
            >
              <option value="">选择授权目标</option>
              {selectableTargets.map((t) => (
                <option value={t.id} key={t.id}>
                  {t.name} · #{t.hash?.slice(0, 12) || t.id.slice(0, 12)}
                </option>
              ))}
            </select>
          </label>
          {target && (
            <span className="target-status">
              {target.verified && target.expires_at > Date.now() / 1000
                ? "已验证"
                : "待验证 / 已过期"}{" "}
              · 剩余 {Math.max(0, target.request_budget - target.used)} 次
            </span>
          )}
          <button onClick={() => run(refresh)} disabled={busy}>
            <WorkspaceIcon name="refresh" />
            刷新
          </button>
        </section>
        {storage?.data_directory && <details className="disclosure"><summary>当前数据位置 · {storage.storage_id?.slice(0, 12) || "历史版本"}</summary><p>数据目录：<code>{storage.data_directory}</code></p><p className="muted">所有目标、账号、任务与报告使用这个工作库。启动时自动备份到该目录的 backups 文件夹。</p></details>}
        {error && (
          <p role="alert" className="error">
            {error}
          </p>
        )}
        {notice && (
          <p role="status" className="notice">
            {notice}
          </p>
        )}
        {tab === "targets" && <div className="section-tabs" aria-label="我的应用视图"><button aria-pressed={appsView==="targets"} className={appsView==="targets"?"active":"secondary"} onClick={()=>setAppsView("targets")}>应用列表</button><button disabled={!target} aria-pressed={appsView==="accounts"} className={appsView==="accounts"?"active":"secondary"} onClick={()=>setAppsView("accounts")}>测试账号</button></div>}
        {tab === "targets" && appsView === "targets" && (
          <TargetManager
            targets={state.target}
            api={api}
            run={run}
            busy={busy}
            desktop={desktop}
            onSelect={setSelected}
            onOpen={(id) => {
              setSelected(id);
              setTab("testing");
            }}
          />
        )}
        {tab === "targets" && appsView === "accounts" && target && <section className="panel"><AccountManager target={target} accounts={state.account.filter(a=>a.target_id===selected)} api={api} run={run} busy={busy} onTask={id=>{setFocusJob(id);setTaskView("tasks");setTaskVisit(v=>v+1);setTab("jobs");}}/><div className="actions"><button className="primary" onClick={()=>setTab("testing")}>检查此应用</button></div></section>}
        {tab === "testing" && <GuidedCheck key={selected} target={target} state={state} api={api} run={run} busy={busy} onManage={()=>{setAppsView("accounts");setTab("targets");}} onAdvanced={()=>setAdvancedChecks(true)} onCreated={id=>{setFocusJob(id);setTaskView("tasks");setTab("jobs");}}/>}
        {tab === "testing" && <details className="disclosure"><summary>离线专项审查：源码、弱口令、日志与文件完整性</summary><OfflineReview key={selected} target={target} api={api} onCreated={id=>{setFocusJob(id);setTaskView("tasks");setTab("jobs");}} /></details>}
        {tab === "testing" && <details className="disclosure" open={advancedChecks} onToggle={e=>setAdvancedChecks(e.currentTarget.open)}><summary>高级：接口发现、导入与自定义检测</summary>
          <EndpointWorkspace
            key={selected || "none"}
            target={target}
            state={state}
            api={api}
            run={run}
            busy={busy}
            onCreated={(id) => {
              setFocusJob(id);
              setTaskView("tasks");
              setTab("jobs");
            }}
          />
        </details>}
        {tab === "testing" && <details className="disclosure"><summary>AI 自动检查（可选，使用已保存模型）</summary>
            <AutoScanPanel targetId={selected} state={state} api={api} run={run} busy={busy} onReport={openJobReport} onAutoReport={(id) => void run(() => downloadAutoReport(id))} onTask={(id) => { setFocusJob(id); setTaskView("tasks"); setTaskVisit(v => v + 1); setTab("jobs"); }} />
        </details>}
        {tab === "jobs" && (
          <div className="section-tabs" aria-label="任务记录视图">
            <button
              className={taskView === "tasks" ? "active" : "secondary"}
              aria-pressed={taskView === "tasks"}
              onClick={() => setTaskView("tasks")}
            >
              任务与日志
            </button>
            <button
              className={taskView === "audit" ? "active" : "secondary"}
              aria-pressed={taskView === "audit"}
              onClick={() => setTaskView("audit")}
            >
              审计记录（高级）
            </button>
          </div>
        )}
        {tab === "jobs" && taskView === "tasks" && (
          <TaskManager
            key={taskVisit}
            initialJobId={focusJob}
            targetId={selected}
            state={state}
            api={api}
            run={run}
            busy={busy}
            onReport={openJobReport}
          />
        )}
        {tab === "models" && (
          <div className="stack">

            <details className="panel disclosure" open={!state.model.length}>
              <summary>
                模型连接与出口设置 · {state.model.length} 个已保存连接
              </summary>
              <ModelManager
                models={state.model}
                api={api}
                run={run}
                busy={busy}
              />
            </details>
            <section className="panel">
              <h2>生成测试建议</h2>
              <form
                onSubmit={(e) => {
                  const d = fields(e);
                  run(async () => {
                    const body = {
                      model_id: d.model,
                      endpoint_ids: requestList(),
                      context: d.context,
                      include_semantic_context: d.semantic === "on",
                      max_cost_usd: Number(d.cost),
                    };
                    if (d.action === "preview") {
                      setPreview(
                        JSON.stringify(
                          await api(`/targets/${selected}/model-preview`, body),
                          null,
                          2,
                        ),
                      );
                    } else {
                      await api(`/targets/${selected}/proposals`, body);
                    }
                  });
                }}
              >
                <label>
                  模型
                  <select name="model" required>
                    {state.model.map((m) => (
                      <option key={m.id} value={m.id}>
                        {m.name} · {m.model}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  业务规则（本地模型或开启语义分析时发送脱敏内容）
                  <textarea name="context" rows={5} />
                </label>
                <label className="check"><input type="checkbox" name="semantic" />启用 AI 语义分析：发送脱敏路径、业务规则与有限响应片段（建议先预览）</label>
                <label>
                  单次费用上限（美元）
                  <input
                    name="cost"
                    type="number"
                    min="0.01"
                    max="5"
                    step="0.01"
                    defaultValue="0.10"
                  />
                </label>
                <div className="actions">
                  <button
                    name="action"
                    value="preview"
                    disabled={busy || !target || !requestList().length}
                  >
                    预览发送内容
                  </button>
                  <button
                    name="action"
                    value="generate"
                    disabled={busy || !target || !requestList().length}
                  >
                    生成建议
                  </button>
                </div>
              </form>
              <p className="muted">
                生成建议不会发送测试请求。创建建议任务后，执行器独立检查范围与预算。
              </p>
              <form
                onSubmit={(e) => {
                  const d = fields(e);
                  run(() =>
                    api(`/targets/${selected}/proposals/run`, {
                      proposal_ids: state.proposal
                        .filter((p) => p.target_id === selected)
                        .slice(-30)
                        .map((p) => p.id),
                      account_ids: state.account
                        .filter((a) => a.target_id === selected)
                        .slice(0, 3)
                        .map((a) => a.id),
                      request_budget: Number(d.budget),
                      duration_seconds: 120,
                    }),
                  );
                }}
              >
                <label>
                  建议任务请求预算
                  <input
                    type="number"
                    name="budget"
                    defaultValue="20"
                    min="1"
                    max="500"
                  />
                </label>
                <button
                  disabled={
                    busy ||
                    !target ||
                    !state.proposal.some((p) => p.target_id === selected)
                  }
                >
                  创建这些建议的测试任务
                </button>
              </form>
              {(state.ai_assessment || []).filter(a => a.target_id === selected).map(a => <article className="inset-panel" key={a.id}>
                <h3>AI 验证假设 · 待确认</h3><p>{a.hypothesis}</p><p>观察：{a.observation}</p>
                <p>还需验证：{a.missing_evidence}</p><p className="muted">接口 {a.endpoint_id} · 证据 {a.evidence_ids.join("、") || "暂无，仅为假设"}</p>
              </article>)}
              {state.proposal
                .filter((p) => p.target_id === selected)
                .map((p) => (
                  <article key={p.id}>
                    <h3>{p.test_type}</h3>
                    <p>{p.expected_evidence}</p>
                    <code>{p.endpoint_id}</code>
                  </article>
                ))}
            </section>
          </div>
        )}
        {tab === "findings" && (
          <>
            <section className="panel">
              <div className="row">
                <div>
                  <h2>
                    {reportJob
                      ? "任务报告 · " + reportJob.slice(0, 12)
                      : "漏洞报告"}
                  </h2>
                  {reportJob && (
                    <>
                      <p>
                        {reportTarget?.name || "历史目标"} ·{" "}
                        {labels[reportTask?.status] || reportTask?.status}
                      </p>
                      <p className="muted">
                        仅展示本任务范围内的记录；切换阅读方式不会改变检查结果或人工确认状态。
                      </p>
                      <button onClick={() => setReportJob(null)}>
                        取消任务筛选
                      </button>
                    </>
                  )}
                  <p className="muted">
                    {reportView === "easy" ? "易懂版解释现有线索、处理建议和检查局限；技术版保留审核与证据详情。" : reportView === "submission" ? "按单条发现整理平台提交草稿；在下方保存和导出，未确认记录保留待验证提示。" : "技术版正式漏洞导出仅包含人工确认且有关联证据的发现，任务报告另附执行摘要。"}
                  </p>
                </div>
                <div className="actions">
                  {reportView !== "submission" && ["md", "html", "zip"].map((f) => (
                    <button
                      key={f}
                      disabled={busy || !reportTarget}
                      onClick={() => run(() => download(f))}
                    >
                      {f === "zip" ? "导出证据包" : `导出${reportView === "easy" ? "易懂版" : "技术版"} ${f.toUpperCase()}`}
                    </button>
                  ))}
                </div>
              </div>
            </section>
            <div className="section-tabs report-view-switch" role="group" aria-label="报告阅读方式">
              <button type="button" className={reportView === "easy" ? "active" : ""} aria-pressed={reportView === "easy"} onClick={() => setReportView("easy")}>易懂版</button>
              <button type="button" className={reportView === "technical" ? "active" : ""} aria-pressed={reportView === "technical"} onClick={() => setReportView("technical")}>技术版</button>
              <button type="button" className={reportView === "submission" ? "active" : ""} aria-pressed={reportView === "submission"} onClick={() => setReportView("submission")}>平台提交版</button>
            </div>
            {reportView === "easy" && (reportTarget ? <ReadableReport targetId={reportTargetId} jobId={reportJob} token={token} /> : <section className="empty">请先选择目标，再查看易懂版报告。</section>)}
            {reportView === "submission" && <SubmissionReport findings={visibleFindings} api={api} token={token} />}
            {reportView === "technical" && visibleFindings.map((f) => (
              <details className="panel finding-card" key={f.id}>
                <summary>
                  {f.title}{" "}
                  <span className="badge">{labels[f.status] || f.status}</span>
                </summary>
                <div className="row">
                  <h2>{f.title}</h2>
                  <span className="badge">{labels[f.status]}</span>
                </div>
                <p>{f.detail}</p>
                <p className="mono">证据：{f.evidence_ids.join(", ")}</p>
                <form
                  onSubmit={(e) => {
                    const d = fields(e);
                    run(() =>
                      api(
                        `/findings/${f.id}`,
                        { status: d.status, explanation: d.explanation },
                        "PATCH",
                      ),
                    );
                  }}
                >
                  <label>
                    人工复现步骤、前置条件与判断依据
                    <textarea
                      name="explanation"
                      minLength={10}
                      required
                      defaultValue={f.explanation}
                    />
                  </label>
                  <div className="actions">
                    <select
                      name="status"
                      aria-label="审核状态"
                      defaultValue={f.status}
                    >
                      {["lead", "pending", "verified", "false_positive"].map(
                        (s) => (
                          <option value={s} key={s}>
                            {labels[s]}
                          </option>
                        ),
                      )}
                    </select>
                    <button disabled={busy}>保存审核</button>
                  </div>
                </form>
                <form
                  onSubmit={(e) => {
                    const d = fields(e);
                    run(() =>
                      api(`/findings/${f.id}/merge`, {
                        source_id: d.source_id,
                      }),
                    );
                  }}
                >
                  <label>
                    将同目标的另一个发现合并到这里（合并后重新审核）
                    <select name="source_id" required defaultValue="">
                      <option value="" disabled>
                        选择待合并发现
                      </option>
                      {state.finding
                        .filter(
                          (other) =>
                            other.target_id === f.target_id &&
                            other.id !== f.id &&
                            !other.merged_into,
                        )
                        .map((other) => (
                          <option key={other.id} value={other.id}>
                            {other.title} · {other.id.slice(0, 8)}
                          </option>
                        ))}
                    </select>
                  </label>
                  <button disabled={busy}>合并证据</button>
                </form>
              </details>
            ))}
            {reportView === "technical" && visibleFindings.length === 0 && (
              <section className="empty">
                尚无发现。完成授权与测试后，线索会出现在这里。
              </section>
            )}
          </>
        )}
        {tab === "jobs" && taskView === "audit" && (
          <section className="panel">
            <h2>证据与审计</h2>
            <p className="muted">
              此处显示证据摘要；新任务的脱敏 HTTP 请求与响应可在“任务详情 →
              接口与检查”中查看，旧证据无法补回正文。
            </p>
            {state.evidence
              .slice()
              .reverse()
              .map((e) => (
                <details key={e.id}>
                  <summary>
                    {labels[e.state]} · {e.method} {e.url} · {e.role}
                  </summary>
                  <pre>{JSON.stringify(e, null, 2)}</pre>
                </details>
              ))}
            <h3>操作日志</h3>
            {state.audit
              .slice()
              .reverse()
              .slice(0, 100)
              .map((a) => {
                const jobId = a.job_id || state.job.find((j) => j.id === a.subject)?.id || state.evidence.find((e) => e.id === a.subject)?.job_id;
                return (
                <div className="log" key={a.id}>
                  <time>{new Date(a.at * 1000).toLocaleString()}</time>
                  <code>{a.action}</code>
                  <span>{a.subject.slice(0, 16)}</span>
                  {jobId && <button className="secondary" onClick={() => {
                    setFocusJob(jobId);
                    setTaskView("tasks");
                  }}>查看关联任务 · {jobId.slice(0, 12)}</button>}
                </div>
                );
              })}
          </section>
        )}
        {tab === "findings" && (
          <details className="panel disclosure">
            <summary>补充人工证据 / SRC 素材</summary>
            <ManualEvidence
              selected={selected}
              busy={busy}
              submit={(data) =>
                run(() => api(`/targets/${selected}/manual-evidence`, data))
              }
            />
          </details>
        )}
        {preview && (
          <section className="panel">
            <div className="row">
              <h2>检查结果 / 发送预览</h2>
              <button onClick={() => setPreview("")}>关闭</button>
            </div>
            <pre>{preview}</pre>
          </section>
        )}
        <footer>
          AutoMiner 0.1 · 固定模板测试 · 人工确认结论 · 授权变化即时阻断后续请求
        </footer>
      </main>
    </div>
  );
}
createRoot(document.getElementById("root")!).render(<App />);
