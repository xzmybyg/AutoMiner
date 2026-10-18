import { useEffect, useRef, useState } from "react";

type Props = {
  target: any;
  api: (path: string, body?: unknown, method?: string) => Promise<any>;
  run: (fn: () => Promise<unknown>) => Promise<void>;
  busy: boolean;
  onViewList: () => void;
};
const status: Record<string, string> = {
  queued: "排队中",
  running: "发现中",
  completed: "已完成",
  blocked: "已阻断",
  stopped: "已停止",
  reserved: "已预留",
  in_flight: "已发送，等待响应",
  complete: "请求完成",
  failed: "请求失败",
  interrupted: "上次会话已中断",
};

export default function DiscoveryManager({ target, api, run, busy, onViewList }: Props) {
  const [rows, setRows] = useState<any[]>([]);
  const [current, setCurrent] = useState("");
  const [picked, setPicked] = useState<string[]>([]);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const ref = useRef(api);
  ref.current = api;
  useEffect(() => {
    setRows([]);
    setCurrent("");
    setPicked([]);
    setMessage("");
    setError("");
    if (!target?.id) return;
    let alive = true;
    async function refresh() {
      try {
        const next = await ref.current(`/targets/${target.id}/discoveries`);
        if (alive) {
          setRows(next);
          setError("");
        }
      } catch (e) {
        if (alive) setError(String(e));
      }
    }
    void refresh();
    const timer = window.setInterval(refresh, 2000);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, [target?.id]);
  const selected = rows.find((r) => r.id === current) || rows[0];
  const remaining = Math.max(0, (target?.request_budget || 0) - (target?.used || 0));
  const allowed =
    target?.verified &&
    !target.revoked &&
    !target.deleted &&
    target.kind !== "src" &&
    target.expires_at > Date.now() / 1000 && remaining > 0;
  const working = rows.some((r) => ["queued", "running"].includes(r.status));
  const base = target
    ? `${target.scheme}://${target.host.includes(":") ? `[${target.host}]` : target.host}:${target.port}`
    : "";
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("business");
  const [page, setPage] = useState(0);
  const unique = new Map<string, any>();
  for (const c of selected?.candidates || []) {
    const key = c.method + " " + c.url;
    const old = unique.get(key);
    if (old) old.sources.push(c.source);
    else unique.set(key, { ...c, sources: [c.source] });
  }
  const candidates = [...unique.values()];
  const isResource = (url: string) =>
    /\/(?:src|node_modules|assets|@vite|@react-refresh|@fs)(?:\/|$)|\.(?:[cm]?js|tsx?|jsx|css|scss)(?:$|\?)/.test(
      url,
    );
  const filtered = candidates.filter(
    (c) =>
      (filter === "all" ||
        (filter === "restricted" ? !c.importable : !isResource(c.url))) &&
      `${c.method} ${c.url}`.toLowerCase().includes(query.toLowerCase()),
  );
  const lastPage = Math.max(0, Math.ceil(filtered.length / 15) - 1);
  const currentPage = Math.min(page, lastPage);
  const visible = filtered.slice(currentPage * 15, currentPage * 15 + 15);
  return (
    <section className="panel" aria-label="接口发现">
      <h2>自动扫描与接口发现</h2>
      <p className="muted">
        读取授权内的页面、脚本与 OpenAPI
        JSON。仅静态分析，不执行脚本；请求计入目标预算。
      </p>
      <div className="selection-bar">
        <button
          disabled={busy || !allowed || working}
          onClick={() => void run(async () => {
            const row = await api(`/targets/${target.id}/discoveries`, {
              automatic: true,
              request_budget: Math.min(20, remaining),
              max_depth: 2,
            });
            setRows((old) => [row, ...old]);
            setCurrent(row.id);
            setPicked([]);
            setPage(0);
            setMessage("自动扫描已排队，完成后将自动加入接口列表。");
          })}
        >
          {working ? "扫描进行中…" : "自动扫描接口"}
        </button>
        <span className="muted">从授权路径开始，最多 {Math.min(20, remaining)} 次请求、2 层引用。</span>
      </div>
      <p className="muted">
        完成后自动登记范围内的接口线索，已存在的自动跳过；脚本资源、动态路径和未知方法保留待整理。不会自动测试接口或发送业务写入请求。
      </p>
      <details className="disclosure">
        <summary>高级：手工设置发现入口与预算</summary>
        <form
          key={target?.id || "none"}
          onSubmit={(e) => {
            e.preventDefault();
            const d = new FormData(e.currentTarget);
            void run(async () => {
              const row = await api(`/targets/${target.id}/discoveries`, {
                seeds: String(d.get("seeds"))
                  .split("\n")
                  .map((s) => s.trim())
                  .filter(Boolean),
                request_budget: Number(d.get("budget")),
                max_depth: Number(d.get("depth")),
              });
              setRows((old) => [row, ...old]);
              setCurrent(row.id);
              setPicked([]);
              setPage(0);
              setMessage("已加入发现队列，结果每两秒刷新。");
            });
          }}
        >
          <label>
            入口地址（每行一个，最多 10 个）
            <textarea
              name="seeds"
              rows={2}
              required
              defaultValue={base + (target?.paths?.[0] || "/")}
            />
          </label>
          <div className="two">
            <label>
              最多请求数
              <input
                name="budget"
                type="number"
                min={1}
                max={Math.min(20, remaining) || 1}
                defaultValue={Math.min(5, remaining) || 1}
                required
              />
            </label>
            <label>
              跟随引用层数
              <select name="depth" defaultValue="1">
                <option value="0">仅入口</option>
                <option value="1">1 层</option>
                <option value="2">2 层</option>
              </select>
            </label>
          </div>
          <button disabled={busy || !allowed || working}>
            {working ? "发现进行中…" : "开始发现"}
          </button>
          {!allowed && (
            <p className="muted">请选择有效且已验证的本人应用或靶场。</p>
          )}
        </form>
      </details>
      {error && <p role="alert">{error}</p>}
      <p role="status">{message}</p>
      {!!rows.length && (
        <>
          <label>
            发现记录
            <select
              value={selected?.id || ""}
              onChange={(e) => {
                setCurrent(e.target.value);
                setPicked([]);
                setPage(0);
                setMessage("");
              }}
            >
              {rows.map((r) => (
                <option key={r.id} value={r.id}>
                  {new Date(r.created_at * 1000).toLocaleString()} ·{" "}
                  {status[r.status] || r.status} · {r.id.slice(0, 8)}
                </option>
              ))}
            </select>
          </label>
          {selected && (
            <div aria-busy={selected.status === "running"}>
              <div className="row spread">
                <p role="status">
                  {status[selected.status]} · 请求 {selected.used}/
                  {selected.request_budget} · 去重候选 {candidates.length}
                </p>
                {["queued", "running"].includes(selected.status) && (
                  <button
                    className="danger"
                    disabled={busy}
                    onClick={() =>
                      void run(async () => {
                        await api(`/discoveries/${selected.id}/stop`, {});
                        setRows(await api(`/targets/${target.id}/discoveries`));
                      })
                    }
                  >
                    停止发现
                  </button>
                )}
              </div>
              {selected.automatic && <p role="status">
                自动扫描 · {selected.auto_imported !== undefined
                  ? `已自动加入 ${selected.auto_imported} 个新接口，可返回“接口列表”查看。`
                  : "扫描结束后自动整理并登记接口。"}
              </p>}
              {selected.auto_imported !== undefined && <button
                className="secondary"
                disabled={busy}
                onClick={() => void run(async () => { onViewList(); })}
              >
                查看接口列表
              </button>}
              {selected.error && <p role="alert">{selected.error}</p>}
              <div className="filter-bar">
                <label>
                  搜索候选
                  <input
                    type="search"
                    value={query}
                    onChange={(e) => {
                      setQuery(e.target.value);
                      setPage(0);
                    }}
                    placeholder="方法或路径"
                  />
                </label>
                <label>
                  显示内容
                  <select
                    value={filter}
                    onChange={(e) => {
                      setFilter(e.target.value);
                      setPage(0);
                    }}
                  >
                    <option value="business">业务接口线索</option>
                    <option value="all">全部（含脚本资源）</option>
                    <option value="restricted">需人工整理</option>
                  </select>
                </label>
              </div>
              <p className="muted">
                静态引用不证明接口存在。写入方法只记录；未知方法、动态路径及范围外地址不能直接导入。
              </p>
              <div className="selection-bar">
                <span>已选 {picked.length} 项</span>
                <button
                  className="secondary"
                  disabled={!visible.some((c) => c.importable)}
                  onClick={() =>
                    setPicked((old) => [
                      ...new Set([
                        ...old,
                        ...visible.filter((c) => c.importable).map((c) => c.id),
                      ]),
                    ])
                  }
                >
                  选择本页可导入项
                </button>
                <button
                  className="secondary"
                  disabled={!picked.length}
                  onClick={() => setPicked([])}
                >
                  清空
                </button>
                <button
                  disabled={busy || !allowed || !picked.length}
                  onClick={() =>
                    void run(async () => {
                      const r = await api(
                        `/discoveries/${selected.id}/import`,
                        { candidate_ids: picked },
                      );
                      setMessage(
                        `已加入 ${r.imported.length} 个新接口，可在“接口列表”查看。`,
                      );
                      setPicked([]);
                    })
                  }
                >
                  加入接口列表（{picked.length}）
                </button>
              </div>
              <div className="table-scroll">
                <table className="compact-table">
                  <thead>
                    <tr>
                      <th>选择</th>
                      <th>方法</th>
                      <th>候选地址</th>
                      <th>来源与范围</th>
                    </tr>
                  </thead>
                  <tbody>
                    {visible.map((c) => (
                      <tr key={c.id}>
                        <td>
                          <input
                            type="checkbox"
                            aria-label={`选择候选 ${c.method} ${c.url}`}
                            disabled={!c.importable}
                            checked={picked.includes(c.id)}
                            onChange={(e) =>
                              setPicked((old) =>
                                e.target.checked
                                  ? [...old, c.id]
                                  : old.filter((id) => id !== c.id),
                              )
                            }
                          />
                        </td>
                        <td>
                          <span className="method-badge">{c.method}</span>
                        </td>
                        <td className="url-cell">{c.url}</td>
                        <td>
                          <span>
                            {c.importable ? "可导入" : c.reason || "方法未知"}
                          </span>
                          <details>
                            <summary>来源（{new Set(c.sources).size}）</summary>
                            <p>{c.source_type}</p>
                            {[...new Set<string>(c.sources)].map((source) => (
                              <p className="url-cell" key={source}>
                                {source}
                              </p>
                            ))}
                          </details>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {!visible.length && (
                  <p className="empty">
                    当前筛选无候选。可切换“全部”查看脚本与资源引用。
                  </p>
                )}
              </div>
              <div className="pagination">
                <span>
                  匹配 {filtered.length} 项 · 第 {currentPage + 1}/
                  {lastPage + 1} 页
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
              <details className="disclosure">
                <summary>实际访问记录 · {selected.requests.length} 条</summary>
                <p className="muted">{selected.note}</p>
                {selected.requests.map((r: any) => (
                  <p className="url-cell" key={r.id}>
                    <code>{r.method}</code> {r.url}
                    <br />
                    <span className="muted">
                      {status[r.state] || r.state} · HTTP {r.status ?? "—"}
                      {r.error ? ` · ${r.error}` : ""}
                      {r.redirect_blocked ? " · 跳转已阻断" : ""}
                      {r.truncated ? " · 仅读取前 64KB" : ""}
                    </span>
                  </p>
                ))}
              </details>
            </div>
          )}
        </>
      )}
    </section>
  );
}
