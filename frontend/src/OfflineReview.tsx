import { useState } from "react";

export function OfflineResults({ result }: { result: any }) {
  const names: Record<string, string> = { lead: "发现待核实线索", reviewed: "已审查，未命中有限规则", not_run: "未提供所需材料" };
  return <section aria-label="专项审查结果">
    <p className="muted">{result.limitations}</p>
    <div className="table-wrap"><table><thead><tr><th>类别</th><th>本次覆盖情况</th><th>线索数</th></tr></thead><tbody>
      {result.coverage.map((c: any) => <tr key={c.category}><td>{c.name}</td><td>{names[c.status]}</td><td>{c.count}</td></tr>)}
    </tbody></table></div>
    {result.items.map((item: any, index: number) => <details className="task-endpoint" key={index}><summary>{item.title} · {item.location}</summary><p>{item.reason}</p><p>建议：{item.fix}</p></details>)}
  </section>;
}

type Props = { target: any; api: (path: string, body?: unknown, method?: string) => Promise<any>; onCreated: (id: string) => void };
export default function OfflineReview({ target, api, onCreated }: Props) {
  const [sources, setSources] = useState<{path: string; content: string}[]>([]);
  const [materials, setMaterials] = useState("");
  const [passwords, setPasswords] = useState("");
  const [owned, setOwned] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<any>(null);
  const load = async (files: FileList | null) => {
    setError("");
    if (!files) return;
    const picked = Array.from(files);
    if (picked.length > 32 || picked.some(f => f.size > 262144) || picked.reduce((sum, f) => sum + f.size, 0) > 2000000) {
      setError("最多 32 个文本文件，单文件不超过 256 KB，总计不超过 2 MB。"); return;
    }
    try { setSources(await Promise.all(picked.map(async f => ({ path: f.name, content: await f.text() })))); }
    catch { setError("文件读取失败，请重新选择文本文件。"); }
  };
  const submit = async () => {
    setBusy(true); setError(""); setResult(null);
    try {
      const extra = materials.trim() ? JSON.parse(materials) : {};
      if (!extra || Array.isArray(extra) || typeof extra !== "object" || Object.keys(extra).some(k => !["events", "baseline", "current", "known_bad_sha256"].includes(k))) throw new Error("日志与清单 JSON 仅接受 events、baseline、current、known_bad_sha256 字段。");
      const value = await api(`/targets/${target.id}/offline-reviews`, { ...extra, sources, passwords: passwords.split(/\r?\n/).filter(Boolean), materials_owned: owned });
      setPasswords(""); setMaterials(""); setSources([]); setResult(value);
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  };
  return <section className="panel">
    <h2>离线专项审查</h2>
    <p>补充弱口令、后门线索、入侵日志、文件变化及源码危险用法检查。只分析你导入的材料，不向目标发送请求，不执行文件。</p>
    <p className="muted">原始源码、日志、测试口令仅在本机内存处理，不保存、不发送云模型；保存类别覆盖情况、文件摘要、规则及行号。请保留原文件以便复核。</p>
    {!target ? <p>请先在上方选择已登记目标。</p> : <>
      <label>选择源码文本文件（可多选）<input type="file" multiple disabled={busy} onChange={e => void load(e.target.files)} /></label>
      <p className="muted">已选择 {sources.length} 个文件；最多 32 个，每个 256 KB，总计 2 MB。仅支持文本，不解压、不分析二进制。重复文件名请分别审查。</p>
      <details className="disclosure"><summary>导入日志与文件清单（可选）</summary>
        <p>粘贴 JSON。日志需先转换为下面的结构；actor 用于关联同一来源，不保存。文件清单由可信基线与当前版本的相同范围生成。</p>
        <label>日志与清单 JSON<textarea rows={8} maxLength={4000000} value={materials} onChange={e => setMaterials(e.target.value)} /></label>
        <details><summary>查看格式示例</summary><pre>{JSON.stringify({ events: [{ at: 1700000000, kind: "login_failed", actor: "test-account", path: "/login", status: 401 }], baseline: [{path:"app.py",sha256:"a".repeat(64)}], current: [{path:"app.py",sha256:"b".repeat(64)}], known_bad_sha256: [] }, null, 2)}</pre><p className="muted">kind 支持 login_failed、login_success、http_request、admin_change。at 为 Unix 秒。示例摘要仅演示格式，请替换为实际 SHA-256。</p></details>
      </details>
      <details className="disclosure"><summary>离线检查测试口令（可选）</summary><label>每行一个专门用于测试的口令<textarea autoComplete="off" spellCheck={false} rows={3} value={passwords} onChange={e => setPasswords(e.target.value)} /></label><p className="muted">不尝试登录，不读取已保存账号的凭证。最多 50 条；检查后清空输入，仅保留“第几个口令命中规则”。</p></details>
      <label className="check"><input type="checkbox" checked={owned} onChange={e => setOwned(e.target.checked)} />这些材料属于本人或已获分析授权</label>
      {error && <p role="alert">{error}</p>}
      <div className="actions"><button disabled={busy || !owned || !(sources.length || materials.trim() || passwords.trim())} onClick={() => void submit()}>{busy ? "正在审查…" : "开始离线审查并保存任务"}</button>{result && <button className="secondary" onClick={() => onCreated(result.job_id)}>查看本次任务与报告</button>}</div>
      {result && <><p role="status">已保存，发现 {result.items.length} 条待核实线索，目标请求 0 次。</p><OfflineResults result={result} /></>}
    </>}
  </section>;
}
