import { useEffect, useState } from "react";

type Props = {
  target: any;
  accounts: any[];
  api: (path: string, body?: unknown, method?: string) => Promise<any>;
  run: (fn: () => Promise<unknown>) => Promise<void>;
  busy: boolean;
  onTask?: (id: string) => void;
};

export default function AccountManager({ target, accounts, api, run, busy, onTask }: Props) {
  const [lastJob, setLastJob] = useState("");
  const [editing, setEditing] = useState<any>(null);
  const [verifying, setVerifying] = useState<any>(null);
  const [query, setQuery] = useState("");
  const [message, setMessage] = useState("");
  useEffect(() => { setQuery(""); setMessage(""); setEditing(null); setVerifying(null); setLastJob(""); }, [target.id]);
  const rows = accounts.filter(a => `${a.name} ${a.role} ${a.id}`.toLowerCase().includes(query.toLowerCase()));
  return <>
    <h2>测试账号列表 · {accounts.length}</h2>
    <p className="muted">当前目标：{target.name} · {target.scheme}://{target.host}:{target.port}。账号只用于这个目标；凭证加密保存，列表不显示原始 Token 或 Cookie。</p>
    <details className="disclosure" key={`${target.id}-${editing?.id || "new"}`} open={editing ? true : undefined}>
      <summary>{editing ? "更新账号凭证" : "添加新账号"}</summary>
      <form onSubmit={event => {
        event.preventDefault();
        const form = event.currentTarget;
        const data = new FormData(form);
        const headers: Record<string, string> = {};
        for (const name of ["Authorization", "Cookie", "X-Test-Account"]) {
          const value = String(data.get(name) || "").trim();
          if (value) headers[name] = value;
        }
        setMessage("");
        if (!Object.keys(headers).length) { setMessage("请至少填写一种登录请求头。"); return; }
        void run(async () => {
          await api(editing ? `/accounts/${editing.id}` : `/targets/${target.id}/accounts`, {
            name: data.get("name"), role: data.get("role"), headers, synthetic_data_only: true,
          }, editing ? "PUT" : "POST");
          form.reset();
          setEditing(null);
          setMessage("账号已保存，请在下方列表查看。保存成功不代表登录状态已验证。");
        });
      }}>
        <div className="two">
          <label>账号名称<input name="name" defaultValue={editing?.name || ""} required maxLength={100} placeholder="例如：博客管理员测试账号" /></label>
          <label>角色<input name="role" defaultValue={editing?.role || ""} required maxLength={100} placeholder="管理员 / 只读访客 / 普通用户" /></label>
          <label>Authorization（可选）<input name="Authorization" type="password" autoComplete="new-password" placeholder="复制登录请求中的完整值" /></label>
          <label>Cookie（可选）<input name="Cookie" type="password" autoComplete="new-password" placeholder="使用 Cookie 登录时填写" /></label>
        </div>
        <p className="muted">按实际请求原样填写；Authorization 是否带 Bearer 前缀以应用要求为准。</p>
        <details><summary>靶场专用请求头（可选）</summary><label>X-Test-Account<input name="X-Test-Account" placeholder="仅靶场使用，普通网站通常留空" /></label></details>
        <p className="muted">仅保存专用测试账号，使用合成数据。</p>
        <button className="primary" disabled={busy}>{busy ? "处理中…" : editing ? "保存更新" : "保存新账号"}</button>
      </form>
    </details>
    {editing && <button onClick={() => setEditing(null)}>取消更新</button>}
    {message && <p role="status">{message}</p>}
    {lastJob && onTask && <button className="secondary" onClick={()=>onTask(lastJob)}>查看账号验证进度与证据</button>}
    <label>查找已保存账号<input value={query} onChange={e => setQuery(e.target.value)} placeholder="搜索名称、角色或账号 ID" /></label>
    <div className="table-scroll">
      <table className="compact-table account-table">
        <caption className="muted account-list-caption">已保存 {accounts.length} 个账号 · 当前显示 {rows.length} 个</caption>
        <thead><tr><th scope="col">账号名称 / ID</th><th scope="col">角色</th><th scope="col">所属目标</th><th scope="col">凭证信息</th><th scope="col">操作</th></tr></thead>
        <tbody>{rows.map(a => <tr key={a.id}>
          <td><strong>{a.name}</strong><details><summary>查看账号 ID</summary><code>{a.id}</code></details></td>
          <td>{a.role}</td><td>{target.name}<br /><span className="muted">{target.host}:{target.port}</span></td>
          <td>{a.credential_recovery_required ? "需要重存凭证" : a.last_validation?.version === target.version ? ({valid:"可用",invalid:"已失效",inconclusive:"需要确认"} as Record<string,string>)[a.last_validation.status] : "未验证"}<br /><span className="muted">{a.header_names?.length ? a.header_names.join("、") : "请求头类型未记录"}</span></td>
          <td><div className="actions"><button disabled={busy} onClick={() => setVerifying(a)}>验证登录</button><button disabled={busy} onClick={() => setEditing(a)}>更新凭证</button></div>{a.last_validation && <small className="muted">验证于 {new Date(a.last_validation.at*1000).toLocaleString()}<br />{a.last_validation.reason}</small>}</td>
        </tr>)}</tbody>
      </table>
      {!rows.length && <p className="empty">{accounts.length ? "没有匹配的账号。" : "当前目标还没有账号，请点击上方“添加新账号”。"}</p>}
    </div>
    {verifying && <section className="inset-panel" key={verifying.id}>
      <h3>验证登录：{verifying.name}</h3>
      <p>使用一个应拒绝匿名访问、返回当前用户信息的 GET 接口进行 2 次只读对照。普通页面返回 200 不算验证成功。</p>
      <form onSubmit={event => { event.preventDefault(); const data=new FormData(event.currentTarget); void run(async () => {
        const result=await api(`/accounts/${verifying.id}/verify`, {url:data.get("url"),identity_field:data.get("identity"),role_field:"role",expected_role:data.get("role")});
        setLastJob(result.job_id);setMessage(`验证已提交，任务 ${result.job_id.slice(0,12)}。完成后列表会自动更新状态。`);setVerifying(null);
      }); }}>
        <label>登录状态接口<input name="url" type="url" required defaultValue={target.identity_check?.url || ""} placeholder={`${target.scheme}://${target.host}/api/users/me`} /></label>
        <div className="two"><label>用户标识字段<input name="identity" required defaultValue={target.identity_check?.identity_field || "id"} /></label><label>预期角色（可选）<input name="role" defaultValue={verifying.identity_check?.expected_role || ""} placeholder="例如 admin" /></label></div>
        <div className="actions"><button className="primary" disabled={busy}>发送 2 次只读请求验证</button><button type="button" onClick={() => setVerifying(null)}>取消</button></div>
      </form>
    </section>}
  </>;
}
