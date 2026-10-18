import React, { useRef, useState } from "react";

type Props = {
  targets: any[];
  api: (path: string, body?: unknown, method?: string) => Promise<any>;
  run: (fn: () => Promise<unknown>) => Promise<void>;
  busy: boolean;
  desktop: boolean;
  onSelect?: (id: string) => void;
  onOpen?: (id: string) => void;
};
const kinds: Record<string, string> = {
  local: "Windows 本机应用",
  owned: "本人应用",
  lab: "授权靶场",
  src: "SRC（仅整理报告）",
};
function time(value: number) {
  return new Date(value * 1000).toLocaleString();
}
function localTime(value: number) {
  const date = new Date(value * 1000);
  return new Date(date.getTime() - date.getTimezoneOffset() * 60000)
    .toISOString()
    .slice(0, 16);
}
function status(t: any) {
  return t.revoked
    ? "已撤销"
    : t.expires_at <= Date.now() / 1000
      ? "已过期"
      : t.kind === "src"
        ? "仅整理报告"
        : t.verified
          ? "已验证"
          : "待验证";
}
function download(challenge: string) {
  const url = URL.createObjectURL(
    new Blob([challenge], { type: "text/plain" }),
  );
  const a = document.createElement("a");
  a.href = url;
  a.download = "autominer-verification.txt";
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export default function TargetManager({
  targets,
  api,
  run,
  busy,
  desktop,
  onSelect,
  onOpen,
}: Props) {
  const [editing, setEditing] = useState<any>(null);
  const [formKey, setFormKey] = useState(0);
  const [confirmDelete, setConfirmDelete] = useState("");
  const [filter, setFilter] = useState("");
  const [editorOpen, setEditorOpen] = useState(false);
  const editor = useRef<HTMLDetailsElement>(null);
  const visible = targets.filter((t) => !t.deleted);
  const filtered = visible.filter((t) =>
    `${t.name} ${t.host} ${t.id} ${t.hash || ""}`
      .toLowerCase()
      .includes(filter.toLowerCase()),
  );
  const start = (target: any) => {
    setEditing(target);
    setFormKey((k) => k + 1);
    setEditorOpen(true);
    window.setTimeout(
      () => editor.current?.scrollIntoView({ block: "start" }),
      0,
    );
  };
  const t = editing || {};
  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const d = Object.fromEntries(new FormData(event.currentTarget)) as Record<
      string,
      string
    >;
    const lines = (value: string) =>
      value
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean);
    const expiresAt =
      editing && d.expires === localTime(editing.expires_at)
        ? editing.expires_at
        : new Date(d.expires).getTime() / 1000;
    const body = {
      name: d.name,
      kind: d.kind,
      scheme: d.scheme,
      host: d.host.trim(),
      port: Number(d.port),
      paths: lines(d.paths),
      deny_paths: lines(d.deny),
      bound_ips: d.ips
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
      statement: d.statement,
      expires_at: expiresAt,
      request_budget: Number(d.budget),
      ownership_declared: d.owned === "on",
    };
    await run(async () => {
      const result = await api(
        editing ? `/targets/${editing.id}` : "/targets",
        body,
        editing ? "PUT" : "POST",
      );
      start(null);
      setEditorOpen(false);
      if (!result.revoked) onSelect?.(result.id);
    });
  }
  return (
    <div className="target-layout">
      <details
        className="panel disclosure target-editor"
        ref={editor}
        open={editorOpen}
        onToggle={(e) => setEditorOpen(e.currentTarget.open)}
      >
        <summary>{editing ? "编辑目标授权" : "登记新目标"}</summary>
        <h2>
          {editing
            ? `编辑目标 · #${editing.hash?.slice(0, 12) || editing.id.slice(0, 12)}`
            : "登记目标"}
        </h2>
        <p className="muted">
          目标自动保存至本机。修改授权范围后需要重新验证，相关排队、运行及暂停任务将停止；仅改名称不影响授权。
        </p>
        <form key={formKey} onSubmit={submit}>
          <label>
            目标名称
            <input
              name="name"
              required
              maxLength={100}
              defaultValue={t.name || ""}
            />
          </label>
          <div className="two">
            <label>
              授权类型
              <select
                name="kind"
                defaultValue={t.kind || (desktop ? "local" : "owned")}
              >
                {Object.entries(kinds).map(([key, name]) => (
                  <option key={key} value={key}>
                    {name}
                  </option>
                ))}
              </select>
            </label>
            <label>
              协议
              <select
                name="scheme"
                defaultValue={t.scheme || (desktop ? "http" : "https")}
              >
                <option>http</option>
                <option>https</option>
              </select>
            </label>
          </div>
          <div className="two">
            <label>
              精确主机
              <input
                name="host"
                required
                defaultValue={t.host ?? (desktop ? "localhost" : "")}
                placeholder="localhost 或 app.example.com"
              />
            </label>
            <label>
              端口
              <input
                name="port"
                required
                type="number"
                min={1}
                max={65535}
                defaultValue={t.port ?? (desktop ? 5177 : 443)}
              />
            </label>
          </div>
          <label>
            允许路径（每行一个）
            <textarea
              name="paths"
              required
              defaultValue={(t.paths || ["/"]).join("\n")}
            />
          </label>
          <label>
            禁止路径（每行一个）
            <textarea
              name="deny"
              defaultValue={(t.deny_paths || []).join("\n")}
              placeholder="/logout"
            />
          </label>
          <label>
            绑定 IP（靶场必填，逗号分隔）
            <input name="ips" defaultValue={(t.bound_ips || []).join(",")} />
          </label>
          <p className="muted">
            新建本机目标可留空，由 HTTP 验证绑定回环地址。localhost 与 127.0.0.1
            为不同授权主机。
          </p>
          <label>
            授权证明 / 靶场来源
            <textarea
              name="statement"
              required
              minLength={10}
              maxLength={4000}
              defaultValue={t.statement || ""}
            />
          </label>
          <div className="two">
            <label>
              授权到期时间
              <input
                name="expires"
                required
                type="datetime-local"
                defaultValue={localTime(
                  t.expires_at || Date.now() / 1000 + 30 * 86400,
                )}
              />
            </label>
            <label>
              总请求预算
              <input
                name="budget"
                type="number"
                min={Math.max(1, t.used || 0)}
                max={500}
                required
                defaultValue={t.request_budget || 50}
              />
            </label>
          </div>
          <label className="check">
            <input
              name="owned"
              type="checkbox"
              defaultChecked={!!t.ownership_declared}
            />
            我声明拥有该应用，且测试使用专门账号与合成数据
          </label>
          <div className="actions">
            <button disabled={busy}>
              {editing ? "保存修改" : "保存并生成验证挑战"}
            </button>
            <button
              type="button"
              className="secondary"
              disabled={busy}
              onClick={() => {
                setEditorOpen(false);
                setEditing(null);
                setFormKey((k) => k + 1);
              }}
            >
              取消
            </button>
          </div>
        </form>
      </details>
      <section className="panel target-list">
        <div className="row spread">
          <h2>已保存目标 · {visible.length}</h2>
        </div>
        <label>
          查找名称、主机、Hash 或目标 ID
          <input value={filter} onChange={(e) => setFilter(e.target.value)} />
        </label>
        <p className="muted">
          已撤销目标保留供查阅，已删除目标不再展示；历史任务、证据与报告仍保留。
        </p>
        {!filtered.length && <p className="muted">没有匹配的目标。</p>}
        {filtered.map((target) => (
          <article className="target-card" key={target.id}>
            <h3>
              {target.name}{" "}
              <code className="target-hash" title={target.hash}>
                #{target.hash?.slice(0, 12) || "—"}
              </code>{" "}
              <span className="badge">
                {status(target)} · v{target.version}
              </span>
            </h3>
            <p className="mono">
              {target.scheme}://
              {target.host.includes(":") ? `[${target.host}]` : target.host}:
              {target.port}
            </p>
            <p className="muted">
              已用 {target.used} / {target.request_budget} 次
            </p>
            <details>
              <summary>查看目标具体信息</summary>
              <p className="muted">目标 ID：{target.id}</p>
              <p className="url-cell">
                SHA-256：<code>{target.hash}</code>
              </p>
              <dl>
                <dt>授权类型</dt>
                <dd>{kinds[target.kind]}</dd>
                <dt>精确主机 / 端口</dt>
                <dd>
                  {target.host} / {target.port}
                </dd>
                <dt>允许路径</dt>
                <dd>{target.paths.join("、")}</dd>
                <dt>禁止路径</dt>
                <dd>{target.deny_paths.join("、") || "无"}</dd>
                <dt>绑定 IP</dt>
                <dd>{target.bound_ips.join("、") || "尚未绑定"}</dd>
                <dt>授权说明</dt>
                <dd
                  style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}
                >
                  {target.statement}
                </dd>
                <dt>到期时间</dt>
                <dd>{time(target.expires_at)}</dd>
                <dt>所有权声明</dt>
                <dd>{target.ownership_declared ? "已声明" : "未声明"}</dd>
              </dl>
            </details>
            {!target.revoked && target.kind !== "src" && (
              <details>
                <summary>验证说明与挑战</summary>
                <p>
                  本机 / 本人应用：将下方内容放入被测项目的
                  public/.well-known/autominer-verification.txt，并确认目标端口下该地址返回挑战值。靶场需核对来源与绑定
                  IP。
                </p>
                <code style={{ overflowWrap: "anywhere" }}>
                  {target.challenge}
                </code>
                <p>此文件仅对应目标 ID：{target.id}</p>
                <button
                  disabled={busy}
                  onClick={() => download(target.challenge)}
                >
                  下载验证文件
                </button>
                <div className="actions">
                  <button
                    disabled={busy}
                    onClick={() =>
                      run(() => api(`/targets/${target.id}/verify`, {}))
                    }
                  >
                    HTTP / 靶场验证
                  </button>
                  {target.kind === "owned" && (
                    <button
                      disabled={busy}
                      onClick={() =>
                        run(() =>
                          api(`/targets/${target.id}/verify?method=dns`, {}),
                        )
                      }
                    >
                      DNS 验证
                    </button>
                  )}
                </div>
              </details>
            )}
            <div className="actions">
              <button disabled={busy} onClick={() => start(target)}>
                编辑
              </button>
              {!target.revoked && (
                <button
                  disabled={busy}
                  onClick={() => {
                    if (
                      target.verified &&
                      target.expires_at > Date.now() / 1000 &&
                      onOpen
                    )
                      onOpen(target.id);
                    else onSelect?.(target.id);
                  }}
                >
                  {target.verified && target.expires_at > Date.now() / 1000
                    ? "开始检查"
                    : "选择目标"}
                </button>
              )}
              {!target.revoked && (
                <button
                  className="danger"
                  disabled={busy}
                  onClick={() =>
                    run(() => api(`/targets/${target.id}/revoke`, {}))
                  }
                >
                  撤销授权
                </button>
              )}
              <button
                className="danger"
                disabled={busy}
                onClick={() => setConfirmDelete(target.id)}
              >
                删除
              </button>
            </div>
            {confirmDelete === target.id && (
              <div role="alert">
                <p>
                  确认删除「{target.name}
                  」？相关任务将停止，目标从列表移除，历史证据与报告保留。
                </p>
                <div className="actions">
                  <button
                    className="danger"
                    disabled={busy}
                    onClick={() =>
                      run(async () => {
                        await api(`/targets/${target.id}`, {}, "DELETE");
                        if (editing?.id === target.id) start(null);
                        setConfirmDelete("");
                      })
                    }
                  >
                    确认删除
                  </button>
                  <button disabled={busy} onClick={() => setConfirmDelete("")}>
                    取消
                  </button>
                </div>
              </div>
            )}
          </article>
        ))}
      </section>
    </div>
  );
}
