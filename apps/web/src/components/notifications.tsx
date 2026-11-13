"use client";
import * as React from "react";
import { api, useAct, useApi } from "@/lib/api";
import { useCan } from "@/components/shell";
import { Button, Card, ErrorBox, Input, Label, Select, Table, Tag, Td } from "@/components/ui";

const SEVERITIES = ["info", "low", "medium", "high", "critical"];
const EVENTS: Array<{ v: string; l: string }> = [
  { v: "incident.created", l: "New incident" },
  { v: "incident.severity_raised", l: "Severity raised" },
];
type Form = {
  id?: string; kind: "slack" | "email"; name: string; enabled: boolean; minSeverity: string; events: string[]; redactEntities: boolean;
  label: string; webhookUrl: string;
  host: string; port: number; security: "starttls" | "tls" | "none"; allowInsecure: boolean; verifyCert: boolean;
  username: string; password: string; clearPassword: boolean; from: string; fromName: string; to: string;
  hasSecret?: boolean;
};
const blank = (kind: "slack" | "email"): Form => ({
  kind, name: "", enabled: true, minSeverity: "high", events: EVENTS.map((e) => e.v), redactEntities: false,
  label: "", webhookUrl: "", host: "", port: 587, security: "starttls", allowInsecure: false, verifyCert: true,
  username: "", password: "", clearPassword: false, from: "", fromName: "Vigil", to: "",
});
const fromRow = (r: any): Form => ({
  ...blank(r.kind), id: r.id, name: r.name, enabled: r.enabled, minSeverity: r.minSeverity, events: r.events, hasSecret: r.hasSecret,
  redactEntities: !!r.config?.redactEntities, label: r.config?.label ?? "",
  ...(r.kind === "email" ? { host: r.config.host, port: r.config.port, security: r.config.security, allowInsecure: !!r.config.allowInsecure, verifyCert: r.config.verifyCert !== false,
    username: r.config.username ?? "", from: r.config.from, fromName: r.config.fromName ?? "", to: (r.config.to ?? []).join(", ") } : {}),
});

function toBody(f: Form) {
  const common = { name: f.name, enabled: f.enabled, minSeverity: f.minSeverity, events: f.events };
  if (f.kind === "slack") {
    const config = { label: f.label || undefined, redactEntities: f.redactEntities };
    return f.id ? { ...common, config, webhookUrl: f.webhookUrl || null } : { kind: "slack", ...common, config, webhookUrl: f.webhookUrl };
  }
  const config = { host: f.host, port: Number(f.port), security: f.security, allowInsecure: f.security === "none" ? f.allowInsecure : undefined, verifyCert: f.verifyCert,
    username: f.username || null, from: f.from, fromName: f.fromName || null, to: f.to.split(/[\s,;]+/).filter(Boolean), redactEntities: f.redactEntities };
  return f.id ? { ...common, config, password: f.password || null, clearPassword: f.clearPassword || undefined } : { kind: "email", ...common, config, password: f.password || null };
}

const statusTone = (s?: string) => s === "sent" ? "text-emerald-600" : s === "failed" ? "text-red-600" : s === "suppressed" ? "text-amber-600" : "";

export function Notifications() {
  const can = useCan()("notifications:write");
  const q = useApi<any>(can ? ["notification-channels"] : ["notification-channels", "off"], can ? "/notification-channels" : null);
  const log = useApi<any>(can ? ["notification-deliveries"] : ["notification-deliveries", "off"], can ? "/notification-deliveries?limit=50" : null, { refetchInterval: 15_000 });
  const [f, setF] = React.useState<Form | null>(null);
  const [tests, setTests] = React.useState<Record<string, { ok?: boolean; detail?: string; busy?: boolean }>>({});
  const keys = [["notification-channels"], ["notification-deliveries"]];
  const save = useAct((v: Form) => v.id ? api(`/notification-channels/${v.id}`, { method: "PATCH", body: toBody(v) }) : api("/notification-channels", { method: "POST", body: toBody(v) }), keys);
  const patch = useAct((v: { id: string; body: any }) => api(`/notification-channels/${v.id}`, { method: "PATCH", body: v.body }), keys);
  const del = useAct((id: string) => api(`/notification-channels/${id}`, { method: "DELETE" }), keys);
  if (!can) return null;

  const set = <K extends keyof Form>(k: K, v: Form[K]) => setF((p) => (p ? { ...p, [k]: v } : p));
  const inp = (k: keyof Form) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => set(k, (e.target.type === "number" ? Number(e.target.value) : e.target.value) as never);
  const test = async (id: string) => {
    setTests((t) => ({ ...t, [id]: { busy: true } }));
    try { const r = await api<any>(`/notification-channels/${id}/test`, { method: "POST" }); setTests((t) => ({ ...t, [id]: r })); }
    catch (e) { setTests((t) => ({ ...t, [id]: { ok: false, detail: (e as Error).message } })); }
  };
  const secretHint = (f: Form) => f.id && f.hasSecret ? "stored — leave blank to keep" : undefined;

  return (
    <Card title="Notifications" actions={
      <div className="flex gap-1">
        {f ? <Button size="sm" onClick={() => { setF(null); save.reset(); }}>Cancel</Button> : <>
          <Button size="sm" onClick={() => setF(blank("slack"))}>Add Slack</Button>
          <Button size="sm" onClick={() => setF(blank("email"))}>Add email</Button>
        </>}
      </div>}>
      <div className="space-y-4 text-[13px]">
        <p className="text-xs text-muted">
          Alerts carry the case number, title, severity, status, primary entity, first/last seen, rule names and a link — never raw events or evidence.
          Turn on <i>Hide entity values</i> to keep IPs, users and resource names out of Slack and email. Each channel sends at most 20 alerts per 10 minutes, then one summary.
        </p>

        {f && (
          <form className="grid gap-2 rounded-md border border-border p-3 md:grid-cols-2" onSubmit={(e) => { e.preventDefault(); save.mutate(f, { onSuccess: () => setF(null) }); }}>
            <div><Label>Name</Label><Input className="w-full" required value={f.name} onChange={inp("name")} placeholder={f.kind === "slack" ? "SOC Slack" : "On-call email"} /></div>
            <div><Label>Minimum severity</Label><Select className="w-full" value={f.minSeverity} onChange={inp("minSeverity")}>{SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}</Select></div>
            <div className="md:col-span-2 flex flex-wrap gap-4">
              {EVENTS.map((ev) => (
                <label key={ev.v} className="flex items-center gap-1.5">
                  <input type="checkbox" checked={f.events.includes(ev.v)} onChange={(e) => set("events", e.target.checked ? [...f.events, ev.v] : f.events.filter((x) => x !== ev.v))} />{ev.l}
                </label>
              ))}
              <label className="flex items-center gap-1.5"><input type="checkbox" checked={f.redactEntities} onChange={(e) => set("redactEntities", e.target.checked)} />Hide entity values</label>
              <label className="flex items-center gap-1.5"><input type="checkbox" checked={f.enabled} onChange={(e) => set("enabled", e.target.checked)} />Enabled</label>
            </div>

            {f.kind === "slack" ? <>
              <div><Label hint={secretHint(f) ?? "stored encrypted, write-only"}>Incoming webhook URL</Label>
                <Input className="w-full" type="password" autoComplete="off" required={!f.id} value={f.webhookUrl} onChange={inp("webhookUrl")} placeholder="https://hooks.slack.com/services/…" /></div>
              <div><Label hint="display only">Channel label</Label><Input className="w-full" value={f.label} onChange={inp("label")} placeholder="#sec-alerts" /></div>
            </> : <>
              <div><Label>SMTP host</Label><Input className="w-full" required value={f.host} onChange={inp("host")} placeholder="smtp.example.com" /></div>
              <div className="grid grid-cols-2 gap-2">
                <div><Label>Port</Label><Input className="w-full" type="number" min={1} max={65535} required value={f.port} onChange={inp("port")} /></div>
                <div><Label>Security</Label><Select className="w-full" value={f.security} onChange={(e) => { const v = e.target.value as Form["security"]; setF((p) => p && ({ ...p, security: v, port: v === "tls" ? 465 : v === "starttls" && p.port === 465 ? 587 : p.port })); }}>
                  <option value="starttls">STARTTLS</option><option value="tls">TLS (implicit)</option><option value="none">None (unencrypted)</option></Select></div>
              </div>
              <div><Label hint="optional">Username</Label><Input className="w-full" autoComplete="off" value={f.username} onChange={inp("username")} /></div>
              <div><Label hint={secretHint(f) ?? "stored encrypted, write-only"}>Password</Label>
                <Input className="w-full" type="password" autoComplete="new-password" value={f.password} onChange={inp("password")} disabled={f.clearPassword} />
                {f.id && f.hasSecret && <label className="mt-1 flex items-center gap-1.5 text-xs"><input type="checkbox" checked={f.clearPassword} onChange={(e) => set("clearPassword", e.target.checked)} />Remove stored password</label>}
              </div>
              <div><Label>From address</Label><Input className="w-full" type="email" required value={f.from} onChange={inp("from")} placeholder="vigil@example.com" /></div>
              <div><Label hint="optional">From name</Label><Input className="w-full" value={f.fromName} onChange={inp("fromName")} /></div>
              <div className="md:col-span-2"><Label hint="comma-separated, up to 20">Recipients</Label><Input className="w-full" required value={f.to} onChange={inp("to")} placeholder="soc@example.com, oncall@example.com" /></div>
              <div className="md:col-span-2 flex flex-wrap gap-4">
                <label className="flex items-center gap-1.5"><input type="checkbox" checked={f.verifyCert} onChange={(e) => set("verifyCert", e.target.checked)} />Verify TLS certificate</label>
                {f.security === "none" && <label className="flex items-center gap-1.5 text-amber-700 dark:text-amber-300"><input type="checkbox" checked={f.allowInsecure} onChange={(e) => set("allowInsecure", e.target.checked)} />I understand alerts and the password travel unencrypted</label>}
              </div>
            </>}
            <div className="md:col-span-2"><Button variant="primary" size="sm" loading={save.isPending}>{f.id ? "Save changes" : "Add channel"}</Button><ErrorBox error={save.error} /></div>
          </form>
        )}

        <div className="-mx-4">
          <Table head={["Name", "Type", "Target", "Min severity", "Events", "Status", "Last delivery", ""]} empty="No channels yet. Add Slack or email to get incident alerts.">
            {(q.data?.items ?? []).map((r: any) => (
              <tr key={r.id} className="align-top">
                <Td className="font-medium">{r.name}</Td>
                <Td className="text-xs">{r.kind}</Td>
                <Td className="mono max-w-[220px] truncate text-xs">{r.kind === "slack" ? (r.config.label || "webhook") : `${r.config.host}:${r.config.port} → ${r.config.to.length} recipient${r.config.to.length === 1 ? "" : "s"}`}</Td>
                <Td><Tag>{r.minSeverity}+</Tag></Td>
                <Td className="text-xs">{r.events.map((e: string) => EVENTS.find((x) => x.v === e)?.l ?? e).join(", ")}</Td>
                <Td className="text-xs">{r.enabled ? "enabled" : "disabled"}{r.kind === "email" && r.config.security === "none" && <Tag className="ml-1 text-amber-600">unencrypted</Tag>}</Td>
                <Td className={`text-xs ${statusTone(r.lastDelivery?.status)}`} title={r.lastDelivery?.error ?? ""}>{r.lastDelivery ? `${r.lastDelivery.status} · ${new Date(r.lastDelivery.at).toLocaleString()}` : "—"}</Td>
                <Td>
                  <div className="flex min-w-[260px] flex-col gap-1">
                    <div className="flex gap-1">
                      <Button size="sm" loading={tests[r.id]?.busy} onClick={() => test(r.id)}>Send test</Button>
                      <Button size="sm" onClick={() => { save.reset(); setF(fromRow(r)); }}>Edit</Button>
                      <Button size="sm" onClick={() => patch.mutate({ id: r.id, body: { enabled: !r.enabled } })}>{r.enabled ? "Disable" : "Enable"}</Button>
                      <Button size="sm" variant="ghost" onClick={() => { if (confirm(`Delete channel "${r.name}"? Its stored secret is deleted too.`)) del.mutate(r.id); }}>Delete</Button>
                    </div>
                    {tests[r.id]?.detail && <span className={tests[r.id]?.ok ? "text-xs text-emerald-600" : "text-xs text-red-600"}>{tests[r.id]?.detail}</span>}
                  </div>
                </Td>
              </tr>
            ))}
          </Table>
        </div>
        <ErrorBox error={patch.error ?? del.error} />

        <div>
          <Label>Recent deliveries</Label>
          <div className="-mx-4 mt-1">
            <Table head={["When", "Channel", "Incident", "Event", "Status", "Attempts", "Error"]} empty="Nothing sent yet.">
              {(log.data?.items ?? []).map((d: any) => (
                <tr key={d.id}>
                  <Td className="text-xs tabular-nums">{new Date(d.createdAt).toLocaleString()}</Td>
                  <Td className="text-xs">{d.channelName}</Td>
                  <Td className="max-w-[260px] truncate text-xs"><a className="hover:underline" href={`/incidents/${d.incidentId}`}>#{d.caseNumber} {d.incidentTitle}</a></Td>
                  <Td className="text-xs">{EVENTS.find((x) => x.v === d.event)?.l ?? d.event}{d.dedupeKey ? ` → ${d.dedupeKey}` : ""}</Td>
                  <Td className={`text-xs ${statusTone(d.status)}`}>{d.status}</Td>
                  <Td className="text-xs tabular-nums">{d.attempts}</Td>
                  <Td className="max-w-[280px] truncate text-xs text-muted" title={d.lastError ?? ""}>{d.lastError ?? ""}</Td>
                </tr>
              ))}
            </Table>
          </div>
        </div>
      </div>
    </Card>
  );
}
