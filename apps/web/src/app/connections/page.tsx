"use client";
import * as React from "react";
import { Check, CheckCircle2, Cloud, Copy, Plug, Play, Plus, RefreshCw, ScrollText, Trash2, XCircle } from "lucide-react";
import { api, useAct, useApi } from "@/lib/api";
import { ago, fmtTime } from "@/lib/utils";
import { useCan } from "@/components/shell";
import { Button, Card, ErrorBox, Input, Json, Label, Loading, PageHeader, Select, Status, Table, Tag, Td, Textarea } from "@/components/ui";

export default function Connections() {
  const can = useCan();
  const q = useApi<any>(["connections"], "/cloud-connections", { refetchInterval: 15_000 });
  const jobs = useApi<any>(["jobs"], "/ingestion/jobs?limit=20", { refetchInterval: 5_000 });
  const [adding, setAdding] = React.useState<"pick" | string | null>(null);
  return (
    <>
      <PageHeader title="Connections" description="Read-only connectors to clouds and log platforms. Vigil never modifies customer infrastructure."
        actions={can("connections:write") && <Button onClick={() => setAdding("pick")}><Plus className="size-4" />Add connection</Button>} />
      {adding === "pick" && <ProviderPicker onPick={setAdding} onClose={() => setAdding(null)} />}
      {adding && adding !== "pick" && <AddConnection key={adding} provider={adding} onBack={() => setAdding("pick")} onDone={() => setAdding(null)} />}
      {q.isLoading ? <Loading /> : <div className="space-y-4">{(q.data?.items ?? []).map((c: any) => <ConnectionCard key={c.id} c={c} />)}</div>}
      {q.data?.items?.length === 0 && !adding && <Card><p className="text-sm text-muted">No connections yet. Start with <b>Add connection</b> and pick a cloud or log platform.</p></Card>}
      <Card title="Ingestion jobs" pad={false} className="mt-4">
        <Table head={["Created", "Kind", "Range", "Status", "Pages", "Seen", "Inserted", "Duplicates", "Note"]}>
          {(jobs.data?.items ?? []).map((j: any) => (
            <tr key={j.id}>
              <Td className="whitespace-nowrap text-xs text-muted">{ago(j.createdAt)}</Td><Td className="text-xs">{j.kind}</Td>
              <Td className="whitespace-nowrap text-xs">{fmtTime(j.rangeStart)} → {fmtTime(j.rangeEnd)}</Td><Td><Status value={j.status} /></Td>
              <Td className="tabular-nums">{j.pagesFetched}</Td><Td className="tabular-nums">{j.eventsSeen}</Td><Td className="tabular-nums">{j.eventsInserted}</Td><Td className="tabular-nums">{j.duplicates}</Td>
              <Td className="max-w-xs truncate text-xs text-muted">{j.error ?? ""}</Td>
            </tr>
          ))}
        </Table>
      </Card>
    </>
  );
}

/** Registry metadata from GET /connectors (field schemas, auth modes; never secrets). */
interface FieldDef { name: string; scope: "config" | "credentials"; label: string; help: string | null; kind: "text" | "select" | "secret" | "list" | "json" | "textarea" | "number"; required: boolean; secret: boolean; default?: unknown; placeholder?: string; pattern?: string; options?: Array<{ value: string; label: string }>; showWhen?: Record<string, string[]> }
interface ConnectorDef { id: string; kind: "cloud" | "log_platform"; displayName: string; description: string; fields: FieldDef[]; formHelp: string | null }
const useConnectors = () => useApi<{ items: ConnectorDef[] }>(["connectors"], "/connectors");
const KIND_LABEL: Record<string, string> = { cloud: "Cloud providers", log_platform: "Log platforms" };

function ProviderPicker({ onPick, onClose }: { onPick: (id: string) => void; onClose: () => void }) {
  const reg = useConnectors();
  const groups = Object.entries((reg.data?.items ?? []).reduce<Record<string, ConnectorDef[]>>((acc, d) => ((acc[d.kind] ??= []).push(d), acc), {}));
  return (
    <Card title="Add a connection" className="mb-4" actions={<Button size="sm" variant="ghost" onClick={onClose}>Close</Button>}>
      {reg.isLoading ? <Loading /> : <ErrorBox error={reg.error} />}
      <div className="space-y-4">
        {groups.map(([kind, defs]) => (
          <div key={kind}>
            <div className="mb-2 text-xs font-semibold uppercase text-muted">{KIND_LABEL[kind] ?? kind}</div>
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {defs.map((d) => (
                <button key={d.id} type="button" onClick={() => onPick(d.id)} className="rounded-md border border-border p-3 text-left transition hover:border-foreground/40 hover:bg-foreground/5">
                  <div className="flex items-center gap-2 font-medium">{d.kind === "cloud" ? <Cloud className="size-4" /> : <ScrollText className="size-4" />}{d.displayName}</div>
                  <div className="mt-1 text-xs text-muted">{d.description}</div>
                </button>
              ))}
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
}

const initialValue = (f: FieldDef): string => {
  if (f.default === undefined) return "";
  if (Array.isArray(f.default)) return f.default.join(", ");
  return typeof f.default === "object" ? JSON.stringify(f.default, null, 2) : String(f.default);
};
const visible = (f: FieldDef, v: Record<string, string>) => !f.showWhen || Object.entries(f.showWhen).every(([k, allowed]) => allowed.includes(v[k] ?? ""));

/** Turn form strings into the typed request body; empty optional fields are omitted. */
function buildBody(def: ConnectorDef, v: Record<string, string>, displayName: string) {
  const out = { provider: def.id, displayName, config: {} as Record<string, unknown>, credentials: {} as Record<string, unknown> };
  for (const f of def.fields) {
    if (!visible(f, v)) continue;
    const raw = (v[f.name] ?? "").trim();
    if (!raw) continue;
    let val: unknown = raw;
    if (f.kind === "list") val = raw.split(/[,\n]/).map((s) => s.trim()).filter(Boolean);
    else if (f.kind === "number") val = Number(raw);
    else if (f.kind === "json") { try { val = JSON.parse(raw); } catch { throw new Error(`${f.label}: invalid JSON`); } }
    out[f.scope][f.name] = val;
  }
  return Object.keys(out.credentials).length ? out : { ...out, credentials: undefined };
}

function AddConnection({ provider, onBack, onDone }: { provider: string; onBack: () => void; onDone: () => void }) {
  const reg = useConnectors();
  const def = reg.data?.items.find((d) => d.id === provider);
  const [displayName, setDisplayName] = React.useState("");
  const [v, setV] = React.useState<Record<string, string>>({});
  React.useEffect(() => { if (def) setV(Object.fromEntries(def.fields.map((f) => [f.name, initialValue(f)]))); }, [def]);
  const [result, setResult] = React.useState<any>(null);
  const create = useAct(() => api("/cloud-connections", { method: "POST", body: buildBody(def!, v, displayName) }), [["connections"]]);
  if (!def) return reg.isLoading ? <Loading /> : <Card className="mb-4"><ErrorBox error={reg.error ?? { message: `Unknown connector ${provider}` }} /></Card>;
  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => setV({ ...v, [k]: e.target.value });
  return (
    <Card title={`Connect ${def.displayName}`} className="mb-4" actions={<>{!result && <Button size="sm" variant="ghost" onClick={onBack}>Back</Button>}<Button size="sm" variant="ghost" onClick={onDone}>Close</Button></>}>
      {!result ? (
        <form className="grid gap-3 md:grid-cols-2" onSubmit={(e) => { e.preventDefault(); create.mutate(undefined as any, { onSuccess: setResult }); }}>
          <div><Label>Display name</Label><Input value={displayName} onChange={(e) => setDisplayName(e.target.value)} required placeholder={`Production ${def.displayName}`} /></div>
          {def.fields.filter((f) => visible(f, v)).map((f) => <Field key={f.name} f={f} value={v[f.name] ?? ""} onChange={set(f.name)} />)}
          {def.formHelp && <div className="text-xs text-muted md:col-span-2">{def.formHelp}</div>}
          <div className="md:col-span-2"><Button variant="primary" loading={create.isPending}><Plug className="size-4" />Create connection</Button></div>
          <div className="md:col-span-2"><ErrorBox error={create.error} /></div>
        </form>
      ) : (
        <Onboarding value={result.onboarding} />
      )}
    </Card>
  );
}

/** HTML `pattern` is compiled with the `v` flag and implicitly anchored; skip server patterns that don't fit (the API validates anyway). */
function htmlPattern(p?: string): string | undefined {
  if (!p) return undefined;
  const inner = p.replace(/^\^/, "").replace(/\$$/, "");
  try { new RegExp(`^(?:${inner})$`, "v"); return inner; } catch { return undefined; }
}

type Step = string | { title: string; detail?: string; commands?: string[] };

/** Post-create checklist: numbered steps with copyable commands; anything unstructured stays available as raw JSON. */
function Onboarding({ value }: { value: any }) {
  const steps: Step[] | null = Array.isArray(value?.steps) ? value.steps : null;
  const [raw, setRaw] = React.useState(!steps);
  return (
    <div className="space-y-3">
      <p className="text-sm">Connection created. {steps ? "Finish setup:" : <>Apply this read-only access configuration, then use <b>Test</b> below.</>}</p>
      {steps && (
        <ol className="space-y-3">
          {steps.map((st, i) => {
            const s = typeof st === "string" ? { title: st } : st;
            return (
              <li key={i} className="flex gap-3 text-[13px]">
                <span className="flex size-5 shrink-0 items-center justify-center rounded-full border border-border text-[11px] tabular-nums">{i + 1}</span>
                <div className="min-w-0 flex-1 space-y-1">
                  <div className="font-medium">{s.title}</div>
                  {s.detail && <div className="text-xs text-muted">{s.detail}</div>}
                  {s.commands?.map((cmd) => <CopyCommand key={cmd} cmd={cmd} />)}
                </div>
              </li>
            );
          })}
        </ol>
      )}
      {value?.note && <p className="text-xs text-muted">{value.note}</p>}
      {steps && <button type="button" className="text-xs text-muted underline" onClick={() => setRaw(!raw)}>{raw ? "Hide" : "Show"} raw details</button>}
      {raw && <Json value={value} />}
    </div>
  );
}

function CopyCommand({ cmd }: { cmd: string }) {
  const [copied, setCopied] = React.useState(false);
  return (
    <div className="flex items-start gap-2 rounded-md border border-border bg-foreground/5 px-2 py-1.5">
      <code className="mono min-w-0 flex-1 break-all text-[11px]">{cmd}</code>
      <button type="button" className="shrink-0 text-muted hover:text-foreground" aria-label="Copy command"
        onClick={() => { navigator.clipboard?.writeText(cmd).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500); }, () => {}); }}>
        {copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
      </button>
    </div>
  );
}

function Field({ f, value, onChange }: { f: FieldDef; value: string; onChange: (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => void }) {
  const optional = !f.required && f.default === undefined;
  const label = <Label hint={f.help ?? undefined}>{f.label}{optional && !/optional/i.test(f.label) ? " (optional)" : ""}</Label>;
  if (f.kind === "select") return <div>{label}<Select className="w-full" value={value} onChange={onChange} required={f.required}>{optional && <option value="">—</option>}{f.options?.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}</Select></div>;
  if (f.kind === "json" || f.kind === "textarea") return <div className="md:col-span-2">{label}<Textarea className="mono w-full text-xs" rows={5} value={value} onChange={onChange} required={f.required} placeholder={f.placeholder} /></div>;
  return (
    <div>{label}
      <Input value={value} onChange={onChange} required={f.required} pattern={htmlPattern(f.pattern)} placeholder={f.placeholder ?? (f.kind === "list" ? "comma-separated" : undefined)}
        type={f.secret || f.kind === "secret" ? "password" : f.kind === "number" ? "number" : "text"} autoComplete={f.secret ? "off" : undefined} />
      {f.secret && <div className="mt-0.5 text-[11px] text-muted">Stored encrypted; never shown again.</div>}
    </div>
  );
}

function ConnectionCard({ c }: { c: any }) {
  const can = useCan();
  const test = useAct(() => api(`/cloud-connections/${c.id}/test`, { method: "POST" }), [["connections"]]);
  const [showSources, setShowSources] = React.useState(false);
  const [filters, setFilters] = React.useState<Record<string, string>>({});
  const disc = useApi<any>(["sources", c.id], showSources ? `/cloud-connections/${c.id}/sources` : null);
  const enable = useAct((s: any) => api(`/cloud-connections/${c.id}/sources`, { method: "POST", body: { sourceType: s.sourceType, name: s.name, filter: s.filter, enabled: s.enabled, pollIntervalSeconds: 300 } }), [["connections"], ["sources", c.id]]);
  const disconnect = useAct(() => api(`/cloud-connections/${c.id}`, { method: "DELETE" }), [["connections"]]);
  const tr = test.data ?? c.lastTestResult;
  const cfg = c.config;
  return (
    <Card title={<span className="flex items-center gap-2"><Tag className="uppercase">{c.provider}</Tag>{c.displayName}<span className="mono text-xs font-normal text-muted">{c.accountRef ?? cfg.projectId ?? cfg.accountId}</span></span>}
      actions={<><Status value={c.status} />{can("connections:write") && c.status !== "disconnected" && <>
        <Button size="sm" loading={test.isPending} onClick={() => test.mutate(undefined as any)}><RefreshCw className="size-3.5" />Test</Button>
        <Button size="sm" onClick={() => setShowSources(!showSources)}>Sources</Button>
        <Button size="sm" variant="ghost" onClick={() => confirm("Disconnect? Stored credentials are deleted and ingestion stops. Ingested data is retained per your retention policy.") && disconnect.mutate(undefined as any)}><Trash2 className="size-3.5" /></Button>
      </>}</>}>
      <div className="grid gap-4 lg:grid-cols-2">
        <div className="text-[13px]">
          <div className="text-xs text-muted">{c.connectorName ?? c.provider} · auth: <span className="mono">{c.authMode ?? cfg.authMode ?? "sts:assume-role"}</span> · last tested {ago(c.lastTestedAt)} · last successful ingest {ago(c.lastSuccessfulIngestAt)}</div>
          {tr && (
            <div className="mt-2 space-y-1.5">
              <div className="flex items-center gap-2">{tr.ok ? <CheckCircle2 className="size-4 text-emerald-500" /> : <XCircle className="size-4 text-red-500" />}<span>{tr.ok ? "Connection OK" : "Connection failed"}</span>{tr.ok && (!tr.readOnly ? <Tag className="text-amber-600">over-privileged</Tag> : (tr.checks?.length ?? 0) > 0 ? <Tag className="text-emerald-600">read-only verified</Tag> : <Tag className="text-amber-600">read-only not verified</Tag>)}<span className="text-xs text-muted">as {tr.principal ?? "unknown principal"}</span></div>
              {tr.errors?.map((e: string, i: number) => <div key={i} className="text-xs text-red-600 dark:text-red-400">{e}</div>)}
              {tr.warnings?.map((w: string, i: number) => <div key={i} className="text-xs text-amber-700 dark:text-amber-300">{w}</div>)}
              <div className="flex flex-wrap gap-1">{tr.checks?.map((p: any) => <Tag key={p.permission} className={p.granted ? (p.excessive ? "text-amber-600" : "text-emerald-600") : "line-through"}>{p.permission}</Tag>)}</div>
            </div>
          )}
        </div>
        <div>
          <div className="mb-1 text-xs font-semibold uppercase text-muted">Enabled sources</div>
          {(c.sources ?? []).length === 0 && <p className="text-xs text-muted">None — open Sources to discover and enable.</p>}
          <ul className="space-y-2">{(c.sources ?? []).map((s: any) => <SourceRow key={s.id} s={s} />)}</ul>
        </div>
      </div>
      {showSources && (
        <div className="mt-4 border-t border-border pt-3">
          {disc.isLoading ? <Loading /> : <>
            {disc.data?.error && <ErrorBox error={{ message: `Discovery failed: ${disc.data.error}` }} />}
            <Table head={["Source", "Filter", "Observed", ""]}>
              {(disc.data?.discovered ?? []).map((s: any) => {
                const key = s.sourceType + s.name;
                const configured = c.sources?.find((x: any) => x.sourceType === s.sourceType && x.name === s.name);
                const editable = !!s.meta?.editableFilter && can("connections:write") && !configured?.enabled;
                const filter = filters[key] ?? configured?.filter ?? s.filter;
                return (
                  <tr key={key}>
                    <Td><div className="font-medium">{s.name}</div><div className="text-xs text-muted">{s.description}</div></Td>
                    <Td className="mono max-w-sm break-all text-[11px]">{editable
                      ? <Input aria-label={`Query for ${s.name}`} className="mono w-full text-[11px]" value={filter ?? ""} onChange={(e) => setFilters({ ...filters, [key]: e.target.value })} />
                      : (filter ?? "—")}</Td>
                    <Td>{s.available ? <Status value="healthy" /> : <span className="text-xs text-muted" title={s.meta?.error}>not observed</span>}</Td>
                    <Td>{can("connections:write") && (configured?.enabled ? <Button size="sm" onClick={() => enable.mutate({ ...s, filter: configured.filter, enabled: false })}>Disable</Button> : <Button size="sm" variant="primary" onClick={() => enable.mutate({ ...s, filter: filter?.trim() ? filter.trim() : s.filter, enabled: true })}>Enable (poll)</Button>)}</Td>
                  </tr>
                );
              })}
            </Table>
          </>}
        </div>
      )}
      <ErrorBox error={test.error ?? enable.error ?? disconnect.error} />
    </Card>
  );
}

function SourceRow({ s }: { s: any }) {
  const can = useCan();
  const [hours, setHours] = React.useState("24");
  const run = useAct(() => api("/ingestion/jobs", { method: "POST", body: { logSourceId: s.id, start: new Date(Date.now() - Number(hours) * 3600_000).toISOString(), end: new Date().toISOString() } }), [["jobs"]]);
  return (
    <li className="rounded-md border border-border p-2 text-[13px]">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div><span className="font-medium">{s.name}</span> <Status value={s.enabled ? "healthy" : "disconnected"} /></div>
        {can("ingestion:run") && <div className="flex items-center gap-1.5"><Select value={hours} onChange={(e) => setHours(e.target.value)} aria-label="Historical range">{[["1", "1h"], ["6", "6h"], ["24", "24h"], ["72", "3d"], ["168", "7d"], ["720", "30d"]].map(([v, l]) => <option key={v} value={v}>Last {l}</option>)}</Select><Button size="sm" loading={run.isPending} onClick={() => run.mutate(undefined as any)}><Play className="size-3.5" />Ingest history</Button></div>}
      </div>
      <div className="mt-1 text-xs text-muted">{s.ingestionMode} every {s.pollIntervalSeconds}s · watermark {s.watermark ? fmtTime(s.watermark) : "none"}</div>
      {s.filter && <div className="mono mt-0.5 truncate text-[11px] text-muted" title={s.filter}>{s.filter}</div>}
      {run.isSuccess && <div className="text-xs text-emerald-600">Job queued.</div>}
      <ErrorBox error={run.error} />
    </li>
  );
}
