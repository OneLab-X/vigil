"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { AlertTriangle, CheckCircle2, CircleHelp, Clock, RefreshCw, XCircle } from "lucide-react";
import { api } from "@/lib/api";
import { ago, cn, fmtTime, pct } from "@/lib/utils";
import { useCan, useMe } from "@/components/shell";
import { Button, Card, ErrorBox, Loading, PageHeader, Stat, Status, Table, Tag, Td } from "@/components/ui";

type Win = "1h" | "24h" | "7d" | "30d";
const WINDOWS: Win[] = ["1h", "24h", "7d", "30d"];

// ---------- formatting ----------
const dur = (s?: number | null) => {
  if (s === null || s === undefined) return "—";
  if (s < 60) return `${Math.round(s)}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ${Math.round((s % 3600) / 60)}m`;
  return `${Math.floor(s / 86400)}d ${Math.round((s % 86400) / 3600)}h`;
};
const ms = (v?: number | null) => (v === null || v === undefined ? "—" : v >= 1000 ? `${(v / 1000).toFixed(2)} s` : `${Math.round(v)} ms`);
const bytes = (b?: number | null) => {
  if (b === null || b === undefined) return "—";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0, v = b;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${u[i]}`;
};
const num = (n?: number | null) => (n === null || n === undefined ? "—" : n.toLocaleString());
/** USD arrives as a fixed-decimal string; show 4 decimals without float math on the value. */
const usd = (s?: string | null) => {
  if (!s) return "—";
  const [w, f = ""] = s.split(".");
  return `$${Number(w).toLocaleString()}.${(f + "0000").slice(0, 4)}`;
};
const pctOrDash = (n?: number | null) => (n === null || n === undefined ? "—" : n > 0 && n < 0.01 ? "<1%" : pct(n));

const TONE: Record<string, { icon: React.ElementType; cls: string }> = {
  ok: { icon: CheckCircle2, cls: "text-emerald-600 dark:text-emerald-400" },
  down: { icon: XCircle, cls: "text-red-600 dark:text-red-400" },
  stale: { icon: AlertTriangle, cls: "text-amber-600 dark:text-amber-400" },
  unknown: { icon: CircleHelp, cls: "text-slate-500" },
};

function ComponentTile({ c }: { c: any }) {
  const t = c.status === "down" && !c.required ? { ...TONE.stale! } : TONE[c.status] ?? TONE.unknown!;
  const Icon = t.icon;
  const label = c.status === "down" && !c.required ? "unavailable (optional)" : c.status;
  return (
    <div className="rounded-lg border border-border bg-panel p-3">
      <div className="flex items-center justify-between gap-2 text-xs text-muted"><span className="truncate">{c.label}</span><Icon className={cn("size-4 shrink-0", t.cls)} aria-hidden /></div>
      <div className={cn("mt-1 text-sm font-semibold capitalize", t.cls)}>{label}</div>
      <div className="mt-0.5 truncate text-[11px] text-muted" title={c.detail ?? undefined}>{c.detail ?? (c.lastSeenAt ? `last seen ${ago(c.lastSeenAt)}` : " ")}</div>
    </div>
  );
}

function Empty({ children }: { children: React.ReactNode }) { return <div className="p-8 text-center text-sm text-muted">{children}</div>; }

function useVisible() {
  const [v, setV] = React.useState(true);
  React.useEffect(() => {
    const on = () => setV(document.visibilityState === "visible");
    on(); document.addEventListener("visibilitychange", on);
    return () => document.removeEventListener("visibilitychange", on);
  }, []);
  return v;
}

export default function Operations() {
  const me = useMe();
  const can = useCan();
  const allowed = can("operations:read");
  const [win, setWin] = React.useState<Win>("24h");
  const visible = useVisible();
  const q = useQuery<any>({
    queryKey: ["operations", win],
    queryFn: () => api(`/operations/overview?window=${win}`),
    enabled: allowed,
    refetchInterval: visible ? 30_000 : false, // paused while the tab is hidden
    refetchIntervalInBackground: false,
    placeholderData: (prev: any) => prev,
  });

  if (me && !allowed) {
    return (
      <>
        <PageHeader title="Operations" />
        <Card><p className="text-sm text-muted">System health is available to tenant admins and owners. Ask an owner if you need access.</p></Card>
      </>
    );
  }

  const d = q.data;
  const actions = (
    <>
      <div role="group" aria-label="Time window" className="inline-flex rounded-md border border-border bg-panel p-0.5">
        {WINDOWS.map((w) => (
          <button key={w} onClick={() => setWin(w)} aria-pressed={win === w}
            className={cn("rounded px-2.5 py-1 text-xs font-medium", win === w ? "bg-panel-2 text-fg" : "text-muted hover:text-fg")}>{w}</button>
        ))}
      </div>
      <Button size="sm" variant="ghost" onClick={() => q.refetch()} loading={q.isFetching} aria-label="Refresh"><RefreshCw className={cn("size-3.5", q.isFetching && "hidden")} />Refresh</Button>
    </>
  );

  return (
    <>
      <PageHeader title="Operations" description="Health of this tenant's pipeline: components, ingestion lag, job queue, failures, API latency, AI cost and storage. Refreshes every 30 s." actions={actions} />
      {q.error ? (
        <div className="mb-4 space-y-2">
          <ErrorBox error={new Error(`Couldn't load operations data: ${(q.error as Error).message}`)} />
          <Button size="sm" onClick={() => q.refetch()}>Retry</Button>
        </div>
      ) : null}
      {!d && q.isLoading ? <Loading /> : d && (
        <div className="space-y-4">
          <div className="text-[11px] text-muted">Updated {fmtTime(d.generatedAt)} · server time {d.queryMs} ms</div>

          {/* status strip */}
          <section aria-label="Component health" className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
            {d.components.map((c: any) => <ComponentTile key={c.id} c={c} />)}
          </section>

          {/* ingestion */}
          <Card pad={false} title="Ingestion lag by log source" actions={
            <div className="flex flex-wrap gap-1">{Object.entries(d.ingestion.counts).filter(([, n]) => (n as number) > 0).map(([k, n]) => <Tag key={k}>{String(n)} {k.replace(/_/g, " ")}</Tag>)}</div>
          }>
            {d.ingestion.sources.length === 0 ? (
              <Empty>No log sources connected. <Link className="text-accent underline-offset-2 hover:underline" href="/connections">Connect a cloud account</Link> to start ingesting.</Empty>
            ) : (
              <Table head={["Source", "Status", "Lag", "Watermark", "Last success", "Last error"]}>
                {d.ingestion.sources.map((s: any) => (
                  <tr key={s.id}>
                    <Td><div className="font-medium">{s.name}</div><div className="mono text-[11px] text-muted">{s.sourceType}{s.activeJobs ? ` · ${s.activeJobs} job${s.activeJobs > 1 ? "s" : ""} active` : ""}</div></Td>
                    <Td><Status value={s.status} /></Td>
                    <Td className={cn("tabular-nums", s.status === "lagging" && "text-amber-600 dark:text-amber-400")}>{dur(s.lagSeconds)}</Td>
                    <Td className="whitespace-nowrap text-xs text-muted">{s.watermark ? fmtTime(s.watermark) : "—"}</Td>
                    <Td className="whitespace-nowrap text-xs text-muted">{ago(s.lastSuccessAt)}</Td>
                    <Td className="max-w-[360px] text-xs"><span className="line-clamp-2 break-words text-red-700 dark:text-red-300" title={s.lastError ?? undefined}>{s.lastError ?? <span className="text-muted">—</span>}</span></Td>
                  </tr>
                ))}
              </Table>
            )}
            <p className="border-t border-border px-4 py-2 text-[11px] text-muted">Lagging = event watermark older than {d.ingestion.thresholdMinutes} min. Failing = the most recent finished job failed.</p>
          </Card>

          {/* queue + failures */}
          <div className="grid gap-4 lg:grid-cols-2">
            <Card title="Job queue">
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
                <Stat label="Runnable" value={num(d.queue.runnable)} sub={`${num(d.queue.scheduled)} scheduled · ${num(d.queue.retrying)} retrying`} />
                <Stat label="Oldest queued" value={dur(d.queue.oldestQueuedSeconds)} icon={Clock} tone={d.queue.oldestQueuedSeconds > 600 ? "amber" : undefined} />
                <Stat label="Running" value={num(d.queue.running)} />
                <Stat label="Stuck" value={num(d.queue.stuck)} sub={`locked > ${d.queue.stuckAfterMinutes} min`} tone={d.queue.stuck ? "red" : "green"} />
                <Stat label="Dead-lettered" value={num(d.queue.deadLettered)} sub="failed, out of retries" tone={d.queue.deadLettered ? "red" : "green"} />
              </div>
              <div className="mt-3">
                <Table head={["Type", "Status", "Jobs"]} empty="No jobs in this window.">
                  {d.queue.byTypeStatus.map((r: any) => <tr key={`${r.type}-${r.status}`}><Td className="mono text-xs">{r.type}</Td><Td><Status value={r.status === "done" ? "succeeded" : r.status} /></Td><Td className="tabular-nums">{num(r.n)}</Td></tr>)}
                </Table>
              </div>
            </Card>
            <Card title="Failures">
              <Table head={["", "Last 24h", "Last 7d"]}>
                {([["Jobs (dead-lettered)", "jobs"], ["Ingestion jobs", "ingestion"], ["Investigations", "investigations"]] as const).map(([label, k]) => (
                  <tr key={k}><Td>{label}</Td><Td className={cn("tabular-nums", d.failures.counts[k]["24h"] && "font-semibold text-red-600 dark:text-red-400")}>{d.failures.counts[k]["24h"]}</Td><Td className="tabular-nums">{d.failures.counts[k]["7d"]}</Td></tr>
                ))}
              </Table>
              <h4 className="mb-1 mt-4 text-xs font-medium text-muted">Most recent errors</h4>
              {d.failures.recent.length === 0 ? <p className="py-4 text-center text-sm text-muted">No failures in the last 7 days.</p> : (
                <ul className="divide-y divide-border">
                  {d.failures.recent.map((f: any) => (
                    <li key={`${f.kind}-${f.id}`} className="py-2 text-[13px]">
                      <div className="flex flex-wrap items-center gap-2"><Tag>{f.kind}</Tag><span className="font-medium">{f.label}</span><Status value={f.status} /><span className="ml-auto text-[11px] text-muted">{ago(f.at)}</span></div>
                      <div className="mono mt-1 break-words text-[11.5px] text-muted">{f.error ?? "no error message"}</div>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
          </div>

          {/* latency */}
          <Card title={`API latency · last ${d.latency.windowHours >= 168 && win === "30d" ? "7d (retention limit)" : win}`}>
            {d.latency.overall.requests === 0 ? <Empty>No API requests recorded in this window yet.</Empty> : (
              <>
                <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
                  <Stat label="Requests" value={num(d.latency.overall.requests)} />
                  <Stat label="p50" value={ms(d.latency.overall.p50Ms)} />
                  <Stat label="p95" value={ms(d.latency.overall.p95Ms)} />
                  <Stat label="p99" value={ms(d.latency.overall.p99Ms)} />
                  <Stat label="Error rate (5xx)" value={pctOrDash(d.latency.overall.errorRate)} tone={d.latency.overall.errorRate > 0.01 ? "red" : undefined} sub={`4xx ${pctOrDash(d.latency.overall.clientErrorRate)}`} />
                </div>
                <div className="mt-4 h-56" aria-label="Latency percentiles over time">
                  <ResponsiveContainer>
                    <LineChart data={d.latency.series} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                      <XAxis dataKey="t" tickFormatter={(t) => new Date(t).toLocaleString(undefined, win === "1h" || win === "24h" ? { hour: "2-digit", minute: "2-digit" } : { month: "short", day: "numeric" })} tick={{ fontSize: 11, fill: "var(--muted)" }} stroke="var(--border)" minTickGap={24} />
                      <YAxis tickFormatter={(v) => `${v} ms`} tick={{ fontSize: 11, fill: "var(--muted)" }} stroke="var(--border)" width={64} />
                      <Tooltip contentStyle={{ background: "var(--panel)", border: "1px solid var(--border)", fontSize: 12, color: "var(--fg)" }} labelFormatter={(t) => fmtTime(t as string)} formatter={(v: any, n: any) => [ms(v), n]} />
                      <Legend wrapperStyle={{ fontSize: 12 }} />
                      <Line type="monotone" dataKey="p50Ms" name="p50" stroke="var(--series-1)" strokeWidth={2} dot={d.latency.series.length <= 2} isAnimationActive={false} connectNulls />
                      <Line type="monotone" dataKey="p95Ms" name="p95" stroke="var(--series-2)" strokeWidth={2} dot={d.latency.series.length <= 2} isAnimationActive={false} connectNulls />
                      <Line type="monotone" dataKey="p99Ms" name="p99" stroke="var(--series-3)" strokeWidth={2} dot={d.latency.series.length <= 2} isAnimationActive={false} connectNulls />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
                <div className="mt-3">
                  <Table head={["Route group", "Requests", "p50", "p95", "p99", "5xx rate"]}>
                    {d.latency.groups.map((g: any) => (
                      <tr key={g.group}><Td className="mono text-xs">{g.group}</Td><Td className="tabular-nums">{num(g.requests)}</Td><Td className="whitespace-nowrap tabular-nums">{ms(g.p50Ms)}</Td><Td className="whitespace-nowrap tabular-nums">{ms(g.p95Ms)}</Td><Td className="whitespace-nowrap tabular-nums">{ms(g.p99Ms)}</Td><Td className={cn("tabular-nums", g.errorRate > 0.01 && "text-red-600 dark:text-red-400")}>{pctOrDash(g.errorRate)}</Td></tr>
                    ))}
                  </Table>
                </div>
                <p className="mt-2 text-[11px] text-muted">Percentiles are estimated from per-minute histograms (bin {d.latency.binSize}). Rollups are kept {d.latency.retentionDays} days.</p>
              </>
            )}
          </Card>

          {/* cost */}
          <Card title={`AI cost · last ${win}`}>
            {!d.cost.hasInvestigations && d.cost.modelCalls === 0 ? <Empty>No investigations yet. Costs appear once an AI investigation runs.</Empty> : (
              <>
                <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
                  <Stat label="Total spend" value={usd(d.cost.totalUsd)} sub={`${num(d.cost.modelCalls)} model calls`} />
                  <Stat label="Completed investigations" value={num(d.cost.perInvestigation.completedRuns)} />
                  <Stat label="Avg per investigation" value={usd(d.cost.perInvestigation.avgUsd)} sub={`${num(d.cost.perInvestigation.avgTokens)} tokens avg`} />
                  <Stat label="p95 per investigation" value={usd(d.cost.perInvestigation.p95Usd)} />
                  <Stat label="Tokens" value={num(d.cost.inputTokens + d.cost.outputTokens)} sub={`${num(d.cost.inputTokens)} in · ${num(d.cost.outputTokens)} out`} />
                </div>
                <div className="mt-3">
                  <Table head={["Provider", "Model", "Calls", "Runs", "Input tokens", "Output tokens", "Cost"]} empty="No model usage in this window.">
                    {d.cost.byModel.map((m: any) => (
                      <tr key={`${m.provider}/${m.model}`}><Td>{m.provider}</Td><Td className="mono text-xs">{m.model}</Td><Td className="tabular-nums">{num(m.calls)}</Td><Td className="tabular-nums">{num(m.runs)}</Td><Td className="tabular-nums">{num(m.inputTokens)}</Td><Td className="tabular-nums">{num(m.outputTokens)}</Td><Td className="tabular-nums">{usd(m.costUsd)}</Td></tr>
                    ))}
                  </Table>
                </div>
              </>
            )}
          </Card>

          {/* storage */}
          <Card title="Storage">
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
              <Stat label="Security events" value={num(d.storage.securityEvents)} />
              <Stat label="Raw evidence objects" value={num(d.storage.rawEvidenceObjects)} />
              <Stat label="Raw evidence size" value={bytes(d.storage.rawEvidenceBytes)} />
              <Stat label="Database size" value={bytes(d.storage.databaseBytes)} sub={d.storage.databaseNote} />
            </div>
          </Card>
        </div>
      )}
    </>
  );
}
