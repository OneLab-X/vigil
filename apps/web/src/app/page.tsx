"use client";
import Link from "next/link";
import { Activity, Bot, Cloud, DollarSign, Database, ShieldAlert, Siren, Timer } from "lucide-react";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useApi } from "@/lib/api";
import { ago } from "@/lib/utils";
import { Card, ErrorBox, Loading, PageHeader, Severity, Stat, Status, Table, Td, Verdict } from "@/components/ui";

const SEV_COLORS: Record<string, string> = { critical: "#dc2626", high: "#f97316", medium: "#f59e0b", low: "#0ea5e9", info: "#94a3b8" };
const axis = { fontSize: 11, fill: "var(--muted)" };

export default function Overview() {
  const ov = useApi<any>(["overview"], "/overview", { refetchInterval: 30_000 });
  const inc = useApi<any>(["incidents", "open"], "/incidents?open=true&limit=8");
  if (ov.isLoading) return <Loading />;
  if (ov.error) return <ErrorBox error={ov.error} />;
  const d = ov.data;
  // Continuous 7-day axis in 6-hour buckets (empty buckets are zero, not missing).
  const BUCKET = 6 * 3600_000;
  const now = Math.floor(Date.now() / BUCKET) * BUCKET;
  const trendMap = new Map<number, any>();
  for (let t = now - 27 * BUCKET; t <= now; t += BUCKET) trendMap.set(t, { t: new Date(t).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit" }) });
  for (const r of d.findingTrend as any[]) {
    const k = Math.floor(new Date(r.bucket).getTime() / BUCKET) * BUCKET;
    const row = trendMap.get(k);
    if (row) row[r.severity] = (row[r.severity] ?? 0) + r.n;
  }
  const trend = [...trendMap.values()];
  const evTrend = (d.eventTrend as any[]).map((r) => ({ t: new Date(r.bucket).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" }), n: r.n }));
  const healthy = d.connections.filter((c: any) => c.status === "healthy").length;
  const inv = d.investigations;
  const totalRuns = inv.ok + inv.failed + inv.rejected;
  return (
    <>
      <PageHeader title="Overview" description="Security posture across connected cloud accounts" />
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-8">
        <Stat label="Cloud accounts" value={d.connections.length} sub={`${healthy} healthy`} icon={Cloud} />
        <Stat label="Log sources" value={d.monitoredSources} sub="enabled" icon={Database} />
        <Stat label="Events (24h)" value={d.events.last24h.toLocaleString()} sub={`${d.events.total.toLocaleString()} total`} icon={Activity} />
        <Stat label="New findings (24h)" value={d.findings.new24h} sub={`${d.findings.open} open`} icon={Siren} />
        <Stat label="Open incidents" value={d.incidents.open} icon={ShieldAlert} tone={d.incidents.open ? "amber" : undefined} />
        <Stat label="High / critical" value={d.incidents.high} icon={ShieldAlert} tone={d.incidents.high ? "red" : "green"} />
        <Stat label="Investigations" value={totalRuns ? `${Math.round((inv.ok / totalRuns) * 100)}%` : "—"} sub={`${inv.ok} ok · ${inv.failed} failed · ${inv.rejected} rejected`} icon={Bot} />
        <Stat label="Agent cost (30d)" value={`$${d.cost.d30.toFixed(2)}`} sub={`p50 ${inv.p50 ? Math.round(inv.p50) + "s" : "—"} · p95 ${inv.p95 ? Math.round(inv.p95) + "s" : "—"}`} icon={DollarSign} />
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <Card title="Detection trend (7 days, by severity)" className="lg:col-span-2">
          <div className="h-56">
            <ResponsiveContainer>
              <BarChart data={trend}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                <XAxis dataKey="t" tick={axis} tickLine={false} axisLine={false} minTickGap={24} />
                <YAxis tick={axis} tickLine={false} axisLine={false} allowDecimals={false} width={28} />
                <Tooltip contentStyle={{ background: "var(--panel)", border: "1px solid var(--border)", borderRadius: 6, fontSize: 12 }} />
                {["critical", "high", "medium", "low", "info"].map((s) => <Bar key={s} dataKey={s} stackId="a" fill={SEV_COLORS[s]} isAnimationActive={false} />)}
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
        <Card title="Ingestion health">
          <div className="space-y-2.5">
            {d.connections.length === 0 && <p className="text-sm text-muted">No connections yet. <Link className="text-accent underline" href="/connections">Connect a GCP project</Link>.</p>}
            {d.connections.map((c: any, i: number) => (
              <div key={i} className="flex items-center justify-between gap-2">
                <div className="min-w-0"><div className="truncate text-[13px] font-medium">{c.name}</div><div className="text-[11px] uppercase text-muted">{c.provider} · last ingest {ago(c.last)}</div></div>
                <Status value={c.status} />
              </div>
            ))}
            <div className="border-t border-border pt-2 text-xs text-muted">Jobs (7d): {d.ingestionJobs.map((j: any) => `${j.n} ${j.status}`).join(" · ") || "none"}</div>
          </div>
          <div className="mt-3 h-24">
            <ResponsiveContainer>
              <AreaChart data={evTrend}><Area dataKey="n" isAnimationActive={false} stroke="var(--accent)" fill="var(--accent)" fillOpacity={0.15} /><XAxis dataKey="t" hide /><Tooltip contentStyle={{ background: "var(--panel)", border: "1px solid var(--border)", fontSize: 12 }} /></AreaChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>

      <Card title="Open incidents" className="mt-4" pad={false} actions={<Link href="/incidents" className="text-xs text-accent">View all</Link>}>
        <Table head={["Case", "Title", "Severity", "Status", "AI verdict", "Last seen"]} empty="No open incidents.">
          {(inc.data?.items ?? []).map((i: any) => (
            <tr key={i.id} className="hover:bg-panel-2">
              <Td className="mono text-xs"><Link href={`/incidents/${i.id}`} className="text-accent">{i.caseId}</Link></Td>
              <Td className="max-w-md truncate">{i.title}</Td>
              <Td><Severity value={i.severity} /></Td>
              <Td><Status value={i.status} /></Td>
              <Td><Verdict value={i.verdict} /></Td>
              <Td className="text-muted">{ago(i.lastSeen)}</Td>
            </tr>
          ))}
        </Table>
      </Card>
      <p className="mt-3 flex items-center gap-1 text-[11px] text-muted"><Timer className="size-3" />Auto-refreshes every 30s</p>
    </>
  );
}
