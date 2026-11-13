"use client";
import { useSearchParams } from "next/navigation";
import * as React from "react";
import { useApi } from "@/lib/api";
import { fmtTime } from "@/lib/utils";
import { EventDrawer } from "@/components/event-drawer";
import { Button, Card, ErrorBox, Input, Loading, PageHeader, Select, Severity, Table, Tag, Td } from "@/components/ui";

const RANGES: Record<string, number> = { "1h": 1, "24h": 24, "7d": 168, "30d": 720 };

function Explorer() {
  const sp = useSearchParams();
  const [f, setF] = React.useState<Record<string, string>>(() => ({ range: "24h", ...Object.fromEntries(sp.entries()) }));
  const [applied, setApplied] = React.useState(f);
  const [page, setPage] = React.useState(0);
  // Time window is anchored when filters are applied, not on every render: a render-time Date.now()
  // changed the query key on each render and caused an endless refetch loop (429s).
  const [anchor, setAnchor] = React.useState(() => Date.now());
  const [open, setOpen] = React.useState<string | null>(null);
  const connectors = useApi<{ items: Array<{ id: string; displayName: string }> }>(["connectors"], "/connectors");
  const qs = new URLSearchParams();
  const hours = RANGES[applied.range] ?? 24;
  qs.set("start", new Date(anchor - hours * 3600_000).toISOString());
  qs.set("limit", "100"); qs.set("offset", String(page * 100));
  for (const k of ["q", "provider", "account", "severity", "sourceType", "eventType", "category", "sourceIp", "principal", "resourceId", "traceId", "httpStatus"]) if (applied[k]) qs.set(k, applied[k]);
  const q = useApi<any>(["events", qs.toString()], `/events?${qs}`);
  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setF({ ...f, [k]: e.target.value });
  return (
    <>
      <PageHeader title="Event Explorer" description="Normalized, provider-independent security events with links to immutable original evidence" />
      <Card className="mb-4">
        <form className="grid grid-cols-2 gap-2 md:grid-cols-4 xl:grid-cols-6" onSubmit={(e) => { e.preventDefault(); setPage(0); setAnchor(Date.now()); setApplied(f); }}>
          <Input className="col-span-2" placeholder="Search action, path, principal, IP, message…" value={f.q ?? ""} onChange={set("q")} />
          <Select value={f.range} onChange={set("range")}>{Object.keys(RANGES).map((r) => <option key={r} value={r}>Last {r}</option>)}</Select>
          <Select value={f.provider ?? ""} onChange={set("provider")}><option value="">All providers</option>{(connectors.data?.items ?? []).map((c) => <option key={c.id} value={c.id}>{c.displayName}</option>)}</Select>
          <Select value={f.severity ?? ""} onChange={set("severity")}><option value="">Any severity</option>{["critical", "high", "medium", "low", "info"].map((s) => <option key={s}>{s}</option>)}</Select>
          <Select value={f.eventType ?? ""} onChange={set("eventType")}><option value="">Any type</option>{["http.request", "app.log", "cloud.api_call", "iam.change", "iam.credential_create", "firewall.change", "security_policy.change", "logging.config_change", "network.flow", "auth.failure", "auth.success"].map((s) => <option key={s}>{s}</option>)}</Select>
          <Input placeholder="Project / account" value={f.account ?? ""} onChange={set("account")} />
          <Input placeholder="Source IP" value={f.sourceIp ?? ""} onChange={set("sourceIp")} />
          <Input placeholder="Principal" value={f.principal ?? ""} onChange={set("principal")} />
          <Input placeholder="Resource ID" value={f.resourceId ?? ""} onChange={set("resourceId")} />
          <Input placeholder="Trace ID" value={f.traceId ?? ""} onChange={set("traceId")} />
          <Input placeholder="HTTP status" value={f.httpStatus ?? ""} onChange={set("httpStatus")} />
          <div className="col-span-2 flex gap-2 md:col-span-4 xl:col-span-6"><Button variant="primary">Apply filters</Button><Button type="button" variant="ghost" onClick={() => { const r = { range: "24h" }; setF(r); setPage(0); setAnchor(Date.now()); setApplied(r); }}>Reset</Button></div>
        </form>
      </Card>
      <ErrorBox error={q.error} />
      <Card pad={false} title={q.data ? `${q.data.total.toLocaleString()} events` : "Events"} actions={q.data && <div className="flex items-center gap-2 text-xs"><Button size="sm" disabled={page === 0} onClick={() => setPage(page - 1)}>Prev</Button><span>Page {page + 1}</span><Button size="sm" disabled={(page + 1) * 100 >= q.data.total} onClick={() => setPage(page + 1)}>Next</Button></div>}>
        {q.isLoading ? <Loading /> : (
          <Table head={["Time", "Provider", "Account", "Type", "Sev", "Source IP", "Principal", "Action / message", "Status"]} empty="No events in this range. Run an ingestion job from Connections.">
            {(q.data?.items ?? []).map((e: any) => (
              <tr key={e.id} className="cursor-pointer hover:bg-panel-2" onClick={() => setOpen(e.id)}>
                <Td className="whitespace-nowrap text-xs text-muted">{fmtTime(e.eventTimestamp)}</Td>
                <Td className="text-xs uppercase">{e.cloudProvider}</Td>
                <Td className="mono text-xs">{e.projectOrAccountReference}</Td>
                <Td><Tag>{e.normalizedEventType}</Tag></Td>
                <Td><Severity value={e.severity} /></Td>
                <Td className="mono text-xs">{e.sourceIp ?? "—"}</Td>
                <Td className="mono max-w-[180px] truncate text-xs">{e.principal ?? "—"}</Td>
                <Td className="mono max-w-[420px] truncate text-xs">{e.action ?? e.message ?? "—"}</Td>
                <Td className="text-xs">{e.httpStatus ?? e.status ?? "—"}</Td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
      <EventDrawer id={open} onClose={() => setOpen(null)} onOpen={setOpen} />
    </>
  );
}

export default function EventsPage() { return <React.Suspense fallback={<Loading />}><Explorer /></React.Suspense>; }
