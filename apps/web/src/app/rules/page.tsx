"use client";
import * as React from "react";
import { api, useAct, useApi } from "@/lib/api";
import { ago } from "@/lib/utils";
import { useCan } from "@/components/shell";
import { Button, Card, ErrorBox, Json, Loading, PageHeader, Severity, Status, Table, Tag, Td, Textarea } from "@/components/ui";

export default function Rules() {
  const can = useCan();
  const q = useApi<any>(["rules"], "/detection-rules");
  const runs = useApi<any>(["detection-runs"], "/detection-runs?limit=10");
  const toggle = useAct(({ id, enabled }: any) => api(`/detection-rules/${id}`, { method: "PATCH", body: { enabled } }), [["rules"]]);
  const decide = useAct(({ id, decision }: any) => api(`/detection-rules/${id}/decision`, { method: "POST", body: { decision, enable: decision === "approved" } }), [["rules"]]);
  const runNow = useAct(() => api("/detection-runs", { method: "POST", body: { start: new Date(Date.now() - 24 * 3600_000).toISOString(), end: new Date().toISOString() } }), [["detection-runs"]]);
  const [sigma, setSigma] = React.useState("");
  const importSigma = useAct(() => api("/detection-rules/import-sigma", { method: "POST", body: { ruleId: `SIGMA-${Date.now().toString(36).toUpperCase()}`, sigma: JSON.parse(sigma) } }), [["rules"]]);
  const [open, setOpen] = React.useState<string | null>(null);
  return (
    <>
      <PageHeader title="Detection Rules" description="Deterministic, versioned detections. Agent-proposed rules stay disabled until a human approves them."
        actions={can("rules:write") && <Button loading={runNow.isPending} onClick={() => runNow.mutate(undefined as any)}>Run detection (last 24h)</Button>} />
      <ErrorBox error={toggle.error ?? decide.error ?? runNow.error} />
      <Card pad={false}>
        {q.isLoading ? <Loading /> : (
          <Table head={["Rule", "Name", "Provider", "Severity", "MITRE ATT&CK", "Version", "Approval", "Findings", "Owner", "Enabled"]}>
            {(q.data?.items ?? []).map((r: any) => (
              <React.Fragment key={r.id}>
                <tr className="cursor-pointer hover:bg-panel-2" onClick={() => setOpen(open === r.id ? null : r.id)}>
                  <Td className="mono text-xs">{r.ruleId}</Td><Td className="max-w-xs">{r.name}</Td><Td><Tag>{r.provider}</Tag></Td><Td><Severity value={r.severity} /></Td>
                  <Td><div className="flex flex-wrap gap-1">{(r.mitre ?? []).map((m: any) => <Tag key={m.technique}>{m.technique}</Tag>)}</div></Td>
                  <Td className="tabular-nums">v{r.version}</Td><Td><Status value={r.approvalStatus} /></Td><Td className="tabular-nums">{r.findings}</Td>
                  <Td className="text-xs text-muted">{r.owner}</Td>
                  <Td onClick={(e) => e.stopPropagation()}>
                    {r.approvalStatus === "pending" && can("rules:write") ? <div className="flex gap-1"><Button size="sm" variant="primary" onClick={() => decide.mutate({ id: r.id, decision: "approved" })}>Approve</Button><Button size="sm" onClick={() => decide.mutate({ id: r.id, decision: "rejected" })}>Reject</Button></div>
                      : <input type="checkbox" aria-label="enabled" checked={r.enabled} disabled={!can("rules:write") || r.approvalStatus !== "approved"} onChange={(e) => toggle.mutate({ id: r.id, enabled: e.target.checked })} />}
                  </Td>
                </tr>
                {open === r.id && <tr><td colSpan={10} className="bg-panel-2 p-3"><p className="mb-2 text-[13px]">{r.description}</p><Json value={{ detection_query: r.detectionQuery, event_sources: r.eventSources, conditions: r.conditions }} /></td></tr>}
              </React.Fragment>
            ))}
          </Table>
        )}
      </Card>
      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <Card title="Recent detection runs" pad={false}>
          <Table head={["Started", "Window", "Rules", "Findings", "Status"]}>
            {(runs.data?.items ?? []).map((r: any) => <tr key={r.id}><Td className="text-xs text-muted">{ago(r.startedAt)}</Td><Td className="text-xs">{new Date(r.windowStart).toLocaleString()} → {new Date(r.windowEnd).toLocaleTimeString()}</Td><Td>{r.rulesEvaluated}</Td><Td>{r.findingsCreated}</Td><Td><Status value={r.status} /></Td></tr>)}
          </Table>
        </Card>
        {can("rules:write") && (
          <Card title="Import Sigma rule (JSON form of the YAML)">
            <Textarea rows={8} className="mono text-xs" placeholder='{"title":"AWS StopLogging","level":"high","logsource":{"product":"aws"},"detection":{"sel":{"eventName":["StopLogging"]},"condition":"sel"}}' value={sigma} onChange={(e) => setSigma(e.target.value)} />
            <p className="my-2 text-xs text-muted">Supported: field maps with |contains |startswith |endswith |re, list values, and conditions “a”, “a and b”, “a or b”, “a and not b”. Anything else is rejected rather than approximated.</p>
            <Button size="sm" loading={importSigma.isPending} onClick={() => importSigma.mutate(undefined as any)}>Import</Button>
            <ErrorBox error={importSigma.error} />
          </Card>
        )}
      </div>
    </>
  );
}
