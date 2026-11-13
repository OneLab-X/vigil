"use client";
import * as React from "react";
import { api, useAct, useApi } from "@/lib/api";
import { fmtTime, pct } from "@/lib/utils";
import { useCan } from "@/components/shell";
import { Button, Card, ErrorBox, Json, Loading, PageHeader, Stat, Table, Tag, Td } from "@/components/ui";

export default function Evaluation() {
  const can = useCan();
  const q = useApi<any>(["evals"], "/evaluations?limit=50");
  const run = useAct(() => api("/evaluations/detection-replay", { method: "POST" }), [["evals"]]);
  const [open, setOpen] = React.useState<string | null>(null);
  const latest = q.data?.items?.find((e: any) => e.suite === "detection-replay");
  const agentEval = q.data?.items?.find((e: any) => e.suite !== "detection-replay");
  return (
    <>
      <PageHeader title="Evaluation & Performance" description="Replay synthetic attack scenarios (incl. prompt-injection payloads) and score detection and agent quality. A well-formed AI answer is not counted as a correct investigation."
        actions={can("rules:write") && <Button variant="primary" loading={run.isPending} onClick={() => run.mutate(undefined as any)}>Run detection replay</Button>} />
      <ErrorBox error={run.error} />
      {latest && (
        <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-5">
          <Stat label="Detection precision" value={pct(latest.metrics.precision)} />
          <Stat label="Detection recall" value={pct(latest.metrics.recall)} />
          <Stat label="False positives" value={latest.metrics.false_positives} />
          <Stat label="False negatives" value={latest.metrics.false_negatives} tone={latest.metrics.false_negatives ? "red" : "green"} />
          <Stat label="Scenarios" value={latest.metrics.scenarios} sub={latest.metrics.data} />
        </div>
      )}
      {agentEval && (
        <Card title={`Agent evaluation — ${agentEval.suite}`} className="mb-4">
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">{Object.entries(agentEval.metrics).map(([k, v]) => <Stat key={k} label={k.replace(/_/g, " ")} value={typeof v === "number" ? (v <= 1 && !Number.isInteger(v) ? pct(v) : v) : String(v)} />)}</div>
        </Card>
      )}
      <Card pad={false} title="History">
        {q.isLoading ? <Loading /> : (
          <Table head={["When", "Suite", "Subject", "Model", "Version", "Key metrics"]} empty="No evaluations yet.">
            {(q.data?.items ?? []).map((e: any) => (
              <React.Fragment key={e.id}>
                <tr className="cursor-pointer hover:bg-panel-2" onClick={() => setOpen(open === e.id ? null : e.id)}>
                  <Td className="text-xs text-muted">{fmtTime(e.createdAt)}</Td><Td><Tag>{e.suite}</Tag></Td><Td>{e.agentRole}</Td><Td className="mono text-xs">{e.modelProvider}/{e.modelName}</Td><Td className="mono text-xs">{e.promptVersion}</Td>
                  <Td className="mono text-xs">{Object.entries(e.metrics).slice(0, 4).map(([k, v]) => `${k}=${typeof v === "number" ? Math.round(v * 1000) / 1000 : v}`).join("  ")}</Td>
                </tr>
                {open === e.id && <tr><td colSpan={6} className="bg-panel-2 p-3"><Json value={e.cases} /></td></tr>}
              </React.Fragment>
            ))}
          </Table>
        )}
      </Card>
    </>
  );
}
