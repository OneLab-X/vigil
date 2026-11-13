"use client";
import Link from "next/link";
import * as React from "react";
import { useApi } from "@/lib/api";
import { ago } from "@/lib/utils";
import { Card, Json, Loading, PageHeader, Select, Status, Table, Tag, Td } from "@/components/ui";

export default function Investigations() {
  const [status, setStatus] = React.useState("");
  const q = useApi<any>(["runs", status], `/agents/runs?limit=200${status ? `&status=${status}` : ""}`, { refetchInterval: 5_000 });
  const [open, setOpen] = React.useState<string | null>(null);
  const detail = useApi<any>(["run", open], open ? `/agents/runs/${open}` : null);
  return (
    <>
      <PageHeader title="AI Investigations" description="Every agent run: role, model, prompt version, budget use, tool calls and validation outcome"
        actions={<Select value={status} onChange={(e) => setStatus(e.target.value)}><option value="">All statuses</option>{["running", "succeeded", "failed", "rejected", "timeout"].map((s) => <option key={s}>{s}</option>)}</Select>} />
      <Card pad={false}>
        {q.isLoading ? <Loading /> : (
          <Table head={["Started", "Role", "Incident", "Model", "Prompt", "Status", "Steps", "Tokens", "Cost", "Duration", "Error"]} empty="No agent runs yet.">
            {(q.data?.items ?? []).map((r: any) => (
              <React.Fragment key={r.id}>
                <tr className="cursor-pointer hover:bg-panel-2" onClick={() => setOpen(open === r.id ? null : r.id)}>
                  <Td className="whitespace-nowrap text-xs text-muted">{ago(r.createdAt)}</Td><Td><Tag>{r.role}</Tag></Td>
                  <Td><Link onClick={(e) => e.stopPropagation()} className="text-xs text-accent" href={`/incidents/${r.incidentId}`}>open case</Link></Td>
                  <Td className="mono text-xs">{r.modelProvider}/{r.modelName}</Td><Td className="mono text-xs">{r.promptVersion}</Td><Td><Status value={r.status} /></Td>
                  <Td className="tabular-nums">{r.steps}</Td><Td className="tabular-nums">{(r.inputTokens + r.outputTokens).toLocaleString()}</Td><Td className="tabular-nums">${Number(r.costUsd).toFixed(4)}</Td>
                  <Td className="tabular-nums text-xs">{r.finishedAt && r.startedAt ? `${Math.round((new Date(r.finishedAt).getTime() - new Date(r.startedAt).getTime()) / 1000)}s` : "—"}</Td>
                  <Td className="max-w-xs truncate text-xs text-red-600 dark:text-red-400">{r.error ?? (r.validationErrors ? "output rejected (grounding)" : "")}</Td>
                </tr>
                {open === r.id && <tr><td colSpan={11} className="bg-panel-2 p-3">{detail.isLoading ? <Loading /> : <div className="grid gap-3 lg:grid-cols-2"><div><div className="mb-1 text-xs font-semibold uppercase text-muted">Tool calls</div><Json value={detail.data?.toolCalls?.map((c: any) => ({ seq: c.seq, tool: c.tool, allowed: c.allowed, denial: c.denialReason, args: c.arguments, result: c.resultSummary }))} /></div><div><div className="mb-1 text-xs font-semibold uppercase text-muted">Output / validation</div><Json value={{ output: detail.data?.run?.output, validationErrors: detail.data?.run?.validationErrors }} /></div></div>}</td></tr>}
              </React.Fragment>
            ))}
          </Table>
        )}
      </Card>
    </>
  );
}
