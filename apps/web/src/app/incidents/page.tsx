"use client";
import Link from "next/link";
import * as React from "react";
import { useApi } from "@/lib/api";
import { ago, pct } from "@/lib/utils";
import { Card, ErrorBox, Loading, PageHeader, Select, Severity, Status, Table, Td, Verdict } from "@/components/ui";

const STATUSES = ["", "new", "investigating", "needs_review", "confirmed", "false_positive", "remediation_pending", "resolved", "closed"];

export default function Incidents() {
  const [status, setStatus] = React.useState("");
  const [severity, setSeverity] = React.useState("");
  const qs = new URLSearchParams({ limit: "200", ...(status && { status }), ...(severity && { severity }) });
  const q = useApi<any>(["incidents", status, severity], `/incidents?${qs}`, { refetchInterval: 15_000 });
  return (
    <>
      <PageHeader title="Incidents" description="Correlated security cases. Every AI verdict requires human review."
        actions={<>
          <Select value={status} onChange={(e) => setStatus(e.target.value)}>{STATUSES.map((s) => <option key={s} value={s}>{s ? s.replace(/_/g, " ") : "All statuses"}</option>)}</Select>
          <Select value={severity} onChange={(e) => setSeverity(e.target.value)}><option value="">All severities</option>{["critical", "high", "medium", "low", "info"].map((s) => <option key={s}>{s}</option>)}</Select>
        </>} />
      <ErrorBox error={q.error} />
      <Card pad={false}>
        {q.isLoading ? <Loading /> : (
          <Table head={["Case", "Title", "Entity", "Severity", "Status", "AI verdict", "Confidence", "Review", "Events", "Assignee", "Last seen"]} empty="No incidents match.">
            {(q.data?.items ?? []).map((i: any) => (
              <tr key={i.id} className="hover:bg-panel-2">
                <Td className="mono text-xs"><Link href={`/incidents/${i.id}`} className="text-accent">{i.caseId}</Link></Td>
                <Td className="max-w-xs"><Link href={`/incidents/${i.id}`} className="line-clamp-2 hover:underline">{i.title}</Link></Td>
                <Td className="mono max-w-[200px] truncate text-xs text-muted">{i.correlationKey}</Td>
                <Td><Severity value={i.severity} /></Td>
                <Td><Status value={i.status} /></Td>
                <Td><Verdict value={i.verdict} /></Td>
                <Td className="tabular-nums">{pct(i.confidence)}</Td>
                <Td><Status value={i.reviewStatus} /></Td>
                <Td className="tabular-nums">{i.eventCount}</Td>
                <Td className="text-muted">{i.assignee ?? "—"}</Td>
                <Td className="whitespace-nowrap text-muted">{ago(i.lastSeen)}</Td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </>
  );
}
