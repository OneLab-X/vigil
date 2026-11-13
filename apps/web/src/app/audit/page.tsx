"use client";
import * as React from "react";
import { ShieldCheck, ShieldX } from "lucide-react";
import { useApi } from "@/lib/api";
import { fmtTime } from "@/lib/utils";
import { useCan } from "@/components/shell";
import { Button, Card, Input, Loading, PageHeader, Table, Tag, Td } from "@/components/ui";

export default function Audit() {
  const can = useCan();
  const [action, setAction] = React.useState("");
  const [applied, setApplied] = React.useState("");
  const q = useApi<any>(["audit", applied], `/audit-logs?limit=500${applied ? `&action=${encodeURIComponent(applied)}` : ""}`);
  const verify = useApi<any>(["audit-verify"], can("audit:read") ? "/audit-logs/verify" : null);
  return (
    <>
      <PageHeader title="Audit Logs" description="Append-only, hash-chained record of every human, agent and system action"
        actions={<form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); setApplied(action); }}><Input placeholder="Action prefix, e.g. verdict." value={action} onChange={(e) => setAction(e.target.value)} /><Button>Filter</Button></form>} />
      {verify.data && <div className="mb-3 flex items-center gap-2 text-[13px]">{verify.data.ok ? <ShieldCheck className="size-4 text-emerald-500" /> : <ShieldX className="size-4 text-red-500" />}Hash chain {verify.data.ok ? "verified" : `BROKEN at entry ${verify.data.brokenAt}`} across {verify.data.entries} entries</div>}
      <Card pad={false}>
        {q.isLoading ? <Loading /> : (
          <Table head={["#", "Time", "Actor", "Action", "Target", "Details", "Hash"]}>
            {(q.data?.items ?? []).map((l: any) => (
              <tr key={l.id}>
                <Td className="tabular-nums text-xs text-muted">{l.id}</Td><Td className="whitespace-nowrap text-xs text-muted">{fmtTime(l.createdAt)}</Td>
                <Td className="text-xs"><Tag>{l.actorType}</Tag> {l.actorName ?? l.actorId?.slice(0, 18)}</Td>
                <Td className="mono text-xs">{l.action}</Td><Td className="mono text-xs text-muted">{l.targetType}{l.targetId ? `:${l.targetId.slice(0, 8)}` : ""}</Td>
                <Td className="mono max-w-md truncate text-[11px] text-muted">{JSON.stringify(l.details)}</Td><Td className="mono text-[11px] text-muted">{l.hash.slice(0, 10)}</Td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </>
  );
}
