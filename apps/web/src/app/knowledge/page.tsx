"use client";
import * as React from "react";
import { api, useAct, useApi } from "@/lib/api";
import { fmtTime } from "@/lib/utils";
import { useCan, useMe } from "@/components/shell";
import { Button, Card, ErrorBox, Input, Label, Loading, PageHeader, Select, Status, Table, Tag, Td, Textarea } from "@/components/ui";

export default function Knowledge() {
  const can = useCan();
  const me = useMe();
  const [status, setStatus] = React.useState("");
  const q = useApi<any>(["knowledge", status], `/knowledge?limit=200${status ? `&status=${status}` : ""}`);
  const decide = useAct(({ id, decision }: any) => api(`/knowledge/${id}/decision`, { method: "POST", body: { decision } }), [["knowledge"]]);
  const [f, setF] = React.useState({ kind: "trusted_identity", key: "", title: "", body: "", expiresAt: "" });
  const propose = useAct(() => api("/knowledge", { method: "POST", body: { ...f, expiresAt: f.expiresAt ? new Date(f.expiresAt).toISOString() : undefined } }), [["knowledge"]]);
  return (
    <>
      <PageHeader title="Security Knowledge" description="Organizational memory. Agents read only approved entries; proposals need a second human (four-eyes)."
        actions={<Select value={status} onChange={(e) => setStatus(e.target.value)}><option value="">All</option>{["pending", "approved", "rejected"].map((s) => <option key={s}>{s}</option>)}</Select>} />
      <ErrorBox error={decide.error} />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_340px]">
        <Card pad={false}>
          {q.isLoading ? <Loading /> : (
            <Table head={["Kind", "Key", "Title", "Status", "Version", "Proposed by", "Owner", "Expires", ""]}>
              {(q.data?.items ?? []).map((k: any) => (
                <tr key={k.id}>
                  <Td><Tag>{k.kind}</Tag></Td><Td className="mono max-w-[200px] truncate text-xs">{k.key}</Td>
                  <Td className="max-w-sm"><div className="font-medium">{k.title}</div><div className="line-clamp-2 text-xs text-muted">{k.body}</div></Td>
                  <Td><Status value={k.status} /></Td><Td>v{k.version}</Td><Td className="text-xs">{k.proposer ?? "—"}</Td><Td className="text-xs text-muted">{k.owner}</Td>
                  <Td className="text-xs text-muted">{k.expiresAt ? fmtTime(k.expiresAt) : "never"}</Td>
                  <Td>{k.status === "pending" && can("knowledge:approve") && (k.proposedByUserId === me?.user?.id ? <span className="text-xs text-muted">awaiting another reviewer</span> : <div className="flex gap-1"><Button size="sm" variant="primary" onClick={() => decide.mutate({ id: k.id, decision: "approved" })}>Approve</Button><Button size="sm" onClick={() => decide.mutate({ id: k.id, decision: "rejected" })}>Reject</Button></div>)}</Td>
                </tr>
              ))}
            </Table>
          )}
        </Card>
        {can("knowledge:propose") && (
          <Card title="Propose knowledge">
            <form className="space-y-2" onSubmit={(e) => { e.preventDefault(); propose.mutate(undefined as any); }}>
              <div><Label>Kind</Label><Select className="w-full" value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })}>{["trusted_identity", "trusted_ip", "false_positive", "policy", "lesson"].map((k) => <option key={k} value={k}>{k.replace(/_/g, " ")}</option>)}</Select></div>
              <div><Label>Key</Label><Input value={f.key} onChange={(e) => setF({ ...f, key: e.target.value })} required placeholder="IP, principal email/ARN, or rule id" /></div>
              <div><Label>Title</Label><Input value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} required /></div>
              <div><Label>Details</Label><Textarea rows={4} value={f.body} onChange={(e) => setF({ ...f, body: e.target.value })} required /></div>
              <div><Label hint="optional">Expires</Label><Input type="date" value={f.expiresAt} onChange={(e) => setF({ ...f, expiresAt: e.target.value })} /></div>
              <Button variant="primary" size="sm" loading={propose.isPending}>Submit for approval</Button>
              <ErrorBox error={propose.error} />
            </form>
          </Card>
        )}
      </div>
    </>
  );
}
