"use client";
import * as React from "react";
import { api, useAct, useApi } from "@/lib/api";
import { useCan, useMe } from "@/components/shell";
import { Button, Card, ErrorBox, Input, Label, Select, Table, Tag, Td } from "@/components/ui";

const ROLES = [
  { v: "viewer", l: "Viewer — read only" },
  { v: "analyst", l: "Analyst — triage, investigate, review verdicts" },
  { v: "admin", l: "Admin — plus rules, connections, agents, audit" },
  { v: "owner", l: "Owner — plus manage members" },
];
const empty = { email: "", displayName: "", role: "analyst" };

export function Members() {
  const me = useMe();
  const can = useCan()("members:write");
  const q = useApi<any>(["members"], "/members");
  const [adding, setAdding] = React.useState(false);
  const [f, setF] = React.useState(empty);
  const [issued, setIssued] = React.useState<{ email: string; password: string } | null>(null);
  const [notice, setNotice] = React.useState<string | null>(null);
  const [copied, setCopied] = React.useState(false);
  const add = useAct(() => api<any>("/members", { method: "POST", body: f }), [["members"]]);
  const patch = useAct((v: { id: string; role: string }) => api(`/members/${v.id}`, { method: "PATCH", body: { role: v.role } }), [["members"]]);
  const del = useAct((id: string) => api(`/members/${id}`, { method: "DELETE" }), [["members"]]);
  const set = (k: keyof typeof empty) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setF({ ...f, [k]: e.target.value });

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    setIssued(null); setNotice(null); setCopied(false);
    add.mutate(undefined as any, {
      onSuccess: (r) => {
        if (r.oneTimePassword) setIssued({ email: r.email, password: r.oneTimePassword });
        else setNotice(`${r.email} already has an account; they can switch to this organization after signing in.`);
        setF(empty); setAdding(false);
      },
    });
  };

  return (
    <Card title="Members" pad={false}
      actions={can && <Button size="sm" onClick={() => { setAdding(!adding); add.reset(); }}>{adding ? "Cancel" : "Add member"}</Button>}>
      {adding && can && (
        <form className="grid gap-2 border-b border-border p-4 md:grid-cols-[1fr_1fr_1fr_auto] md:items-end" onSubmit={submit}>
          <div><Label>Email</Label><Input className="w-full" type="email" required autoComplete="off" value={f.email} onChange={set("email")} placeholder="name@company.com" /></div>
          <div><Label>Name</Label><Input className="w-full" required value={f.displayName} onChange={set("displayName")} /></div>
          <div><Label>Role</Label><Select className="w-full" value={f.role} onChange={set("role")}>{ROLES.map((r) => <option key={r.v} value={r.v}>{r.l}</option>)}</Select></div>
          <Button variant="primary" size="sm" loading={add.isPending}>Add</Button>
          <div className="md:col-span-4"><ErrorBox error={add.error} /></div>
        </form>
      )}
      {issued && (
        <div className="space-y-2 border-b border-border bg-amber-500/10 p-4 text-[13px]">
          <div>Account created for <b>{issued.email}</b>. Share this one-time password privately — it is shown only now and must be changed at first sign-in.</div>
          <div className="flex flex-wrap items-center gap-2">
            <code className="mono rounded border border-border bg-panel px-2 py-1 text-xs">{issued.password}</code>
            <Button size="sm" onClick={async () => { try { await navigator.clipboard.writeText(issued.password); setCopied(true); } catch { /* clipboard blocked */ } }}>{copied ? "Copied" : "Copy"}</Button>
            <Button size="sm" variant="ghost" onClick={() => setIssued(null)}>Done</Button>
          </div>
        </div>
      )}
      {notice && <div className="flex items-center justify-between gap-2 border-b border-border p-4 text-[13px]"><span>{notice}</span><Button size="sm" variant="ghost" onClick={() => setNotice(null)}>Dismiss</Button></div>}
      <Table head={["Name", "Email", "Role", ""]}>
        {(q.data?.items ?? []).map((m: any) => {
          const self = m.id === me?.user?.id;
          return (
            <tr key={m.id}>
              <Td>{m.displayName}{self && <span className="ml-1 text-xs text-muted">(you)</span>}</Td>
              <Td className="mono text-xs">{m.email}{m.mustChangePassword && <Tag className="ml-2">pending first sign-in</Tag>}</Td>
              <Td>
                {can && !self
                  ? <Select className="h-7 text-xs" disabled={patch.isPending} value={m.role} onChange={(e) => patch.mutate({ id: m.id, role: e.target.value })}>{ROLES.map((r) => <option key={r.v} value={r.v}>{r.v}</option>)}</Select>
                  : <Tag>{m.role}</Tag>}
              </Td>
              <Td className="text-right">
                {can && !self && <Button size="sm" variant="ghost" onClick={() => { if (confirm(`Remove ${m.email} from this organization? Their account is kept; they lose access here immediately.`)) del.mutate(m.id); }}>Remove</Button>}
              </Td>
            </tr>
          );
        })}
      </Table>
      {(patch.error || del.error) && <div className="p-4"><ErrorBox error={patch.error ?? del.error} /></div>}
    </Card>
  );
}
