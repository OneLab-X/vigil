"use client";
import { api, useApi } from "@/lib/api";
import { useMe } from "@/components/shell";
import { Card, PageHeader, Select, Table, Tag, Td } from "@/components/ui";
import { AiModels } from "@/components/ai-models";

export default function Settings() {
  const me = useMe();
  const members = useApi<any>(["members"], "/members");
  return (
    <>
      <PageHeader title="Settings" description="Tenant, members and platform security posture" />
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Workspace">
          <div className="space-y-2 text-[13px]">
            <div>Signed in as <b>{me?.user?.email}</b> ({me?.role})</div>
            {me?.tenants?.length > 1 && <Select value={me.activeTenantId} onChange={async (e) => { await api("/auth/switch-tenant", { method: "POST", body: { tenantId: e.target.value } }); location.reload(); }}>{me.tenants.map((t: any) => <option key={t.id} value={t.id}>{t.name}</option>)}</Select>}
            <div className="flex flex-wrap gap-1">{me?.permissions?.map((p: string) => <Tag key={p}>{p}</Tag>)}</div>
          </div>
        </Card>
        <Card title="Security posture">
          <ul className="list-disc space-y-1 pl-5 text-[13px]">
            <li>Tenant isolation enforced by PostgreSQL row-level security (FORCE RLS; app role cannot bypass).</li>
            <li>Cloud access is read-only; connection tests flag over-privileged credentials.</li>
            <li>Agents never see credentials; all data access goes through the audited tool broker.</li>
            <li>AI provider keys are encrypted at rest and used only by the agent service; an AI data policy can restrict runs to customer-hosted models.</li>
            <li>AI verdicts and recommendations require human approval; nothing is auto-remediated.</li>
            <li>Raw evidence is content-addressed and immutable; audit log is append-only and hash-chained.</li>
          </ul>
        </Card>
        <AiModels />
        <Card title="Members" pad={false} className="lg:col-span-2">
          <Table head={["Name", "Email", "Role"]}>{(members.data?.items ?? []).map((m: any) => <tr key={m.id}><Td>{m.displayName}</Td><Td className="mono text-xs">{m.email}</Td><Td><Tag>{m.role}</Tag></Td></tr>)}</Table>
        </Card>
      </div>
    </>
  );
}
