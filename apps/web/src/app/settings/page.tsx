"use client";
import * as React from "react";
import { api } from "@/lib/api";
import { useCan, useMe } from "@/components/shell";
import { Card, Label, PageHeader, Select, Tabs, Tag } from "@/components/ui";
import { AiModels } from "@/components/ai-models";
import { Members } from "@/components/members";
import { Notifications } from "@/components/notifications";

type TabId = "general" | "ai-models" | "members" | "notifications";
const ALL_TABS: Array<{ id: TabId; label: string; perm?: string }> = [
  { id: "general", label: "General" },
  { id: "ai-models", label: "AI models" },
  { id: "members", label: "Members" },
  { id: "notifications", label: "Notifications", perm: "notifications:write" },
];

/** Selected tab lives in the URL hash (#members) so it survives reloads and can be linked to. */
function useHashTab(allowed: TabId[]): [TabId, (t: TabId) => void] {
  const [tab, setTab] = React.useState<TabId>("general");
  React.useEffect(() => {
    const read = () => { const h = window.location.hash.slice(1) as TabId; setTab(allowed.includes(h) ? h : "general"); };
    read();
    window.addEventListener("hashchange", read);
    return () => window.removeEventListener("hashchange", read);
  }, [allowed.join(",")]); // eslint-disable-line react-hooks/exhaustive-deps
  const select = (t: TabId) => { setTab(t); history.replaceState(null, "", t === "general" ? window.location.pathname : `#${t}`); };
  return [tab, select];
}

export default function Settings() {
  const me = useMe();
  const can = useCan();
  const tabs = ALL_TABS.filter((t) => !t.perm || can(t.perm));
  const [tab, setTab] = useHashTab(tabs.map((t) => t.id));

  return (
    <>
      <PageHeader title="Settings" description="Workspace, AI models, members and incident alerts" />
      <div className="mb-4 overflow-x-auto"><Tabs value={tab} onChange={setTab} tabs={tabs} /></div>
      {tab === "general" && <General me={me} />}
      {tab === "ai-models" && <AiModels />}
      {tab === "members" && <Members />}
      {tab === "notifications" && <Notifications />}
    </>
  );
}

function General({ me }: { me: any }) {
  const active = me?.tenants?.find((t: any) => t.id === me?.activeTenantId);
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card title="Workspace">
        <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-4 gap-y-2 text-[13px]">
          <dt className="text-muted">Organization</dt><dd className="font-medium">{active?.name ?? "—"}</dd>
          <dt className="text-muted">Signed in as</dt><dd className="truncate">{me?.user?.email ?? "—"}</dd>
          <dt className="text-muted">Role</dt><dd>{me?.role ? <Tag>{me.role}</Tag> : "—"}</dd>
        </dl>
        {me?.tenants?.length > 1 && (
          <div className="mt-4">
            <Label>Switch organization</Label>
            <Select className="w-full" value={me.activeTenantId} onChange={async (e) => { await api("/auth/switch-tenant", { method: "POST", body: { tenantId: e.target.value } }); location.reload(); }}>
              {me.tenants.map((t: any) => <option key={t.id} value={t.id}>{t.name} ({t.role})</option>)}
            </Select>
          </div>
        )}
        <div className="mt-4">
          <Label>Your permissions</Label>
          <div className="mt-1 flex flex-wrap gap-1">{me?.permissions?.map((p: string) => <Tag key={p}>{p}</Tag>)}</div>
        </div>
      </Card>
      <Card title="Security posture">
        <ul className="list-disc space-y-1.5 pl-5 text-[13px]">
          <li>Tenant isolation enforced by PostgreSQL row-level security (FORCE RLS; app role cannot bypass).</li>
          <li>Cloud access is read-only; connection tests flag over-privileged credentials.</li>
          <li>Agents never see credentials; all data access goes through the audited tool broker.</li>
          <li>AI provider keys are encrypted at rest and used only by the agent service; an AI data policy can restrict runs to customer-hosted models.</li>
          <li>AI verdicts and recommendations require human approval; nothing is auto-remediated.</li>
          <li>Raw evidence is content-addressed and immutable; audit log is append-only and hash-chained.</li>
          <li>Alert webhook URLs and SMTP passwords are encrypted at rest and write-only.</li>
        </ul>
      </Card>
    </div>
  );
}
