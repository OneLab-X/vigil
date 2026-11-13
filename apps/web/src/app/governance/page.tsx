"use client";
import * as React from "react";
import { ShieldCheck } from "lucide-react";
import { api, useAct, useApi } from "@/lib/api";
import { cn } from "@/lib/utils";
import { useCan } from "@/components/shell";
import { Button, Card, ErrorBox, Input, Label, Loading, PageHeader, Select, Status, Table, Tag, Td } from "@/components/ui";

export default function Governance() {
  const can = useCan();
  const q = useApi<any>(["agents"], "/agents", { refetchInterval: 10_000 });
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const d = q.data;
  const active = d.definitions.filter((x: any) => x.enabled);
  return (
    <>
      <PageHeader title="Agent Governance" description="Bounded agents: explicit role, allow-listed tools, step/time/token/cost budgets, versioned prompts and models" />
      <div className="mb-4 flex flex-wrap gap-2 text-xs">
        {Object.entries(d.providerKeysVisibleToApi).map(([p, ok]) => <Tag key={p} className={cn("whitespace-normal", ok ? "text-emerald-600" : "")}>{p}: {ok ? "key configured on API host" : "no key on API host (worker may have its own)"}</Tag>)}
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        {active.map((a: any) => <AgentCard key={a.id} a={a} canEdit={can("agents:write")} />)}
      </div>
      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <Card title="Runs by role and outcome" pad={false}>
          <Table head={["Role", "Status", "Runs", "Tokens", "Total cost", "Avg cost", "Avg duration"]}>
            {(d.stats as any[]).map((s, i) => <tr key={i}><Td><Tag>{s.role}</Tag></Td><Td><Status value={s.status} /></Td><Td>{s.n}</Td><Td className="tabular-nums">{s.tokens.toLocaleString()}</Td><Td className="tabular-nums">${s.cost.toFixed(4)}</Td><Td className="tabular-nums">${s.avg_cost.toFixed(4)}</Td><Td className="tabular-nums">{s.avg_seconds ? `${s.avg_seconds.toFixed(1)}s` : "—"}</Td></tr>)}
          </Table>
        </Card>
        <Card title="Model usage" pad={false}>
          <Table head={["Provider", "Model", "Input tok", "Output tok", "Cost"]}>
            {(d.usage as any[]).map((u, i) => <tr key={i}><Td>{u.provider}</Td><Td className="mono text-xs">{u.model}</Td><Td className="tabular-nums">{u.input.toLocaleString()}</Td><Td className="tabular-nums">{u.output.toLocaleString()}</Td><Td className="tabular-nums">${u.cost.toFixed(4)}</Td></tr>)}
          </Table>
        </Card>
      </div>
      <Card title="All definition versions" pad={false} className="mt-4">
        <Table head={["Role", "Version", "Model", "Prompt", "Steps", "Timeout", "Token budget", "Cost budget", "Enabled"]}>
          {d.definitions.map((a: any) => <tr key={a.id}><Td><Tag>{a.role}</Tag></Td><Td>v{a.version}</Td><Td className="mono text-xs">{a.modelProvider}/{a.modelName}</Td><Td className="mono text-xs">{a.promptVersion}</Td><Td>{a.maxSteps}</Td><Td>{a.timeoutSeconds}s</Td><Td>{a.tokenBudget.toLocaleString()}</Td><Td>${a.costBudgetUsd}</Td><Td>{a.enabled ? "yes" : "no"}</Td></tr>)}
        </Table>
      </Card>
    </>
  );
}

function AgentCard({ a, canEdit }: { a: any; canEdit: boolean }) {
  const [edit, setEdit] = React.useState(false);
  const providers = useApi<any>(["model-providers"], edit ? "/model-providers" : null);
  const [src, setSrc] = React.useState<string>(a.modelProviderId ? `cfg:${a.modelProviderId}` : `env:${a.modelProvider}`);
  const [f, setF] = React.useState({ modelProvider: a.modelProvider, modelName: a.modelName, maxSteps: a.maxSteps, timeoutSeconds: a.timeoutSeconds, tokenBudget: a.tokenBudget, costBudgetUsd: Number(a.costBudgetUsd), allowedTools: a.allowedTools as string[] });
  const save = useAct(() => {
    const cfg = src.startsWith("cfg:") ? (providers.data?.items ?? []).find((p: any) => p.id === src.slice(4)) : null;
    return api(`/agents/${a.id}/versions`, { method: "POST", body: { ...f, modelProvider: cfg ? cfg.kind : src.slice(4), modelProviderId: cfg ? cfg.id : null } });
  }, [["agents"]]);
  return (
    <Card title={<span className="flex items-center gap-2"><ShieldCheck className="size-4" />{a.role.replace("_", " ")} <span className="text-xs font-normal text-muted">v{a.version}</span></span>} actions={canEdit && <Button size="sm" onClick={() => setEdit(!edit)}>{edit ? "Cancel" : "New version"}</Button>}>
      {!edit ? (
        <dl className="grid grid-cols-[130px_minmax(0,1fr)] gap-y-1 text-[13px]">
          <dt className="text-muted">Model</dt><dd className="mono text-xs">{a.modelProvider}/{a.modelName}{a.modelProviderId ? " · configured provider" : " · agent-service key"}</dd>
          <dt className="text-muted">Prompt version</dt><dd className="mono text-xs">{a.promptVersion}</dd>
          <dt className="text-muted">Budgets</dt><dd>{a.maxSteps} steps · {a.timeoutSeconds}s · {a.tokenBudget.toLocaleString()} tokens · ${a.costBudgetUsd}</dd>
          <dt className="text-muted">Tool permissions</dt><dd className="flex flex-wrap gap-1">{a.toolCatalog.map((t: string) => <Tag key={t} className={cn("whitespace-normal [overflow-wrap:anywhere]", a.allowedTools.includes(t) ? "text-emerald-600" : "line-through")}>{t}</Tag>)}</dd>
          <dt className="text-muted">Never allowed</dt><dd className="text-xs text-muted">shell, database, cloud credentials, infrastructure changes, self-approval</dd>
        </dl>
      ) : (
        <form className="grid grid-cols-2 gap-2" onSubmit={(e) => { e.preventDefault(); save.mutate(undefined as any, { onSuccess: () => setEdit(false) }); }}>
          <div><Label>Provider</Label><Select className="w-full" value={src} onChange={(e) => setSrc(e.target.value)}>
            <optgroup label="Configured in Settings → AI models">{(providers.data?.items ?? []).filter((p: any) => p.enabled).map((p: any) => <option key={p.id} value={`cfg:${p.id}`}>{p.name} ({p.hosting === "customer_hosted" ? "customer-hosted" : "external"})</option>)}</optgroup>
            <optgroup label="Agent service key (env)">{["gemini", "anthropic", "openai"].map((p) => <option key={p} value={`env:${p}`}>{p}</option>)}</optgroup>
          </Select></div>
          <div><Label>Model</Label><Input value={f.modelName} onChange={(e) => setF({ ...f, modelName: e.target.value })} /></div>
          <div><Label>Max steps</Label><Input type="number" value={f.maxSteps} onChange={(e) => setF({ ...f, maxSteps: Number(e.target.value) })} /></div>
          <div><Label>Timeout (s)</Label><Input type="number" value={f.timeoutSeconds} onChange={(e) => setF({ ...f, timeoutSeconds: Number(e.target.value) })} /></div>
          <div><Label>Token budget</Label><Input type="number" value={f.tokenBudget} onChange={(e) => setF({ ...f, tokenBudget: Number(e.target.value) })} /></div>
          <div><Label>Cost budget (USD)</Label><Input type="number" step="0.01" value={f.costBudgetUsd} onChange={(e) => setF({ ...f, costBudgetUsd: Number(e.target.value) })} /></div>
          <div className="col-span-2"><Label>Allowed tools</Label><div className="flex flex-wrap gap-2">{a.toolCatalog.map((t: string) => <label key={t} className="flex items-center gap-1 text-xs"><input type="checkbox" checked={f.allowedTools.includes(t)} onChange={(e) => setF({ ...f, allowedTools: e.target.checked ? [...f.allowedTools, t] : f.allowedTools.filter((x) => x !== t) })} />{t}</label>)}</div></div>
          <div className="col-span-2"><Button variant="primary" size="sm" loading={save.isPending}>Save as new version</Button><ErrorBox error={save.error} /></div>
        </form>
      )}
    </Card>
  );
}
