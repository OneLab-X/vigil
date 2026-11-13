"use client";
import * as React from "react";
import { api, useAct, useApi } from "@/lib/api";
import { useCan } from "@/components/shell";
import { Button, Card, ErrorBox, Input, Label, Select, Table, Tag, Td } from "@/components/ui";

const POLICY_TEXT: Record<string, string> = {
  any: "Any configured provider (vendor-hosted APIs allowed)",
  customer_hosted_only: "Customer-hosted models only — evidence never leaves your infrastructure",
  disabled: "AI investigations disabled",
};
const KINDS = [
  { v: "openai_compatible", l: "OpenAI-compatible (Ollama, vLLM, LM Studio…)" },
  { v: "gemini", l: "Google Gemini API" },
  { v: "anthropic", l: "Anthropic API" },
  { v: "openai", l: "OpenAI API" },
];
const empty = { name: "", kind: "openai_compatible", baseUrl: "http://host.docker.internal:11434/v1", apiKey: "", hosting: "customer_hosted", timeoutSeconds: 120, priceInputPerMtok: 0, priceOutputPerMtok: 0 };

export function AiModels() {
  const can = useCan()("agents:write");
  const q = useApi<any>(["model-providers"], "/model-providers");
  const [f, setF] = React.useState<any>(empty);
  const [adding, setAdding] = React.useState(false);
  const [probe, setProbe] = React.useState<Record<string, { model: string; result?: string; ok?: boolean; busy?: boolean }>>({});
  const add = useAct(() => api("/model-providers", { method: "POST", body: { ...f, baseUrl: f.baseUrl || null, apiKey: f.apiKey || null } }), [["model-providers"]]);
  const patch = useAct((v: { id: string; body: any }) => api(`/model-providers/${v.id}`, { method: "PATCH", body: v.body }), [["model-providers"]]);
  const del = useAct((id: string) => api(`/model-providers/${id}`, { method: "DELETE" }), [["model-providers"]]);
  const policy = useAct((p: string) => api("/settings/ai", { method: "PUT", body: { dataPolicy: p } }), [["model-providers"]]);
  const masking = useAct((m: string) => api("/settings/ai", { method: "PUT", body: { masking: m } }), [["model-providers"]]);
  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setF({ ...f, [k]: e.target.type === "number" ? Number(e.target.value) : e.target.value });
  const test = async (id: string) => {
    const model = probe[id]?.model?.trim();
    if (!model) return setProbe({ ...probe, [id]: { model: "", result: "Enter a model name to test", ok: false } });
    setProbe((p) => ({ ...p, [id]: { model, busy: true } }));
    try { const r = await api<any>(`/model-providers/${id}/test`, { method: "POST", body: { model } }); setProbe((p) => ({ ...p, [id]: { model, ok: r.ok, result: r.detail } })); }
    catch (e) { setProbe((p) => ({ ...p, [id]: { model, ok: false, result: (e as Error).message } })); }
  };

  return (
    <Card title="AI models" actions={can && <Button size="sm" onClick={() => setAdding(!adding)}>{adding ? "Cancel" : "Add provider"}</Button>}>
      <div className="space-y-4 text-[13px]">
        <div className="grid gap-2 md:grid-cols-[minmax(0,1fr)_minmax(0,2fr)] md:items-center">
          <div><Label>AI data policy</Label><p className="text-xs text-muted">Checked before every investigation run.</p></div>
          <Select className="w-full" disabled={!can || policy.isPending} value={q.data?.dataPolicy ?? "any"} onChange={(e) => policy.mutate(e.target.value)}>
            {Object.entries(POLICY_TEXT).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </Select>
        </div>
        <ErrorBox error={policy.error} />
        <div className="grid gap-2 md:grid-cols-[minmax(0,1fr)_minmax(0,2fr)] md:items-center">
          <div><Label>Mask sensitive data</Label><p className="text-xs text-muted">Default for every run; admins can override per run.</p></div>
          <Select className="w-full" disabled={!can || masking.isPending} value={q.data?.masking ?? "on"} onChange={(e) => masking.mutate(e.target.value)}>
            <option value="on">On — IPs, emails, identities, accounts and resources are replaced with tokens</option>
            <option value="off">Off — real values are sent to the model</option>
          </Select>
        </div>
        <ErrorBox error={masking.error} />
        <p className="text-xs text-muted">
          Investigations send case context and redacted log excerpts to the model you choose. With masking on, IPs, emails, identities, cloud accounts and
          resource names are replaced by consistent tokens (e.g. [[IP_3:public]]) and restored only inside Vigil; URL paths, actions, user agents and timestamps stay visible. Keys are encrypted at rest,
          used only by the agent service, and never shown again or given to the model. Agents without a configured provider use the API keys set on the agent service.
        </p>

        {adding && can && (
          <form className="grid gap-2 rounded-md border border-border p-3 md:grid-cols-2" onSubmit={(e) => { e.preventDefault(); add.mutate(undefined as any, { onSuccess: () => { setAdding(false); setF(empty); } }); }}>
            <div><Label>Name</Label><Input className="w-full" required value={f.name} onChange={set("name")} placeholder="Local Ollama" /></div>
            <div><Label>Type</Label><Select className="w-full" value={f.kind} onChange={set("kind")}>{KINDS.map((k) => <option key={k.v} value={k.v}>{k.l}</option>)}</Select></div>
            <div><Label hint={f.kind === "openai_compatible" ? "required" : "optional, for gateways"}>Base URL</Label><Input className="w-full" value={f.baseUrl} onChange={set("baseUrl")} /></div>
            <div><Label hint="stored encrypted, write-only">API key</Label><Input className="w-full" type="password" autoComplete="off" value={f.apiKey} onChange={set("apiKey")} /></div>
            <div><Label>Hosting</Label><Select className="w-full" value={f.hosting} onChange={set("hosting")}><option value="customer_hosted">Customer-hosted (your infrastructure)</option><option value="external">External (vendor API)</option></Select></div>
            <div><Label>Timeout (s)</Label><Input className="w-full" type="number" min={5} max={1800} value={f.timeoutSeconds} onChange={set("timeoutSeconds")} /></div>
            <div><Label hint="USD per 1M tokens">Input price</Label><Input className="w-full" type="number" step="0.01" min={0} value={f.priceInputPerMtok} onChange={set("priceInputPerMtok")} /></div>
            <div><Label hint="USD per 1M tokens">Output price</Label><Input className="w-full" type="number" step="0.01" min={0} value={f.priceOutputPerMtok} onChange={set("priceOutputPerMtok")} /></div>
            <div className="md:col-span-2"><Button variant="primary" size="sm" loading={add.isPending}>Save provider</Button><ErrorBox error={add.error} /></div>
          </form>
        )}

        <div className="-mx-4">
          <Table head={["Name", "Type", "Hosting", "Endpoint", "Key", "Price in/out", "Status", ""]} empty="No providers configured. Agents use the keys set on the agent service.">
            {(q.data?.items ?? []).map((p: any) => (
              <tr key={p.id} className="align-top">
                <Td className="font-medium">{p.name}</Td>
                <Td className="text-xs">{p.kind}</Td>
                <Td><Tag className={p.hosting === "customer_hosted" ? "text-emerald-600" : ""}>{p.hosting === "customer_hosted" ? "customer-hosted" : "external"}</Tag></Td>
                <Td className="mono max-w-[220px] truncate text-xs" title={p.baseUrl ?? ""}>{p.baseUrl ?? "default"}</Td>
                <Td className="text-xs">{p.hasApiKey ? "stored" : "none"}</Td>
                <Td className="text-xs tabular-nums">${p.priceInputPerMtok} / ${p.priceOutputPerMtok}</Td>
                <Td className="text-xs">{p.enabled ? "enabled" : "disabled"}</Td>
                <Td>
                  {can && (
                    <div className="flex min-w-[260px] flex-col gap-1">
                      <div className="flex gap-1">
                        <Input className="h-7 w-36 text-xs" placeholder="model to test" value={probe[p.id]?.model ?? ""} onChange={(e) => setProbe({ ...probe, [p.id]: { model: e.target.value } })} />
                        <Button size="sm" loading={probe[p.id]?.busy} onClick={() => test(p.id)}>Test</Button>
                        <Button size="sm" onClick={() => patch.mutate({ id: p.id, body: { enabled: !p.enabled } })}>{p.enabled ? "Disable" : "Enable"}</Button>
                        <Button size="sm" variant="ghost" onClick={() => { if (confirm(`Delete provider "${p.name}"?`)) del.mutate(p.id); }}>Delete</Button>
                      </div>
                      {probe[p.id]?.result && <span className={probe[p.id]?.ok ? "text-xs text-emerald-600" : "text-xs text-red-600"}>{probe[p.id]?.result}</span>}
                    </div>
                  )}
                </Td>
              </tr>
            ))}
          </Table>
        </div>
        <ErrorBox error={patch.error ?? del.error} />
      </div>
    </Card>
  );
}
