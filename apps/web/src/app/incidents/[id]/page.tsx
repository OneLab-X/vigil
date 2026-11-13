"use client";
import Link from "next/link";
import { useParams } from "next/navigation";
import * as React from "react";
import { AlertTriangle, Bot, CheckCircle2, CircleSlash, Clock, EyeOff, FileSearch, Link2, ShieldCheck, User, XCircle } from "lucide-react";
import { api, useAct, useApi } from "@/lib/api";
import { cn, fmtTime, pct } from "@/lib/utils";
import { useCan } from "@/components/shell";
import { EventDrawer } from "@/components/event-drawer";
import { Button, Card, ErrorBox, Input, Json, Loading, Select, Severity, Status, Table, Tabs, Tag, Td, Textarea, Verdict } from "@/components/ui";

const MASK_NAMES: Record<string, string> = { IP: "IPs", EMAIL: "emails", USER: "users", SVC: "service accounts", ROLE: "roles", ACCOUNT: "accounts", RESOURCE: "resources" };
const maskLabel = (s: Record<string, number> | null | undefined) => Object.entries(s ?? {}).filter(([, n]) => n > 0).map(([k, n]) => `${n} ${MASK_NAMES[k] ?? k}`).join(" · ");

export default function IncidentWorkspace() {
  const { id } = useParams<{ id: string }>();
  const can = useCan();
  const key = ["incident", id];
  const q = useApi<any>(key, `/incidents/${id}`, { refetchInterval: 8_000 });
  const [eventId, setEventId] = React.useState<string | null>(null);
  const [tab, setTab] = React.useState<"evidence" | "events" | "trace" | "audit">("evidence");
  const ai = useApi<any>(["model-providers"], "/model-providers");
  const maskDefault: "on" | "off" = ai.data?.masking ?? "on";
  const investigate = useAct((v: { role: string; masking?: "on" | "off" }) => api(`/incidents/${id}/investigate`, { method: "POST", body: v }), [key]);
  const patch = useAct((body: any) => api(`/incidents/${id}`, { method: "PATCH", body }), [key, ["incidents"]]);

  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const d = q.data;
  const inc = d.incident;
  const verdict = d.verdicts[0];
  const contract = verdict?.contract;
  const activeRun = d.runs.find((r: any) => r.status === "running" || r.status === "queued");
  const eventsById = new Map(d.events.map((e: any) => [e.id, e]));
  const evLink = (eid?: string | null) => eid ? <button onClick={() => setEventId(eid)} className="mono inline-flex items-center gap-1 text-[11px] text-accent hover:underline"><Link2 className="size-3" />{eid.slice(0, 8)}</button> : null;

  return (
    <>
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-xs text-muted"><Link href="/incidents" className="hover:underline">Incidents</Link><span>/</span><span className="mono">{inc.caseId}</span></div>
          <h1 className="mt-1 text-xl font-semibold tracking-tight">{inc.title}</h1>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <Severity value={inc.severity} /><Status value={inc.status} /><Tag className="mono">{inc.correlationKey}</Tag>
            <span className="text-xs text-muted">{fmtTime(inc.firstSeen)} → {fmtTime(inc.lastSeen)}</span>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {can("incidents:write") && (
            <>
              <Select value="" onChange={(e) => e.target.value && patch.mutate({ status: e.target.value })} aria-label="Change status">
                <option value="">Move to…</option>{d.allowedTransitions.map((s: string) => <option key={s} value={s}>{s.replace(/_/g, " ")}</option>)}
              </Select>
              <Select value="" onChange={(e) => e.target.value && patch.mutate({ severity: e.target.value })} aria-label="Change severity">
                <option value="">Severity…</option>{["critical", "high", "medium", "low", "info"].map((s) => <option key={s}>{s}</option>)}
              </Select>
              <Select value={inc.assigneeId ?? ""} onChange={(e) => patch.mutate({ assigneeId: e.target.value || null })} aria-label="Assignee">
                <option value="">Unassigned</option>{d.members.map((m: any) => <option key={m.id} value={m.id}>{m.displayName}</option>)}
              </Select>
            </>
          )}
          {can("investigations:run") && (
            <div className="flex items-center gap-1">
              <Button variant="primary" loading={investigate.isPending} disabled={!!activeRun} onClick={() => investigate.mutate({ role: "investigation_analyst" })}
                title={maskDefault === "on" ? "IPs, emails, identities, accounts and resources are replaced with tokens before reaching the AI model" : "Real values are sent to the AI model"}>
                <Bot className="size-4" />{activeRun ? `${activeRun.role.replace("_", " ")} running…` : "Run AI investigation"}
                {!activeRun && <span className="ml-1 rounded bg-white/20 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide">{maskDefault === "on" ? "masked" : "unmasked"}</span>}
              </Button>
              {!activeRun && maskDefault === "on" && can("agents:write") && (
                <Button size="sm" variant="ghost" disabled={investigate.isPending}
                  onClick={() => { if (confirm("Run this investigation WITHOUT masking? Real IPs, emails, identities and account names will be sent to the AI model.")) investigate.mutate({ role: "investigation_analyst", masking: "off" }); }}>Run unmasked</Button>
              )}
              {!activeRun && maskDefault === "off" && (
                <Button size="sm" variant="ghost" disabled={investigate.isPending} onClick={() => investigate.mutate({ role: "investigation_analyst", masking: "on" })}><EyeOff className="size-3.5" />Run masked</Button>
              )}
            </div>
          )}
        </div>
      </div>
      <ErrorBox error={investigate.error ?? patch.error} />

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_380px]">
        <div className="space-y-4 min-w-0">
          <VerdictPanel d={d} verdict={verdict} contract={contract} evLink={evLink} incidentId={id} queryKey={key} />

          <Card pad={false}>
            <div className="px-2"><Tabs value={tab} onChange={setTab} tabs={[
              { id: "evidence", label: `Evidence (${d.evidence.length})` }, { id: "events", label: `Supporting events (${d.events.length})` },
              { id: "trace", label: `AI reasoning trace (${d.toolCalls.length})` }, { id: "audit", label: `Audit history (${d.audit.length})` },
            ]} /></div>
            {tab === "evidence" && (
              <Table head={["", "Claim", "Event", "Time", "Source IP", "Action", "Result"]} empty="No AI evidence yet. Run an investigation.">
                {d.evidence.map((e: any) => (
                  <tr key={e.id}>
                    <Td>{e.kind === "supporting" ? <CheckCircle2 className="size-4 text-emerald-500" aria-label="supporting" /> : <CircleSlash className="size-4 text-amber-500" aria-label="contradictory" />}</Td>
                    <Td className="max-w-md">{e.claim}{e.verified && <span className="ml-1.5 text-[10px] font-semibold uppercase text-emerald-600 dark:text-emerald-400">verified</span>}</Td>
                    <Td>{evLink(e.eventId)}</Td>
                    <Td className="whitespace-nowrap text-xs text-muted">{fmtTime(e.event?.eventTimestamp)}</Td>
                    <Td className="mono text-xs">{e.event?.sourceIp ?? "—"}</Td>
                    <Td className="mono max-w-[220px] truncate text-xs">{e.event?.action ?? "—"}</Td>
                    <Td className="text-xs">{e.event?.httpStatus ?? e.event?.status ?? "—"}</Td>
                  </tr>
                ))}
              </Table>
            )}
            {tab === "events" && (
              <Table head={["Time", "Provider", "Type", "Source IP / principal", "Action", "Status", ""]}>
                {d.events.map((e: any) => (
                  <tr key={e.id} className="hover:bg-panel-2">
                    <Td className="whitespace-nowrap text-xs text-muted">{fmtTime(e.eventTimestamp)}</Td>
                    <Td className="text-xs uppercase">{e.cloudProvider}</Td>
                    <Td><Tag>{e.normalizedEventType}</Tag></Td>
                    <Td className="mono max-w-[220px] truncate text-xs">{e.sourceIp ?? e.principal ?? "—"}</Td>
                    <Td className="mono max-w-[260px] truncate text-xs">{e.action ?? "—"}</Td>
                    <Td className="text-xs">{e.httpStatus ?? e.status ?? "—"}</Td>
                    <Td>{evLink(e.id)}</Td>
                  </tr>
                ))}
              </Table>
            )}
            {tab === "trace" && (
              <div className="divide-y divide-border">
                {d.runs.length === 0 && <p className="p-6 text-center text-sm text-muted">No agent runs yet.</p>}
                {d.runs.map((r: any) => (
                  <details key={r.id} className="group" open={r === d.runs[0]}>
                    <summary className="flex cursor-pointer flex-wrap items-center gap-2 px-4 py-2.5 text-[13px]">
                      <Bot className="size-4 text-muted" /><span className="font-medium">{r.role.replace("_", " ")}</span><Status value={r.status} />
                      <span className="text-xs text-muted">{r.modelProvider}/{r.modelName} · prompt {r.promptVersion} · {r.steps} steps · {(r.inputTokens + r.outputTokens).toLocaleString()} tok · ${Number(r.costUsd).toFixed(4)}</span>
                      <Tag className={r.masking === "on" ? "text-emerald-600" : ""}>{r.masking === "on" ? <><EyeOff className="mr-1 size-3" />masked</> : "unmasked"}</Tag>
                      <span className="ml-auto text-xs text-muted">{fmtTime(r.createdAt)}</span>
                    </summary>
                    <div className="space-y-2 px-4 pb-4">
                      <p className="text-xs text-muted"><b>Task:</b> {r.task}</p>
                      {r.masking === "on" && (
                        <p className="text-xs text-muted"><b>Masked before reaching the model:</b> {maskLabel(r.maskStats) || "nothing sensitive found yet"}. Tool arguments below show what the model saw (tokens); the verdict and notes show real values.</p>
                      )}
                      {r.error && <ErrorBox error={{ message: r.error }} />}
                      {r.validationErrors && (
                        <div className="rounded-md border border-red-500/30 bg-red-500/5 p-2.5 text-xs">
                          <div className="mb-1 flex items-center gap-1 font-semibold text-red-600 dark:text-red-400"><AlertTriangle className="size-3.5" />Output rejected by control-plane validation</div>
                          <ul className="list-disc pl-5">{(r.validationErrors as any[]).map((v, i) => <li key={i}><span className="mono">{v.path ?? v.path?.join?.(".")}</span>: {v.problem ?? v.message}</li>)}</ul>
                        </div>
                      )}
                      <ol className="space-y-1">
                        {d.toolCalls.filter((c: any) => c.runId === r.id).map((c: any) => (
                          <li key={c.id} className="flex flex-wrap items-baseline gap-2 text-xs">
                            <span className="mono text-muted">#{c.seq}</span>
                            <span className={cn("mono font-medium", !c.allowed && "text-red-600 line-through dark:text-red-400")}>{c.tool}</span>
                            <span className="mono max-w-xl truncate text-muted">{JSON.stringify(c.arguments)}</span>
                            {!c.allowed && <Tag className="text-red-600">denied: {c.denialReason}</Tag>}
                            {c.allowed && <span className="text-muted">→ {c.resultSummary?.events ?? 0} events · {c.durationMs}ms{c.resultSummary?.error ? ` · error: ${c.resultSummary.error}` : ""}</span>}
                          </li>
                        ))}
                      </ol>
                    </div>
                  </details>
                ))}
              </div>
            )}
            {tab === "audit" && (
              <Table head={["Time", "Actor", "Action", "Details"]}>
                {d.audit.map((a: any) => (
                  <tr key={a.id}>
                    <Td className="whitespace-nowrap text-xs text-muted">{fmtTime(a.createdAt)}</Td>
                    <Td className="text-xs">{a.actorType === "agent" ? <span className="inline-flex items-center gap-1"><Bot className="size-3" />agent</span> : a.actorType === "user" ? <span className="inline-flex items-center gap-1"><User className="size-3" />{d.members.find((m: any) => m.id === a.actorId)?.displayName ?? "user"}</span> : a.actorId}</Td>
                    <Td className="mono text-xs">{a.action}</Td>
                    <Td className="mono max-w-lg truncate text-[11px] text-muted">{JSON.stringify(a.details)}</Td>
                  </tr>
                ))}
              </Table>
            )}
          </Card>
        </div>

        <div className="space-y-4">
          <Card title="Detections">
            <ul className="space-y-3">
              {d.findings.map((f: any) => (
                <li key={f.id} className="text-[13px]">
                  <div className="flex items-center justify-between gap-2"><span className="font-medium">{f.rule.name}</span><Severity value={f.severity} /></div>
                  <div className="mt-0.5 text-xs text-muted"><span className="mono">{f.rule.ruleId} v{f.rule.version}</span> · {f.eventCount} events · rule confidence {pct(f.confidence)}</div>
                  <div className="mt-1 flex flex-wrap gap-1">{(f.rule.mitre ?? []).map((m: any) => <Tag key={m.technique}>{m.technique}{m.name ? ` ${m.name}` : ""}</Tag>)}</div>
                  <div className="mono mt-1 text-[11px] text-muted">{JSON.stringify(f.details)}</div>
                </li>
              ))}
            </ul>
          </Card>
          {contract && (
            <Card title="Related entities">
              {(["ips", "principals", "resources"] as const).map((k) => contract.entities[k]?.length ? (
                <div key={k} className="mb-2"><div className="mb-1 text-[11px] uppercase text-muted">{k}</div><div className="flex flex-wrap gap-1">{contract.entities[k].map((v: string) => <Link key={v} href={`/events?${k === "ips" ? "sourceIp" : k === "principals" ? "principal" : "resourceId"}=${encodeURIComponent(v)}`}><Tag className="mono hover:text-fg">{v}</Tag></Link>)}</div></div>
              ) : null)}
            </Card>
          )}
          <Notes d={d} incidentId={id} queryKey={key} />
          <Feedback incidentId={id} queryKey={key} defaultKey={inc.correlationKey.split(":").slice(1).join(":")} />
        </div>
      </div>
      <EventDrawer id={eventId} onClose={() => setEventId(null)} onOpen={setEventId} />
    </>
  );
}

function VerdictPanel({ d, verdict, contract, evLink, incidentId, queryKey }: any) {
  const can = useCan();
  const [comment, setComment] = React.useState("");
  const [override, setOverride] = React.useState("");
  const decide = useAct((decision: string) => api(`/incidents/${incidentId}/approve`, { method: "POST", body: { verdictId: verdict.id, decision, comment: comment || undefined, overrideVerdict: override || undefined } }), [queryKey, ["incidents"]]);
  const rec = useAct(({ id, ...body }: any) => api(`/recommendations/${id}`, { method: "PATCH", body }), [queryKey]);
  if (!verdict) {
    const last = d.runs[0];
    return (
      <Card title="AI verdict">
        <p className="text-sm text-muted">{last ? <>Latest run: <b>{last.role.replace("_", " ")}</b> — <Status value={last.status} />{last.error ? ` (${last.error})` : ""}</> : "No investigation has run yet."}</p>
        {d.notes.filter((n: any) => n.authorRunId).slice(-1).map((n: any) => <p key={n.id} className="mt-2 rounded-md bg-panel-2 p-2.5 text-[13px]">{n.body}</p>)}
      </Card>
    );
  }
  return (
    <Card title={<span className="flex items-center gap-2"><Bot className="size-4" />AI investigation result</span>} actions={<span className="text-xs text-muted">review: <Status value={verdict.reviewStatus} /></span>}>
      <div className="flex flex-wrap items-center gap-3">
        <Verdict value={verdict.verdict} />
        <span className="text-xs text-muted">Severity</span><Severity value={verdict.severity} />
        <span className="text-xs text-muted">Confidence</span>
        <div className="flex items-center gap-1.5"><div className="h-1.5 w-24 overflow-hidden rounded bg-panel-2"><div className="h-full bg-accent" style={{ width: pct(verdict.confidence) }} /></div><span className="text-xs tabular-nums">{pct(verdict.confidence)}</span></div>
      </div>
      <p className="mt-3 text-[14px] leading-relaxed">{verdict.summary}</p>
      {contract.abstention_reason && <p className="mt-2 text-xs text-muted">Abstention reason: {contract.abstention_reason}</p>}

      <div className="mt-4 grid gap-4 md:grid-cols-2">
        <div>
          <h4 className="mb-2 flex items-center gap-1 text-xs font-semibold uppercase text-muted"><Clock className="size-3.5" />Timeline</h4>
          <ol className="space-y-2 border-l border-border pl-3">
            {contract.timeline.map((t: any, i: number) => (
              <li key={i} className="text-[13px]"><div className="text-[11px] text-muted">{fmtTime(t.timestamp)} {evLink(t.event_id)}</div>{t.description}</li>
            ))}
          </ol>
        </div>
        <div>
          <h4 className="mb-2 flex items-center gap-1 text-xs font-semibold uppercase text-muted"><FileSearch className="size-3.5" />Impact assessment</h4>
          <dl className="grid grid-cols-[110px_minmax(0,1fr)] gap-y-1 text-[13px]">
            <dt className="text-muted">Outcome</dt><dd className="font-medium">{contract.impact_assessment.outcome}</dd>
            <dt className="text-muted">Data exposure</dt><dd>{contract.impact_assessment.data_exposure.replace(/_/g, " ")}</dd>
            <dt className="text-muted">Scope</dt><dd>{contract.impact_assessment.scope}</dd>
          </dl>
          {contract.contradictory_evidence.length > 0 && (
            <div className="mt-3 rounded-md border border-amber-500/30 bg-amber-500/5 p-2.5">
              <div className="mb-1 text-xs font-semibold text-amber-700 dark:text-amber-300">Contradictory findings</div>
              <ul className="space-y-1 text-[13px]">{contract.contradictory_evidence.map((e: any, i: number) => <li key={i}>{e.claim} {evLink(e.event_id)}</li>)}</ul>
            </div>
          )}
        </div>
      </div>

      <h4 className="mb-2 mt-4 text-xs font-semibold uppercase text-muted">Recommended actions (require approval — Vigil never executes them)</h4>
      <ul className="space-y-2">
        {d.recommendations.filter((r: any) => r.verdictId === verdict.id).map((r: any) => (
          <li key={r.id} className="flex flex-wrap items-start justify-between gap-2 rounded-md border border-border p-2.5">
            <div className="min-w-0 flex-1"><div className="text-[13px] font-medium">{r.action}</div><div className="text-xs text-muted">{r.rationale}</div>{r.ticketRef && <div className="mt-1 text-xs">Ticket: <span className="mono">{r.ticketRef}</span></div>}</div>
            <div className="flex items-center gap-1.5"><Tag>{r.priority}</Tag><Status value={r.status} />
              {can("verdicts:review") && r.status === "proposed" && <>
                <Button size="sm" onClick={() => rec.mutate({ id: r.id, status: "approved" })}>Approve</Button>
                <Button size="sm" variant="ghost" onClick={() => rec.mutate({ id: r.id, status: "rejected" })}>Reject</Button>
              </>}
              {can("verdicts:review") && r.status === "approved" && <Button size="sm" onClick={() => { const t = prompt("Ticket reference (e.g. JIRA-123)"); if (t) rec.mutate({ id: r.id, status: "ticketed", ticketRef: t }); }}>Create ticket ref</Button>}
              {can("verdicts:review") && (r.status === "approved" || r.status === "ticketed") && <Button size="sm" variant="ghost" onClick={() => { const n = prompt("Final action taken"); if (n) rec.mutate({ id: r.id, status: "done", finalActionNote: n }); }}>Record final action</Button>}
            </div>
          </li>
        ))}
      </ul>

      {verdict.reviewStatus === "pending" && can("verdicts:review") && (
        <div className="mt-4 rounded-md border border-accent/40 bg-accent/5 p-3">
          <div className="mb-2 flex items-center gap-1.5 text-[13px] font-semibold"><ShieldCheck className="size-4" />Human decision required</div>
          <div className="grid gap-2 md:grid-cols-[minmax(0,1fr)_200px]">
            <Input placeholder="Comment (recorded in the audit log)" value={comment} onChange={(e) => setComment(e.target.value)} />
            <Select value={override} onChange={(e) => setOverride(e.target.value)}><option value="">Accept AI verdict</option>{["confirmed", "likely", "benign", "inconclusive", "needs_more_data"].map((v) => <option key={v} value={v}>Override → {v.replace(/_/g, " ")}</option>)}</Select>
          </div>
          <div className="mt-2 flex gap-2">
            <Button variant="primary" loading={decide.isPending} onClick={() => decide.mutate("approved")}><CheckCircle2 className="size-4" />Approve conclusion</Button>
            <Button loading={decide.isPending} onClick={() => decide.mutate("rejected")}><XCircle className="size-4" />Reject &amp; reopen</Button>
          </div>
          <ErrorBox error={decide.error ?? rec.error} />
        </div>
      )}
      {verdict.reviewStatus !== "pending" && <p className="mt-3 text-xs text-muted">Reviewed {fmtTime(verdict.reviewedAt)}{verdict.reviewComment ? ` — “${verdict.reviewComment}”` : ""}</p>}
      <details className="mt-3"><summary className="cursor-pointer text-xs text-muted">Raw output contract</summary><Json value={contract} className="mt-2" /></details>
    </Card>
  );
}

function Notes({ d, incidentId, queryKey }: any) {
  const can = useCan();
  const [body, setBody] = React.useState("");
  const add = useAct(() => api(`/incidents/${incidentId}/notes`, { method: "POST", body: { body } }), [queryKey]);
  return (
    <Card title="Analyst notes">
      <ul className="max-h-80 space-y-2 overflow-y-auto">
        {d.notes.map((n: any) => (
          <li key={n.id} className="rounded-md bg-panel-2 p-2 text-[13px]"><div className="mb-0.5 flex items-center gap-1 text-[11px] text-muted">{n.authorRunId ? <Bot className="size-3" /> : <User className="size-3" />}{n.author} · {fmtTime(n.createdAt)}</div><p className="whitespace-pre-wrap">{n.body}</p></li>
        ))}
      </ul>
      {can("incidents:write") && (
        <form className="mt-2 space-y-2" onSubmit={(e) => { e.preventDefault(); if (body.trim()) add.mutate(undefined as any, { onSuccess: () => setBody("") }); }}>
          <Textarea rows={2} placeholder="Add a note…" value={body} onChange={(e) => setBody(e.target.value)} />
          <Button size="sm" loading={add.isPending}>Add note</Button>
        </form>
      )}
    </Card>
  );
}

function Feedback({ incidentId, queryKey, defaultKey }: any) {
  const can = useCan();
  const [kind, setKind] = React.useState("false_positive");
  const [k, setK] = React.useState(defaultKey);
  const [title, setTitle] = React.useState("");
  const [body, setBody] = React.useState("");
  const send = useAct(() => api(`/incidents/${incidentId}/feedback`, { method: "POST", body: { kind, key: k, title, body } }), [queryKey, ["knowledge"]]);
  if (!can("knowledge:propose")) return null;
  return (
    <Card title="Feedback → knowledge proposal">
      <form className="space-y-2" onSubmit={(e) => { e.preventDefault(); send.mutate(undefined as any, { onSuccess: () => { setTitle(""); setBody(""); } }); }}>
        <Select className="w-full" value={kind} onChange={(e) => setKind(e.target.value)}>{["false_positive", "trusted_identity", "trusted_ip", "lesson", "policy"].map((x) => <option key={x} value={x}>{x.replace(/_/g, " ")}</option>)}</Select>
        <Input placeholder="Key (IP, principal, rule id)" value={k} onChange={(e) => setK(e.target.value)} required />
        <Input placeholder="Title" value={title} onChange={(e) => setTitle(e.target.value)} required minLength={3} />
        <Textarea rows={3} placeholder="Why? (future agents will see this once approved)" value={body} onChange={(e) => setBody(e.target.value)} required minLength={3} />
        <Button size="sm" loading={send.isPending}>Submit for approval</Button>
        {send.isSuccess && <p className="text-xs text-emerald-600">Proposed. Another analyst must approve it in Security Knowledge.</p>}
        <ErrorBox error={send.error} />
      </form>
    </Card>
  );
}
