"use client";
import Link from "next/link";
import * as React from "react";
import { ShieldCheck, ShieldX } from "lucide-react";
import { useApi } from "@/lib/api";
import { fmtTime } from "@/lib/utils";
import { Drawer, Json, Loading, Severity, Table, Tabs, Tag, Td } from "@/components/ui";

const FIELDS = ["cloudProvider", "projectOrAccountReference", "region", "sourceType", "sourceName", "resourceType", "resourceId", "serviceName", "principal", "sourceIp", "destinationIp", "action", "status", "httpStatus", "httpMethod", "urlPath", "userAgent", "traceId", "requestId", "normalizedEventType", "deduplicationKey"];

export function EventDrawer({ id, onClose, onOpen }: { id: string | null; onClose: () => void; onOpen?: (id: string) => void }) {
  const q = useApi<any>(["event", id], id ? `/events/${id}` : null);
  const [tab, setTab] = React.useState<"normalized" | "raw" | "related">("normalized");
  const e = q.data?.event;
  return (
    <Drawer open={!!id} onClose={onClose} title={<span className="mono">event {id?.slice(0, 8)}</span>}>
      {q.isLoading || !e ? <Loading /> : (
        <>
          <div className="flex flex-wrap items-center gap-2">
            <Tag>{e.normalizedEventType}</Tag>{(e.categories ?? []).map((c: string) => <Tag key={c}>{c}</Tag>)}<Severity value={e.severity} />
            <span className="text-xs text-muted">{fmtTime(e.eventTimestamp)} (ingested {fmtTime(e.ingestionTimestamp)})</span>
          </div>
          <div className="flex items-center gap-2 text-xs">
            {q.data.integrity === "verified" ? <><ShieldCheck className="size-4 text-emerald-500" />Original evidence integrity verified (sha256 <span className="mono">{q.data.rawReference?.sha256.slice(0, 16)}…</span>)</>
              : <><ShieldX className="size-4 text-red-500" />Original evidence {q.data.integrity}</>}
          </div>
          {q.data.incidents?.length > 0 && <div className="text-xs">Part of: {q.data.incidents.map((i: any) => <Link key={i.id} className="mr-2 text-accent" href={`/incidents/${i.id}`}>CASE-{String(i.case_number).padStart(4, "0")}</Link>)}</div>}
          <Tabs value={tab} onChange={setTab} tabs={[{ id: "normalized", label: "Normalized" }, { id: "raw", label: "Original (redacted view)" }, { id: "related", label: `Related by trace (${q.data.relatedByTrace.length})` }]} />
          {tab === "normalized" && (
            <>
              <dl className="grid grid-cols-[180px_minmax(0,1fr)] gap-x-3 gap-y-1 text-[12.5px]">
                {FIELDS.map((f) => <React.Fragment key={f}><dt className="text-muted">{f}</dt><dd className="mono break-all">{e[f] === null || e[f] === undefined ? <span className="text-muted">null</span> : String(e[f])}</dd></React.Fragment>)}
              </dl>
              <Json value={e.normalizedPayload} />
            </>
          )}
          {tab === "raw" && <><p className="text-xs text-muted">Stored immutably; secrets/tokens are redacted in this view only.</p><Json value={q.data.raw} /></>}
          {tab === "related" && (
            <Table head={["Time", "Log", "Type", "Detail", ""]} empty="No trace correlation for this event.">
              {q.data.relatedByTrace.map((r: any) => (
                <tr key={r.id}>
                  <Td className="whitespace-nowrap text-xs text-muted">{fmtTime(r.eventTimestamp)}</Td>
                  <Td className="mono text-xs">{r.sourceName}</Td>
                  <Td><Tag>{r.normalizedEventType}</Tag></Td>
                  <Td className="mono max-w-sm truncate text-xs">{r.action ?? r.message}</Td>
                  <Td>{onOpen && <button className="text-xs text-accent" onClick={() => onOpen(r.id)}>open</button>}</Td>
                </tr>
              ))}
            </Table>
          )}
        </>
      )}
    </Drawer>
  );
}
