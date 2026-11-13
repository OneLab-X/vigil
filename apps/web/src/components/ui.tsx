"use client";
import * as React from "react";
import { cn } from "@/lib/utils";
import { Loader2 } from "lucide-react";

export function Card({ className, children, title, actions, pad = true }: { className?: string; children?: React.ReactNode; title?: React.ReactNode; actions?: React.ReactNode; pad?: boolean }) {
  return (
    <section className={cn("min-w-0 rounded-lg border border-border bg-panel", className)}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-2 border-b border-border px-4 py-2.5">
          <h3 className="text-[13px] font-semibold tracking-tight">{title}</h3>
          <div className="flex items-center gap-2">{actions}</div>
        </header>
      )}
      <div className={cn(pad && "p-4")}>{children}</div>
    </section>
  );
}

type BtnProps = React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "ghost" | "danger"; size?: "sm" | "md"; loading?: boolean };
export function Button({ variant = "secondary", size = "md", loading, className, children, disabled, ...p }: BtnProps) {
  return (
    <button
      {...p}
      disabled={disabled || loading}
      className={cn(
        "inline-flex items-center justify-center gap-1.5 rounded-md font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent",
        size === "sm" ? "h-7 px-2.5 text-xs" : "h-8 px-3 text-[13px]",
        variant === "primary" && "bg-accent text-accent-fg hover:opacity-90",
        variant === "secondary" && "border border-border bg-panel hover:bg-panel-2",
        variant === "ghost" && "hover:bg-panel-2",
        variant === "danger" && "bg-red-600 text-white hover:bg-red-700",
        className,
      )}
    >
      {loading && <Loader2 className="size-3.5 animate-spin" />}
      {children}
    </button>
  );
}

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(({ className, ...p }, ref) => (
  <input ref={ref} {...p} className={cn("h-8 w-full rounded-md border border-border bg-panel px-2.5 text-[13px] outline-none placeholder:text-muted focus:border-accent", className)} />
));
Input.displayName = "Input";

export function Select({ className, children, ...p }: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return <select {...p} className={cn("h-8 rounded-md border border-border bg-panel px-2 text-[13px] outline-none focus:border-accent", className)}>{children}</select>;
}

export function Textarea({ className, ...p }: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea {...p} className={cn("w-full rounded-md border border-border bg-panel p-2.5 text-[13px] outline-none placeholder:text-muted focus:border-accent", className)} />;
}

export function Label({ children, hint }: { children: React.ReactNode; hint?: string }) {
  return <label className="mb-1 block text-xs font-medium text-muted">{children}{hint && <span className="ml-1 font-normal opacity-70">{hint}</span>}</label>;
}

const SEV: Record<string, string> = {
  critical: "bg-red-600/15 text-red-600 dark:text-red-400 ring-red-600/30",
  high: "bg-orange-500/15 text-orange-600 dark:text-orange-400 ring-orange-500/30",
  medium: "bg-amber-400/15 text-amber-700 dark:text-amber-300 ring-amber-400/30",
  low: "bg-sky-500/15 text-sky-700 dark:text-sky-300 ring-sky-500/30",
  info: "bg-slate-500/15 text-slate-600 dark:text-slate-300 ring-slate-500/30",
};
export function Severity({ value }: { value?: string | null }) {
  if (!value) return <span className="text-muted">—</span>;
  return <span className={cn("inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide ring-1 ring-inset", SEV[value] ?? SEV.info)}><span className="size-1.5 rounded-full bg-current" />{value}</span>;
}

const STATUS: Record<string, string> = {
  new: "text-sky-600 dark:text-sky-400", investigating: "text-violet-600 dark:text-violet-400", needs_review: "text-amber-600 dark:text-amber-400",
  confirmed: "text-red-600 dark:text-red-400", false_positive: "text-slate-500", remediation_pending: "text-orange-600 dark:text-orange-400",
  resolved: "text-emerald-600 dark:text-emerald-400", closed: "text-slate-500",
  healthy: "text-emerald-600 dark:text-emerald-400", degraded: "text-amber-600 dark:text-amber-400", error: "text-red-600 dark:text-red-400",
  pending: "text-amber-600 dark:text-amber-400", disconnected: "text-slate-500", succeeded: "text-emerald-600 dark:text-emerald-400",
  failed: "text-red-600 dark:text-red-400", rejected: "text-red-600 dark:text-red-400", running: "text-violet-600 dark:text-violet-400",
  queued: "text-sky-600 dark:text-sky-400", timeout: "text-red-600 dark:text-red-400", approved: "text-emerald-600 dark:text-emerald-400",
  open: "text-sky-600 dark:text-sky-400", suppressed: "text-slate-500", proposed: "text-sky-600 dark:text-sky-400",
  ok: "text-emerald-600 dark:text-emerald-400", down: "text-red-600 dark:text-red-400", stale: "text-amber-600 dark:text-amber-400",
  unknown: "text-slate-500", lagging: "text-amber-600 dark:text-amber-400", failing: "text-red-600 dark:text-red-400",
  never_run: "text-slate-500", disabled: "text-slate-500",
};
export function Status({ value }: { value?: string | null }) {
  if (!value) return <span className="text-muted">—</span>;
  return <span className={cn("inline-flex items-center gap-1.5 text-xs font-medium", STATUS[value] ?? "text-muted")}><span className="size-1.5 rounded-full bg-current" />{value.replace(/_/g, " ")}</span>;
}

const VERDICT: Record<string, string> = {
  confirmed: "bg-red-600 text-white", likely: "bg-orange-500 text-white", benign: "bg-emerald-600 text-white",
  inconclusive: "bg-slate-500 text-white", needs_more_data: "bg-sky-600 text-white",
};
export function Verdict({ value }: { value?: string | null }) {
  if (!value) return <span className="text-xs text-muted">no verdict</span>;
  return <span className={cn("rounded px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide", VERDICT[value] ?? "bg-slate-500 text-white")}>{value.replace(/_/g, " ")}</span>;
}

export function Tag({ children, className }: { children: React.ReactNode; className?: string }) {
  return <span className={cn("inline-flex max-w-full items-center whitespace-nowrap rounded border border-border bg-panel-2 px-1.5 py-0.5 text-[11px] text-muted", className)}>{children}</span>;
}

export function Stat({ label, value, sub, icon: Icon, tone }: { label: string; value: React.ReactNode; sub?: React.ReactNode; icon?: React.ElementType; tone?: "red" | "amber" | "green" }) {
  return (
    <div className="rounded-lg border border-border bg-panel p-3.5">
      <div className="flex items-center justify-between text-xs text-muted">{label}{Icon && <Icon className="size-4 opacity-60" />}</div>
      <div className={cn("mt-1.5 text-2xl font-semibold tabular-nums tracking-tight", tone === "red" && "text-red-600 dark:text-red-400", tone === "amber" && "text-amber-600 dark:text-amber-400", tone === "green" && "text-emerald-600 dark:text-emerald-400")}>{value}</div>
      {sub && <div className="mt-0.5 text-xs text-muted">{sub}</div>}
    </div>
  );
}

export function Table({ head, children, empty }: { head: React.ReactNode[]; children: React.ReactNode; empty?: React.ReactNode }) {
  const rows = React.Children.count(children);
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-[13px]">
        <thead><tr className="border-b border-border text-left text-[11px] uppercase tracking-wide text-muted">{head.map((h, i) => <th key={i} className="px-3 py-2 font-medium">{h}</th>)}</tr></thead>
        <tbody className="divide-y divide-border">{children}</tbody>
      </table>
      {rows === 0 && <div className="p-8 text-center text-sm text-muted">{empty ?? "Nothing here yet."}</div>}
    </div>
  );
}
export const Td = ({ children, className, ...p }: React.TdHTMLAttributes<HTMLTableCellElement>) => <td {...p} className={cn("px-3 py-2 align-top", className)}>{children}</td>;

export function PageHeader({ title, description, actions }: { title: string; description?: string; actions?: React.ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div><h1 className="text-xl font-semibold tracking-tight">{title}</h1>{description && <p className="mt-0.5 text-[13px] text-muted">{description}</p>}</div>
      <div className="flex items-center gap-2">{actions}</div>
    </div>
  );
}

export function Loading() { return <div className="flex items-center gap-2 p-6 text-sm text-muted"><Loader2 className="size-4 animate-spin" />Loading…</div>; }
export function ErrorBox({ error }: { error: unknown }) {
  if (!error) return null;
  return <div className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-[13px] text-red-700 dark:text-red-300">{(error as Error).message}</div>;
}

export function Json({ value, className }: { value: unknown; className?: string }) {
  return <pre className={cn("mono max-h-[480px] overflow-auto rounded-md border border-border bg-panel-2 p-3 text-[11.5px] leading-relaxed", className)}>{JSON.stringify(value, null, 2)}</pre>;
}

export function Drawer({ open, onClose, title, children }: { open: boolean; onClose: () => void; title: React.ReactNode; children: React.ReactNode }) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-black/30" onClick={onClose}>
      <aside className="h-full w-full max-w-3xl overflow-y-auto border-l border-border bg-bg shadow-xl" onClick={(e) => e.stopPropagation()}>
        <header className="sticky top-0 z-10 flex items-center justify-between border-b border-border bg-panel px-4 py-3">
          <h2 className="text-sm font-semibold">{title}</h2>
          <Button size="sm" variant="ghost" onClick={onClose}>Close</Button>
        </header>
        <div className="space-y-4 p-4">{children}</div>
      </aside>
    </div>
  );
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: Array<{ id: T; label: React.ReactNode }>; value: T; onChange: (v: T) => void }) {
  return (
    <div className="flex gap-1 border-b border-border">
      {tabs.map((t) => (
        <button key={t.id} onClick={() => onChange(t.id)} className={cn("-mb-px border-b-2 px-3 py-2 text-[13px] font-medium", value === t.id ? "border-accent text-fg" : "border-transparent text-muted hover:text-fg")}>{t.label}</button>
      ))}
    </div>
  );
}
