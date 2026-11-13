"use client";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import * as React from "react";
import {
  LayoutDashboard, ShieldAlert, Search, Cloud, ListChecks, Bot, BookOpen, ShieldCheck, Gauge, ScrollText, Settings, Moon, Sun, LogOut, Radar, Activity,
} from "lucide-react";
import { api, setCsrf, useApi } from "@/lib/api";
import { cn } from "@/lib/utils";
import { Button, Card, Input, Label } from "@/components/ui";

const NAV: Array<{ href: string; label: string; icon: React.ElementType; perm?: string }> = [
  { href: "/", label: "Overview", icon: LayoutDashboard },
  { href: "/incidents", label: "Incidents", icon: ShieldAlert },
  { href: "/events", label: "Event Explorer", icon: Search },
  { href: "/connections", label: "Connections", icon: Cloud },
  { href: "/rules", label: "Detection Rules", icon: ListChecks },
  { href: "/investigations", label: "AI Investigations", icon: Bot },
  { href: "/knowledge", label: "Security Knowledge", icon: BookOpen },
  { href: "/governance", label: "Agent Governance", icon: ShieldCheck },
  { href: "/evaluation", label: "Evaluation & Performance", icon: Gauge },
  { href: "/audit", label: "Audit Logs", icon: ScrollText },
  { href: "/operations", label: "Operations", icon: Activity, perm: "operations:read" },
  { href: "/settings", label: "Settings", icon: Settings },
];

export const MeContext = React.createContext<any>(null);
export const useMe = () => React.useContext(MeContext);
export const useCan = () => { const me = useMe(); return (p: string) => !!me?.permissions?.includes(p); };

function ThemeToggle() {
  const [dark, setDark] = React.useState(false);
  React.useEffect(() => setDark(document.documentElement.classList.contains("dark")), []);
  const toggle = () => {
    const next = !dark;
    setDark(next);
    document.documentElement.classList.toggle("dark", next);
    try { localStorage.setItem("vigil-theme", next ? "dark" : "light"); } catch { /* storage unavailable */ }
  };
  return <button onClick={toggle} aria-label="Toggle theme" className="rounded-md p-1.5 text-muted hover:bg-panel-2 hover:text-fg">{dark ? <Sun className="size-4" /> : <Moon className="size-4" />}</button>;
}

function ChangePassword() {
  const [cur, setCur] = React.useState("");
  const [next, setNext] = React.useState("");
  const [again, setAgain] = React.useState("");
  const [err, setErr] = React.useState<string | null>(null);
  const [busy, setBusy] = React.useState(false);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr(null);
    if (next.length < 12) return setErr("Use at least 12 characters.");
    if (next !== again) return setErr("The new passwords don't match.");
    setBusy(true);
    try { await api("/auth/change-password", { method: "POST", body: { currentPassword: cur, newPassword: next } }); window.location.href = "/"; }
    catch (x) { setErr((x as Error).message); setBusy(false); }
  };
  return (
    <div className="grid min-h-screen place-items-center px-4">
      <Card title="Set your password" className="w-full max-w-sm">
        <p className="mb-3 text-[13px] text-muted">You signed in with a one-time password. Choose a new one to continue.</p>
        <form className="space-y-3" onSubmit={submit}>
          <div><Label>One-time password</Label><Input className="w-full" type="password" autoComplete="current-password" value={cur} onChange={(e) => setCur(e.target.value)} /></div>
          <div><Label>New password (12+ characters)</Label><Input className="w-full" type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} /></div>
          <div><Label>Repeat new password</Label><Input className="w-full" type="password" autoComplete="new-password" value={again} onChange={(e) => setAgain(e.target.value)} /></div>
          {err && <p className="text-[13px] text-red-600" role="alert">{err}</p>}
          <Button variant="primary" className="w-full" disabled={busy}>{busy ? "Saving…" : "Save password"}</Button>
        </form>
      </Card>
    </div>
  );
}

export function Shell({ children }: { children: React.ReactNode }) {
  const path = usePathname();
  const router = useRouter();
  const me = useApi(["me"], path === "/login" ? null : "/auth/me");
  React.useEffect(() => { if (me.data?.csrf) setCsrf(me.data.csrf); }, [me.data]);
  if (path === "/login") return <>{children}</>;
  if (me.data?.user?.mustChangePassword) return <ChangePassword />;
  const tenant = me.data?.tenants?.find((t: any) => t.id === me.data?.activeTenantId);
  // Items gated by a permission stay hidden until /auth/me confirms it (mirrors the API's RBAC).
  const nav = NAV.filter((n) => !n.perm || !!me.data?.permissions?.includes(n.perm));
  return (
    <MeContext.Provider value={me.data}>
      <div className="flex min-h-screen">
        <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-border bg-panel md:flex">
          <div className="flex items-center gap-2 px-4 py-4">
            <div className="grid size-7 place-items-center rounded-md bg-accent text-accent-fg"><Radar className="size-4" /></div>
            <div><div className="text-sm font-semibold leading-none">Vigil</div><div className="text-[11px] text-muted">Agentic SOC</div></div>
          </div>
          <nav className="flex-1 space-y-0.5 overflow-y-auto px-2">
            {nav.map(({ href, label, icon: Icon }) => {
              const active = href === "/" ? path === "/" : path.startsWith(href);
              return (
                <Link key={href} href={href} className={cn("flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-[13px]", active ? "bg-panel-2 font-medium text-fg" : "text-muted hover:bg-panel-2 hover:text-fg")}>
                  <Icon className="size-4" />{label}
                </Link>
              );
            })}
          </nav>
          <div className="border-t border-border p-3 text-xs">
            <div className="truncate font-medium">{me.data?.user?.displayName ?? "…"}</div>
            <div className="truncate text-muted">{tenant?.name ?? ""} · {me.data?.role ?? ""}</div>
          </div>
        </aside>
        <div className="flex min-w-0 flex-1 flex-col">
          <header className="sticky top-0 z-20 flex h-12 items-center justify-between gap-3 border-b border-border bg-panel/90 px-4 backdrop-blur">
            <div className="flex min-w-0 items-center gap-1 overflow-x-auto md:hidden">
              {nav.map(({ href, icon: Icon, label }) => <Link key={href} href={href} aria-label={label} className="rounded-md p-1.5 text-muted hover:bg-panel-2"><Icon className="size-4" /></Link>)}
            </div>
            <div className="hidden text-xs text-muted md:block">Read-only cloud access · Human approval required for every action</div>
            <div className="flex items-center gap-1">
              <ThemeToggle />
              <button aria-label="Sign out" className="rounded-md p-1.5 text-muted hover:bg-panel-2 hover:text-fg" onClick={async () => { await api("/auth/logout", { method: "POST" }).catch(() => {}); router.push("/login"); }}><LogOut className="size-4" /></button>
            </div>
          </header>
          <main className="mx-auto w-full max-w-[1400px] flex-1 px-4 py-5 md:px-6">{children}</main>
        </div>
      </div>
    </MeContext.Provider>
  );
}
