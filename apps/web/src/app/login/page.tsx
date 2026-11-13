"use client";
import { useRouter } from "next/navigation";
import * as React from "react";
import { Radar } from "lucide-react";
import { api, setCsrf } from "@/lib/api";
import { Button, ErrorBox, Input, Label } from "@/components/ui";

export default function Login() {
  const router = useRouter();
  const [email, setEmail] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [err, setErr] = React.useState<unknown>(null);
  const [busy, setBusy] = React.useState(false);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault(); setBusy(true); setErr(null);
    try { const r = await api("/auth/login", { method: "POST", body: { email, password } }); setCsrf(r.csrf); router.push("/"); router.refresh(); }
    catch (e) { setErr(e); } finally { setBusy(false); }
  };
  return (
    <div className="grid min-h-screen place-items-center px-4">
      <form onSubmit={submit} className="w-full max-w-sm space-y-4 rounded-xl border border-border bg-panel p-6">
        <div className="flex items-center gap-2"><div className="grid size-8 place-items-center rounded-md bg-accent text-accent-fg"><Radar className="size-4" /></div><div><div className="font-semibold">Vigil</div><div className="text-xs text-muted">Agentic security operations</div></div></div>
        <div><Label>Email</Label><Input type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} required /></div>
        <div><Label>Password</Label><Input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required /></div>
        <ErrorBox error={err} />
        <Button variant="primary" className="w-full" loading={busy}>Sign in</Button>
      </form>
    </div>
  );
}
