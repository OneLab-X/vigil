import net from "node:net";

/**
 * Reversible, per-run pseudonymization of sensitive values before anything reaches an AI model.
 *
 * The model sees consistent tokens such as `[[IP_3:public]]`, `[[SVC_1:gcp]]`, `[[ACCOUNT_1:gcp]]` instead of real
 * IPs, emails, identities, account ids and resource names. The token map stays in the control plane (encrypted per
 * run); tool arguments and the final result are unmasked before use, so queries, grounding checks and stored verdicts
 * all work on real values. Hints after the colon are non-identifying (IP scope, identity kind, cloud).
 *
 * Best effort: detection is field-based plus pattern-based. It is not a DLP guarantee.
 */
export type MaskKind = "IP" | "EMAIL" | "USER" | "SVC" | "ROLE" | "ACCOUNT" | "RESOURCE";

export interface MaskState {
  v: 1;
  counters: Partial<Record<MaskKind, number>>;
  /** real value -> token core (e.g. "IP_3") */
  byValue: Record<string, string>;
  /** token core -> { real value, hint } */
  byToken: Record<string, { value: string; hint?: string }>;
}

export type MaskStats = Partial<Record<MaskKind, number>>;

const TOKEN_RE = /\[\[([A-Z]+_\d+)(?::[a-z0-9_-]*)?\]\]/g;
const IS_TOKEN = /^\[\[[A-Z]+_\d+(?::[a-z0-9_-]*)?\]\]$/;
const SPLIT_TOKENS = /(\[\[[A-Z]+_\d+(?::[a-z0-9_-]*)?\]\])/;

/** Field names (snake_case agent views and camelCase group keys) whose whole value is sensitive. */
const FIELD_KIND: Record<string, "ip" | "principal" | "account" | "resource"> = {
  source_ip: "ip", destination_ip: "ip", sourceIp: "ip", destinationIp: "ip", ip: "ip",
  principal: "principal", principal_email: "principal", principalEmail: "principal",
  account: "account", projectOrAccountReference: "account", project_id: "account", projectId: "account", account_id: "account",
  resource_id: "resource", resourceId: "resource",
};

const ARN_RE = /\barn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[^\s"',;)\]]+/g;
const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b/g;
// IPv4 not embedded in version strings like Chrome/120.0.0.0 or 1.2.3.4.5
const IPV4_RE = /(?<![\w/.])(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?![\w.])/g;
const IPV6_CANDIDATE_RE = /(?<![\w:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![\w:])/g;
const GCP_PROJECT_PATH_RE = /\bprojects\/([a-z][a-z0-9-]{4,28}[a-z0-9]|\d{6,20})(?=\/|\b)/g;
const AZURE_SUB_PATH_RE = /\/subscriptions\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=\/|\b)/gi;

export function ipScope(ip: string): string {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number) as [number, number];
    if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127)) return "private";
    if (a === 127) return "loopback";
    if (a === 169 && b === 254) return "link_local";
    if (a === 0 || a >= 224) return "reserved";
    if ((a === 192 && b === 0) || (a === 198 && (b === 18 || b === 19 || b === 51)) || (a === 203 && b === 0)) return "reserved"; // test/benchmark nets
    return "public";
  }
  const v = ip.toLowerCase();
  if (v === "::1") return "loopback";
  if (v.startsWith("fe8") || v.startsWith("fe9") || v.startsWith("fea") || v.startsWith("feb")) return "link_local";
  if (v.startsWith("fc") || v.startsWith("fd")) return "private";
  if (v.startsWith("2001:db8")) return "reserved";
  return "public";
}

function classifyPrincipal(v: string): { kind: MaskKind; hint?: string } {
  const s = v.toLowerCase();
  if (s.startsWith("arn:aws")) {
    if (/:(role|assumed-role)\//.test(s)) return { kind: "ROLE", hint: "aws" };
    if (/:user\//.test(s)) return { kind: "USER", hint: "aws" };
    if (/:root$/.test(s)) return { kind: "USER", hint: "aws_root" };
    return { kind: "RESOURCE", hint: "aws" };
  }
  if (s.endsWith(".gserviceaccount.com")) return { kind: "SVC", hint: "gcp" };
  if (s.includes("@")) return { kind: "EMAIL" };
  return { kind: "USER" };
}

const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function accountHint(v: string) { return /^\d{12}$/.test(v) ? "aws" : GUID_RE.test(v) ? "azure" : "gcp"; }

export class Masker {
  private s: MaskState;
  private dict: Array<[string, string]> | null = null;

  constructor(state?: MaskState | null) {
    this.s = state ?? { v: 1, counters: {}, byValue: {}, byToken: {} };
  }

  state(): MaskState { return this.s; }
  stats(): MaskStats { return { ...this.s.counters }; }

  /** Pre-register values that should be masked wherever they appear in free text (e.g. the tenant's project ids). */
  seed(values: Array<{ kind: MaskKind; value: string; hint?: string }>) {
    for (const x of values) if (x.value && x.value.length >= 3) this.token(x.kind, x.value, x.hint);
  }

  private token(kind: MaskKind, value: string, hint?: string): string {
    let core = this.s.byValue[value];
    if (!core) {
      const n = (this.s.counters[kind] ?? 0) + 1;
      this.s.counters[kind] = n;
      core = `${kind}_${n}`;
      this.s.byValue[value] = core;
      this.s.byToken[core] = hint ? { value, hint } : { value };
      this.dict = null;
    }
    const h = this.s.byToken[core]!.hint;
    return h ? `[[${core}:${h}]]` : `[[${core}]]`;
  }

  private fieldToken(kind: "ip" | "principal" | "account" | "resource", v: string): string {
    if (!v || IS_TOKEN.test(v)) return v;
    if (kind === "ip") return net.isIP(v) ? this.token("IP", v, ipScope(v)) : this.maskText(v);
    if (kind === "principal") { const c = classifyPrincipal(v); return this.token(c.kind, v, c.hint); }
    if (kind === "account") return this.token("ACCOUNT", v, accountHint(v));
    return this.token("RESOURCE", v);
  }

  /** Replace sensitive substrings in free text. */
  maskText(text: string): string {
    if (!text) return text;
    let out = text;
    // 1) everything already known this run (longest first so "x@p.iam.gserviceaccount.com" wins over "p")
    if (!this.dict) this.dict = Object.entries(this.s.byValue).filter(([v]) => v.length >= 3).sort((a, b) => b[0].length - a[0].length);
    for (const [value, core] of this.dict) {
      if (!out.includes(value)) continue;
      const h = this.s.byToken[core]!.hint;
      const tok = h ? `[[${core}:${h}]]` : `[[${core}]]`;
      // replace only outside existing tokens (a short value like "gcp" must not rewrite "[[SVC_1:gcp]]")
      out = out.split(SPLIT_TOKENS).map((part) => (IS_TOKEN.test(part) ? part : part.split(value).join(tok))).join("");
    }
    // 2) detectors for values not seen before
    out = out.replace(ARN_RE, (m) => { const c = classifyPrincipal(m); return this.token(c.kind, m, c.hint); });
    out = out.replace(EMAIL_RE, (m) => { const c = classifyPrincipal(m); return this.token(c.kind, m, c.hint); });
    out = out.replace(GCP_PROJECT_PATH_RE, (_m, id: string) => `projects/${this.token("ACCOUNT", id, "gcp")}`);
    out = out.replace(AZURE_SUB_PATH_RE, (_m, id: string) => `/subscriptions/${this.token("ACCOUNT", id.toLowerCase(), "azure")}`);
    out = out.replace(IPV4_RE, (m) => this.token("IP", m, ipScope(m)));
    out = out.replace(IPV6_CANDIDATE_RE, (m) => (m.length >= 3 && net.isIPv6(m) ? this.token("IP", m, ipScope(m)) : m));
    return out;
  }

  /** Deep-mask a JSON-like value (object keys are never changed). */
  mask<T>(value: T): T { return this.walk(value, undefined, 0) as T; }

  private walk(value: unknown, key: string | undefined, depth: number): unknown {
    if (depth > 16) return value;
    if (typeof value === "string") {
      const fk = key ? FIELD_KIND[key] : undefined;
      return fk ? this.fieldToken(fk, value) : this.maskText(value);
    }
    if (Array.isArray(value)) return value.map((v) => this.walk(v, key, depth + 1));
    if (value && typeof value === "object") {
      const o = value as Record<string, unknown>;
      // { field: "sourceIp", value: "1.2.3.4" } (incident primary entity)
      if (typeof o.field === "string" && typeof o.value === "string" && FIELD_KIND[o.field]) {
        return { ...o, value: this.fieldToken(FIELD_KIND[o.field]!, o.value) };
      }
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(o)) out[k] = this.walk(v, k, depth + 1);
      return out;
    }
    return value;
  }

  /** Restore real values. Unknown tokens (never issued in this run) are reported and left in place. */
  unmask<T>(value: T): { value: T; unknownTokens: string[] } {
    const unknown = new Set<string>();
    const fix = (s: string) => s.replace(TOKEN_RE, (m, core: string) => {
      const t = this.s.byToken[core];
      if (!t) { unknown.add(m); return m; }
      return t.value;
    });
    const walk = (v: unknown, d: number): unknown => {
      if (d > 16) return v;
      if (typeof v === "string") return fix(v);
      if (Array.isArray(v)) return v.map((x) => walk(x, d + 1));
      if (v && typeof v === "object") return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, walk(x, d + 1)]));
      return v;
    };
    return { value: walk(value, 0) as T, unknownTokens: [...unknown] };
  }
}

export function maskStatsLabel(s: MaskStats): string {
  const names: Record<MaskKind, string> = { IP: "IPs", EMAIL: "emails", USER: "users", SVC: "service accounts", ROLE: "roles", ACCOUNT: "accounts", RESOURCE: "resources" };
  return (Object.entries(s) as Array<[MaskKind, number]>).filter(([, n]) => n > 0).map(([k, n]) => `${n} ${names[k]}`).join(" · ");
}
