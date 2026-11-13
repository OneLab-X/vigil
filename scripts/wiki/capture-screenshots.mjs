// Capture the wiki screenshots (docs/wiki/images) from a DEMO stack — synthetic data only, never a real database.
// usage: CHROME=/path/to/chromium node scripts/wiki/capture-screenshots.mjs <baseUrl> <demo-credentials.json> <outDir>
// Needs `playwright-core` installed next to this file (outside the pnpm workspace) and any local Chromium-based browser. See docs/wiki/Maintaining-this-Wiki.md.
import fs from "node:fs";
import { chromium } from "playwright-core";

const [base, credsFile, out] = process.argv.slice(2);
const creds = JSON.parse(fs.readFileSync(credsFile, "utf8"));
fs.mkdirSync(out, { recursive: true });
const browser = await chromium.launch({ executablePath: process.env.CHROME ?? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", headless: true });
const HIDE = "nextjs-portal, [data-nextjs-toast], [data-next-badge-root] { display: none !important; }";

async function context(scheme = "light") {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2, colorScheme: scheme });
  await ctx.addInitScript((css) => { addEventListener("DOMContentLoaded", () => { const s = document.createElement("style"); s.textContent = css; document.head.append(s); }); }, HIDE);
  return ctx;
}
async function settle(page) { await page.waitForLoadState("networkidle").catch(() => {}); await page.waitForTimeout(900); }
async function shot(page, name, { full = true, clip } = {}) {
  await settle(page);
  await page.screenshot({ path: `${out}/${name}.png`, fullPage: full && !clip, clip });
  console.log("saved", name);
}
async function login(ctx, email) {
  const page = await ctx.newPage();
  await page.goto(`${base}/login`); await settle(page);
  const r = await page.evaluate(async ([e, p]) => (await fetch("/api/v1/auth/login", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: e, password: p }) })).status, [email, creds[email]]);
  if (r !== 200) throw new Error(`login ${email} -> ${r}`);
  return page;
}
const clickText = async (page, text) => { await page.getByText(text, { exact: false }).first().click(); await settle(page); };

// ---- logged out ----
{ const ctx = await context(); const p = await ctx.newPage(); await p.goto(`${base}/login`); await shot(p, "01-login", { full: false }); await ctx.close(); }

// ---- owner, light ----
const ctx = await context();
const page = await login(ctx, "owner@example.com");
const go = async (path, name, opts) => { await page.goto(`${base}${path}`); await shot(page, name, opts); };

await go("/", "02-overview");
await go("/incidents", "03-incidents");
const incidents = await page.evaluate(async () => (await (await fetch("/api/v1/incidents?limit=100")).json()).items);
const brute = incidents.find((i) => i.correlationKey.startsWith("sourceIp:198.51.100.77"));
await go(`/incidents/${brute.id}`, "04-incident-detail");
for (const [label, name] of [["Supporting events", "05-incident-events"], ["AI reasoning trace", "06-incident-ai-trace"], ["Audit history", "07-incident-audit"]]) {
  await clickText(page, label); await shot(page, name);
}
await go("/events", "08-event-explorer");
await page.locator("tbody tr.cursor-pointer").first().click(); await shot(page, "09-event-drawer", { full: false });
await go("/connections", "10-connections");
await clickText(page, "Add connection"); await shot(page, "11-add-connection");
await go("/rules", "12-detection-rules");
await go("/investigations", "13-ai-investigations");
await go("/knowledge", "14-security-knowledge");
await go("/governance", "15-agent-governance");
await go("/evaluation", "16-evaluation");
await go("/audit", "17-audit-logs");
await go("/operations", "18-operations");
await go("/settings", "19-settings-general");
await go("/settings#ai-models", "20-settings-ai-models");
await clickText(page, "Add provider"); await shot(page, "21-settings-add-ai-provider");
await go("/settings#members", "22-settings-members");
await clickText(page, "Add member"); await shot(page, "23-settings-add-member");
await go("/settings#notifications", "24-settings-notifications");
await clickText(page, "Add Slack"); await shot(page, "25-settings-add-slack");
await clickText(page, "Cancel");
await clickText(page, "Add email"); await shot(page, "26-settings-add-email");
await ctx.close();

// ---- dark mode samples ----
const dctx = await context("dark");
const dpage = await login(dctx, "owner@example.com");
await dpage.evaluate(() => { document.documentElement.classList.add("dark"); localStorage.setItem("vigil-theme", "dark"); });
for (const [path, name] of [["/", "27-dark-overview"], [`/incidents/${brute.id}`, "28-dark-incident-detail"]]) {
  await dpage.goto(`${base}${path}`); await dpage.evaluate(() => document.documentElement.classList.add("dark")); await shot(dpage, name, { full: false });
}
await dctx.close();

// ---- viewer: what a read-only user sees ----
const vctx = await context();
const vpage = await login(vctx, "viewer@example.com");
await vpage.goto(`${base}/settings`); await shot(vpage, "29-viewer-settings", { full: false });
await vctx.close();

await browser.close();
