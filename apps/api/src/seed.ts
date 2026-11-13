/**
 * Dev bootstrap: creates a tenant, three users (owner/analyst/viewer) and seed detection content.
 * Generated passwords are written to .local/dev-credentials.json (git-ignored) — never printed.
 */
import fs from "node:fs/promises";
import path from "node:path";
import { eq } from "drizzle-orm";
import { tenants, withUser } from "@vigil/db";
import { getDb, closeDb } from "./db.js";
import { env } from "./env.js";
import { randomToken } from "./lib/crypto.js";
import { addMember, createTenant, upsertUser } from "./services/tenancy.js";

if (env.nodeEnv === "production") {
  console.error("refusing to seed demo users in production; use `vigil-admin create-owner` instead");
  process.exit(1);
}
const db = getDb();
const credsFile = path.join(env.dataDir, "dev-credentials.json");
let creds: Record<string, string> = {};
try { creds = JSON.parse(await fs.readFile(credsFile, "utf8")); } catch { /* first run */ }
const pw = (k: string) => (creds[k] ??= randomToken(15));

const owner = await upsertUser(db, "owner@vigil.test", "Olivia Owner", pw("owner@vigil.test"));
const analyst = await upsertUser(db, "analyst@vigil.test", "Arjun Analyst", pw("analyst@vigil.test"));
const analyst2 = await upsertUser(db, "reviewer@vigil.test", "Riya Reviewer", pw("reviewer@vigil.test"));
const viewer = await upsertUser(db, "viewer@vigil.test", "Vik Viewer", pw("viewer@vigil.test"));

// tenants is RLS-protected; look it up through the owner's memberships
const found = await withUser(db, owner, (tx) => tx.select().from(tenants).where(eq(tenants.slug, "example")));
let tenantId = found[0]?.id;
if (!tenantId) tenantId = await createTenant(db, "Example Security", "example", owner);
await addMember(db, tenantId, analyst, "analyst");
await addMember(db, tenantId, analyst2, "analyst");
await addMember(db, tenantId, viewer, "viewer");

await fs.mkdir(env.dataDir, { recursive: true });
await fs.writeFile(credsFile, JSON.stringify(creds, null, 2), { mode: 0o600 });
console.log(`seeded tenant example (${tenantId}); dev credentials written to ${credsFile}`);
await closeDb();
