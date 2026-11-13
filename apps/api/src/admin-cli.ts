/**
 * vigil-admin — operator CLI for self-hosted installs (run inside the api container).
 *   create-owner --email E --name N --org O [--slug S]   first administrator + organization
 *   add-member --email E --name N --role R [--org SLUG]  add someone to an organization (R: owner|admin|analyst|viewer)
 *   reset-password --email E                             issue a new one-time password
 *   verify-audit                                         verify every tenant's audit hash chain
 *   verify-evidence [--sample N]                         re-hash a random sample of stored raw evidence
 *   init-storage                                         create the S3 evidence bucket (versioned)
 *   status                                               counts for post-restore checks
 * One-time passwords are printed once to this terminal and must be changed at first sign-in.
 */
import { asc, eq, sql } from "drizzle-orm";
import { auditLogs, rawEventReferences, tenants, users, withTenant } from "@vigil/db";
import { closeDb, getDb } from "./db.js";
import { hashPassword, randomToken } from "./lib/crypto.js";
import { verifyChain } from "./lib/audit.js";
import { audit } from "./lib/audit.js";
import { createTenant, inviteMember } from "./services/tenancy.js";
import type { Role } from "./lib/rbac.js";
import { blobStore } from "./lib/blobstore.js";

const [cmd, ...rest] = process.argv.slice(2);
const args: Record<string, string> = {};
for (let i = 0; i < rest.length; i += 2) if (rest[i]?.startsWith("--")) args[rest[i]!.slice(2)] = rest[i + 1] ?? "";
const need = (k: string) => { const v = args[k]?.trim(); if (!v) { console.error(`missing --${k}`); process.exit(2); } return v; };
const db = getDb();

async function tenantIds(): Promise<string[]> {
  // vigil_app cannot list tenants across RLS; the SECURITY DEFINER helper exposes ids only.
  const r = await db.execute(sql`select vigil_tenant_ids() as id`) as unknown as Array<{ id: string }>;
  return r.map((x) => x.id);
}

try {
  if (cmd === "create-owner") {
    const email = need("email").toLowerCase(), name = need("name"), org = need("org");
    const slug = (args.slug ?? org).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 40) || "org";
    if (!/^[^@\s]+@[^@\s]+$/.test(email)) throw new Error("invalid email");
    const [existing] = await db.select({ id: users.id }).from(users).where(eq(users.email, email));
    if (existing) throw new Error("user already exists; use reset-password");
    const pw = randomToken(18);
    const [u] = await db.insert(users).values({ email, displayName: name, passwordHash: await hashPassword(pw), mustChangePassword: true }).returning({ id: users.id });
    const tenantId = await createTenant(db, org, slug, u!.id);
    console.log(`created organization "${org}" (${tenantId}) and owner ${email}`);
    console.log(`one-time password: ${pw}`);
    console.log("sign in and change it immediately; it is not stored anywhere in plain text.");
  } else if (cmd === "add-member") {
    const email = need("email").toLowerCase(), name = need("name"), role = need("role") as Role;
    if (!["owner", "admin", "analyst", "viewer"].includes(role)) throw new Error("--role must be owner, admin, analyst or viewer");
    const orgs: Array<{ id: string; slug: string; name: string }> = [];
    for (const id of await tenantIds()) {
      const [t] = await withTenant(db, { tenantId: id }, (tx) => tx.select({ id: tenants.id, slug: tenants.slug, name: tenants.name }).from(tenants).where(eq(tenants.id, id)));
      if (t) orgs.push(t);
    }
    const org = args.org ? orgs.find((o) => o.slug === args.org || o.id === args.org) : orgs.length === 1 ? orgs[0] : undefined;
    if (!org) throw new Error(args.org ? `no organization "${args.org}"` : `several organizations exist; pass --org with one of: ${orgs.map((o) => o.slug).join(", ") || "(none)"}`);
    const r = await withTenant(db, { tenantId: org.id }, async (tx) => {
      const res = await inviteMember(tx, org.id, { email, displayName: name, role });
      await audit(tx, { tenantId: org.id, actorType: "system", actorId: "vigil-admin", action: "member.added", targetType: "user", targetId: res.userId, details: { email, role, newAccount: res.created } });
      return res;
    });
    console.log(`added ${email} to "${org.name}" as ${role}`);
    if (r.oneTimePassword) {
      console.log("one-time password was generated for this user.");
      console.log("share it privately; they must change it at first sign-in. It is not stored anywhere in plain text.");
    } else console.log("existing account: they sign in with their current password and can switch to this organization.");
  } else if (cmd === "reset-password") {
    const email = need("email").toLowerCase();
    const pw = randomToken(18);
    const r = await db.update(users).set({ passwordHash: await hashPassword(pw), mustChangePassword: true }).where(eq(users.email, email)).returning({ id: users.id });
    if (!r.length) throw new Error("no such user");
    await db.execute(sql`delete from sessions where user_id = ${r[0]!.id}`);
    console.log(`one-time password for ${email}: ${pw}`);
  } else if (cmd === "verify-audit") {
    let bad = 0;
    for (const id of await tenantIds()) {
      const t = { id };
      const rows = await withTenant(db, { tenantId: t.id }, (tx) => tx.select().from(auditLogs).orderBy(asc(auditLogs.id)));
      const v = verifyChain(rows);
      console.log(`tenant ${t.id}: ${rows.length} entries, chain ${v.ok ? "OK" : `BROKEN at ${v.brokenAt}`}`);
      if (!v.ok) bad++;
    }
    if (bad) process.exitCode = 1;
  } else if (cmd === "verify-evidence") {
    // Re-reads a random sample of raw evidence objects; the store re-checks each sha256 on read.
    const sample = Math.max(1, Math.min(10_000, Number(args.sample ?? 200)));
    let checked = 0, failed = 0;
    for (const id of await tenantIds()) {
      const refs = await withTenant(db, { tenantId: id }, (tx) => tx.select({ uri: rawEventReferences.storageUri, sha: rawEventReferences.sha256 }).from(rawEventReferences).orderBy(sql`random()`).limit(sample));
      for (const r of refs) {
        checked++;
        try { await blobStore.get(r.uri); } catch (e) { failed++; console.error(`tenant ${id}: ${r.sha.slice(0, 12)}… ${(e as Error).message}`); }
      }
    }
    console.log(`evidence sample: ${checked} checked, ${failed} failed`);
    if (failed) process.exitCode = 1;
  } else if (cmd === "init-storage") {
    // Creates the evidence bucket (S3/MinIO) with versioning so overwritten/deleted objects stay recoverable.
    if ((process.env.VIGIL_BLOB_STORE ?? "local") !== "s3") { console.log("local evidence store; nothing to initialise"); }
    else {
      const { S3Client, HeadBucketCommand, CreateBucketCommand, PutBucketVersioningCommand } = await import("@aws-sdk/client-s3");
      const Bucket = process.env.VIGIL_S3_BUCKET!;
      const s3 = new S3Client({ region: process.env.VIGIL_S3_REGION ?? "us-east-1", endpoint: process.env.VIGIL_S3_ENDPOINT || undefined, forcePathStyle: process.env.VIGIL_S3_FORCE_PATH_STYLE !== "0" });
      let exists = true;
      try { await s3.send(new HeadBucketCommand({ Bucket })); } catch { exists = false; }
      if (!exists) { await s3.send(new CreateBucketCommand({ Bucket })); console.log(`created bucket ${Bucket}`); }
      await s3.send(new PutBucketVersioningCommand({ Bucket, VersioningConfiguration: { Status: "Enabled" } }));
      console.log(`evidence bucket ${Bucket} ready (versioning enabled)`);
    }
  } else if (cmd === "status") {
    const r = await db.execute(sql`select (select count(*) from users)::int as users`) as unknown as Array<{ users: number }>;
    console.log(JSON.stringify({ users: r[0]?.users }));
  } else {
    console.error("usage: vigil-admin create-owner --email E --name N --org O [--slug S] | add-member --email E --name N --role R [--org SLUG] | reset-password --email E | verify-audit | verify-evidence [--sample N] | init-storage | status");
    process.exitCode = 2;
  }
} catch (e) {
  console.error(`error: ${(e as Error).message}`);
  process.exitCode = 1;
} finally {
  await closeDb();
}
