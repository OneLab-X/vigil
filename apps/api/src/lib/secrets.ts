import fs from "node:fs/promises";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { and, eq } from "drizzle-orm";
import { vigilSecrets, withTenant } from "@vigil/db";
import { env } from "../env.js";
import { getDb } from "../db.js";
import { decrypt, encrypt } from "./crypto.js";

/**
 * Secret store abstraction. Rows elsewhere only ever hold a `secretRef`; values are AES-256-GCM
 * encrypted with VIGIL_SECRET_KEY. External secret managers (Vault, GCP/AWS Secret Manager) plug in
 * behind this interface (roadmap).
 */
export interface SecretStore {
  put(tenantId: string, value: string): Promise<string>;
  get(tenantId: string, ref: string): Promise<string>;
  delete(tenantId: string, ref: string): Promise<void>;
}

/** Default store: ciphertext in Postgres (`vigil_secrets`, tenant RLS). One backup covers it; every container can read it. */
export class DbEncryptedSecretStore implements SecretStore {
  async put(tenantId: string, value: string) {
    const ref = `db:${tenantId}:${randomUUID()}`;
    await withTenant(getDb(), { tenantId }, (tx) => tx.insert(vigilSecrets).values({ tenantId, ref, ciphertext: encrypt(value) }));
    return ref;
  }
  async get(tenantId: string, ref: string) {
    const [row] = await withTenant(getDb(), { tenantId }, (tx) => tx.select().from(vigilSecrets).where(and(eq(vigilSecrets.ref, ref), eq(vigilSecrets.tenantId, tenantId))));
    if (!row) throw new Error("secret not found");
    return decrypt(row.ciphertext);
  }
  async delete(tenantId: string, ref: string) {
    await withTenant(getDb(), { tenantId }, (tx) => tx.delete(vigilSecrets).where(and(eq(vigilSecrets.ref, ref), eq(vigilSecrets.tenantId, tenantId))));
  }
}

/** Legacy dev store (encrypted JSON file under the data dir). Read/delete only for refs created before 0004. */
export class LocalEncryptedSecretStore implements SecretStore {
  private file = path.join(env.dataDir, "secrets.enc.json");
  private async load(): Promise<Record<string, string>> {
    try { return JSON.parse(await fs.readFile(this.file, "utf8")); } catch { return {}; }
  }
  private async save(d: Record<string, string>) {
    await fs.mkdir(path.dirname(this.file), { recursive: true });
    await fs.writeFile(this.file, JSON.stringify(d), { mode: 0o600 });
  }
  async put(tenantId: string, value: string) {
    const d = await this.load();
    const ref = `local:${tenantId}:${randomUUID()}`;
    d[ref] = encrypt(value);
    await this.save(d);
    return ref;
  }
  async get(tenantId: string, ref: string) {
    const v = (await this.load())[ref];
    if (!v) throw new Error("secret not found");
    return decrypt(v);
  }
  async delete(_tenantId: string, ref: string) {
    const d = await this.load();
    delete d[ref];
    await this.save(d);
  }
}

class RoutingSecretStore implements SecretStore {
  constructor(private dbStore = new DbEncryptedSecretStore(), private local = new LocalEncryptedSecretStore()) {}
  private pick(tenantId: string, ref: string): SecretStore {
    const [kind, owner] = ref.split(":");
    if (owner !== tenantId) throw new Error("secret ref does not belong to tenant");
    if (kind === "db") return this.dbStore;
    if (kind === "local") return this.local;
    throw new Error("unknown secret ref kind");
  }
  put(tenantId: string, value: string) { return this.dbStore.put(tenantId, value); }
  get(tenantId: string, ref: string) { return this.pick(tenantId, ref).get(tenantId, ref); }
  delete(tenantId: string, ref: string) { return this.pick(tenantId, ref).delete(tenantId, ref); }
}

export const secretStore: SecretStore = new RoutingSecretStore();
