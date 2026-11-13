import fs from "node:fs/promises";
import path from "node:path";
import { createHash } from "node:crypto";
import { GetObjectCommand, HeadBucketCommand, PutObjectCommand, S3Client, S3ServiceException } from "@aws-sdk/client-s3";
import { env } from "../env.js";

/**
 * Content-addressed, write-once raw evidence store. `local` writes to a directory (dev / single host);
 * `s3` writes to any S3-compatible store (MinIO in the Compose install, AWS S3, GCS interop, Ceph...).
 * Both refuse to overwrite and re-verify the sha256 on read so tampering is detected, not served.
 */
export interface BlobStore {
  putImmutable(tenantId: string, sha256: string, body: string): Promise<string>;
  get(uri: string): Promise<string>;
  /** readiness probe: can we reach the store? */
  check(): Promise<void>;
}

const sha = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");
function assertKey(tenantId: string, digest: string) {
  if (!/^[0-9a-f]{64}$/.test(digest) || !/^[0-9a-f-]{36}$/.test(tenantId)) throw new Error("bad blob key");
}
function verify(uri: string, body: string) {
  const m = /([0-9a-f]{64})\.json$/.exec(uri);
  if (m && sha(body) !== m[1]) throw new Error("evidence integrity check failed (sha256 mismatch)");
  return body;
}

export class LocalBlobStore implements BlobStore {
  constructor(private base = path.join(env.dataDir, "evidence")) {}
  async putImmutable(tenantId: string, digest: string, body: string) {
    assertKey(tenantId, digest);
    const p = path.join(this.base, tenantId, digest.slice(0, 2), `${digest}.json`);
    await fs.mkdir(path.dirname(p), { recursive: true });
    try {
      await fs.writeFile(p, body, { flag: "wx", mode: 0o440 }); // wx: never overwrite existing evidence
    } catch (e: any) {
      if (e.code !== "EEXIST") throw e;
    }
    return `file://${p}`;
  }
  async get(uri: string) {
    if (!uri.startsWith("file://")) throw new Error("unsupported uri");
    const p = path.resolve(uri.slice(7));
    if (!p.startsWith(path.resolve(this.base))) throw new Error("path escapes evidence store");
    return verify(uri, await fs.readFile(p, "utf8"));
  }
  async check() {
    await fs.mkdir(this.base, { recursive: true });
    await fs.access(this.base, fs.constants.W_OK);
  }
}

export class S3BlobStore implements BlobStore {
  private s3: S3Client;
  constructor(private bucket: string, opts: { endpoint?: string; region: string; forcePathStyle: boolean }) {
    // Credentials come from the standard AWS chain (env, web identity, instance role) — never from the DB.
    this.s3 = new S3Client({ region: opts.region, endpoint: opts.endpoint, forcePathStyle: opts.forcePathStyle });
  }
  private key(tenantId: string, digest: string) { return `evidence/${tenantId}/${digest.slice(0, 2)}/${digest}.json`; }
  async putImmutable(tenantId: string, digest: string, body: string) {
    assertKey(tenantId, digest);
    const Key = this.key(tenantId, digest);
    try {
      // If-None-Match: * — the store rejects the write if the object already exists (never overwrite evidence).
      await this.s3.send(new PutObjectCommand({ Bucket: this.bucket, Key, Body: body, ContentType: "application/json", IfNoneMatch: "*",
        ChecksumAlgorithm: "SHA256" }));
    } catch (e) {
      const status = e instanceof S3ServiceException ? e.$metadata.httpStatusCode : undefined;
      if (status !== 412 && status !== 409) throw e; // 412/409: already stored (content-addressed => identical)
    }
    return `s3://${this.bucket}/${Key}`;
  }
  async get(uri: string) {
    const prefix = `s3://${this.bucket}/`;
    if (!uri.startsWith(prefix)) throw new Error("unsupported uri");
    const Key = uri.slice(prefix.length);
    if (!/^evidence\/[0-9a-f-]{36}\/[0-9a-f]{2}\/[0-9a-f]{64}\.json$/.test(Key)) throw new Error("bad evidence key");
    const r = await this.s3.send(new GetObjectCommand({ Bucket: this.bucket, Key }));
    return verify(uri, await r.Body!.transformToString("utf8"));
  }
  async check() { await this.s3.send(new HeadBucketCommand({ Bucket: this.bucket })); }
}

function makeBlobStore(): BlobStore {
  if ((process.env.VIGIL_BLOB_STORE ?? "local") === "s3") {
    const bucket = process.env.VIGIL_S3_BUCKET;
    if (!bucket) throw new Error("VIGIL_S3_BUCKET is required when VIGIL_BLOB_STORE=s3");
    return new S3BlobStore(bucket, { endpoint: process.env.VIGIL_S3_ENDPOINT || undefined, region: process.env.VIGIL_S3_REGION ?? "us-east-1",
      forcePathStyle: process.env.VIGIL_S3_FORCE_PATH_STYLE !== "0" });
  }
  return new LocalBlobStore();
}

export const blobStore: BlobStore = makeBlobStore();
