import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, scrypt as scryptCb, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { env } from "../env.js";

const scrypt = promisify(scryptCb) as (pw: string, salt: Buffer, len: number, opts: object) => Promise<Buffer>;
const SCRYPT = { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

export async function hashPassword(pw: string): Promise<string> {
  const salt = randomBytes(16);
  const key = await scrypt(pw, salt, 32, SCRYPT);
  return `scrypt$${SCRYPT.N}$${salt.toString("base64")}$${key.toString("base64")}`;
}

export async function verifyPassword(pw: string, stored: string | null): Promise<boolean> {
  // Always do the work, even for unknown users, to avoid a timing oracle.
  const [, n, saltB64, keyB64] = (stored ?? "scrypt$32768$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").split("$");
  const key = await scrypt(pw, Buffer.from(saltB64!, "base64"), 32, { ...SCRYPT, N: Number(n) });
  const expected = Buffer.from(keyB64!, "base64");
  return stored !== null && expected.length === key.length && timingSafeEqual(expected, key);
}

export const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");
export const randomToken = (bytes = 32) => randomBytes(bytes).toString("base64url");

const key = () => Buffer.from(env.secretKey, "hex");

export function encrypt(plain: string): string {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key(), iv);
  const ct = Buffer.concat([c.update(plain, "utf8"), c.final()]);
  return `v1.${iv.toString("base64url")}.${c.getAuthTag().toString("base64url")}.${ct.toString("base64url")}`;
}

export function decrypt(blob: string): string {
  const [v, iv, tag, ct] = blob.split(".");
  if (v !== "v1") throw new Error("unknown ciphertext version");
  const d = createDecipheriv("aes-256-gcm", key(), Buffer.from(iv!, "base64url"));
  d.setAuthTag(Buffer.from(tag!, "base64url"));
  return Buffer.concat([d.update(Buffer.from(ct!, "base64url")), d.final()]).toString("utf8");
}

/** Compact HMAC-signed token: base64url(json).base64url(hmac). */
export function signToken(payload: object): string {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const mac = createHmac("sha256", key()).update(`run-token.${body}`).digest("base64url");
  return `${body}.${mac}`;
}

export function verifyToken<T>(token: string): T | null {
  const [body, mac] = token.split(".");
  if (!body || !mac) return null;
  const expected = createHmac("sha256", key()).update(`run-token.${body}`).digest();
  const got = Buffer.from(mac, "base64url");
  if (got.length !== expected.length || !timingSafeEqual(got, expected)) return null;
  try { return JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as T; } catch { return null; }
}
