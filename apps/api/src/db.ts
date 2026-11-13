import { createDb, type Db } from "@vigil/db";
import { env } from "./env.js";

let instance: ReturnType<typeof createDb> | null = null;
export function getDb(): Db {
  if (!instance) instance = createDb(env.databaseUrl, { max: 20 });
  return instance.db;
}
export async function closeDb() { await instance?.close(); instance = null; }
export function setDbForTests(url: string) { instance = createDb(url, { max: 10 }); return instance.db; }
