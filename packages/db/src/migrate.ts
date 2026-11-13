import { migrate } from "drizzle-orm/postgres-js/migrator";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { createDb } from "./client.js";

const url = process.env.VIGIL_OWNER_DATABASE_URL ?? "postgres://vigil_owner:vigil_owner_dev@127.0.0.1:54329/vigil";
const { db, close } = createDb(url, { max: 1 });
const folder = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "migrations");
await migrate(db, { migrationsFolder: folder });
console.log(`migrations applied to ${url.replace(/:[^:@/]+@/, ":***@")}`);
await close();
