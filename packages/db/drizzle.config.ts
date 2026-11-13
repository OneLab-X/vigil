import { defineConfig } from "drizzle-kit";
export default defineConfig({
  dialect: "postgresql",
  schema: "./src/schema.ts",
  out: "./migrations",
  dbCredentials: { url: process.env.VIGIL_OWNER_DATABASE_URL ?? "postgres://vigil_owner:vigil_owner_dev@127.0.0.1:54329/vigil" },
});
