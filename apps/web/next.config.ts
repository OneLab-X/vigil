import path from "node:path";
import type { NextConfig } from "next";

const api = process.env.VIGIL_API_URL ?? "http://127.0.0.1:8080";
const config: NextConfig = {
  // Container builds produce a self-contained server (deploy/docker/web.Dockerfile).
  ...(process.env.VIGIL_STANDALONE === "1" ? { output: "standalone" as const, outputFileTracingRoot: path.resolve(process.cwd(), "../..") } : {}),
  // Same-origin proxy so the httpOnly session cookie and CSRF header work without CORS.
  async rewrites() { return [{ source: "/api/v1/:path*", destination: `${api}/api/v1/:path*` }]; },
  async headers() {
    return [{ source: "/:path*", headers: [
      { key: "X-Frame-Options", value: "DENY" }, { key: "X-Content-Type-Options", value: "nosniff" },
      { key: "Referrer-Policy", value: "same-origin" },
    ] }];
  },
};
export default config;
