// Project site: https://onelab-x.github.io/vigil/ (GitHub Pages). Docs come from docs/wiki via scripts/sync-docs.mjs.
import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";
import sidebar from "./src/sidebar.generated.json" with { type: "json" };

export default defineConfig({
  site: "https://onelab-x.github.io",
  base: "/vigil",
  trailingSlash: "always",
  integrations: [
    starlight({
      title: "Vigil",
      description: "Open-source, self-hosted, AI-assisted security operations for your clouds.",
      logo: { src: "./src/assets/logo.svg" },
      favicon: "/favicon.svg",
      social: [{ icon: "github", label: "GitHub", href: "https://github.com/OneLab-X/vigil" }],
      sidebar,
      customCss: ["./src/styles/docs.css"],
      lastUpdated: false,
      pagination: true,
      head: [{ tag: "meta", attrs: { name: "theme-color", content: "#4f46e5" } }],
    }),
  ],
});
