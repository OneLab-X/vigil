// Turn docs/wiki (the single source, also published to the GitHub wiki) into Starlight docs pages.
//   docs/wiki/Event-Explorer.md  →  src/content/docs/docs/event-explorer.md  →  /vigil/docs/event-explorer/
//   docs/wiki/Home.md            →  src/content/docs/docs/index.md           →  /vigil/docs/
// Rewrites [[Wiki Links]] and images/ paths, builds the sidebar from _Sidebar.md. Output is generated (git-ignored).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const site = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const wiki = path.resolve(site, "../docs/wiki");
const outDocs = path.join(site, "src/content/docs/docs");
const outImages = path.join(site, "public/images");
const BASE = "/vigil";

const pages = fs.readdirSync(wiki).filter((f) => f.endsWith(".md") && !f.startsWith("_"));
const slugOf = (file) => (file === "Home.md" ? "" : file.replace(/\.md$/, "").toLowerCase());
const bySlug = new Map(pages.map((f) => [f.replace(/\.md$/, "").replace(/-/g, " ").toLowerCase(), slugOf(f)]));
const href = (title) => {
  const slug = bySlug.get(title.trim().toLowerCase());
  if (slug === undefined) throw new Error(`[[${title}]] does not match any page in docs/wiki`);
  return `${BASE}/docs/${slug ? `${slug}/` : ""}`;
};

function convert(md, file) {
  const lines = md.split("\n");
  const h = lines.findIndex((l) => l.startsWith("# "));
  if (h < 0) throw new Error(`${file}: missing "# Title" heading`);
  const title = lines[h].slice(2).trim();
  let body = lines.filter((_, i) => i !== h).join("\n").replace(/^\n+/, "");
  // leave code fences and inline code untouched
  body = body.split(/(```[\s\S]*?```|`[^`\n]*`)/g).map((part, i) => i % 2 ? part : part
    .replace(/\[\[([^\]|]+)\|([^\]]+)\]\]/g, (_, label, t) => `[${label}](${href(t)})`)
    .replace(/\[\[([^\]]+)\]\]/g, (_, t) => `[${t}](${href(t)})`)
    .replace(/\]\(images\//g, `](${BASE}/images/`)).join("");
  const first = body.split("\n").find((l) => /^[A-Za-z*]/.test(l) && !l.startsWith("|")) ?? "";
  const description = first.replace(/\[([^\]]+)\]\([^)]*\)/g, "$1").replace(/[*_`]/g, "").slice(0, 160);
  return `---\ntitle: ${JSON.stringify(file === "Home.md" ? "Vigil documentation" : title)}\ndescription: ${JSON.stringify(description)}\n---\n\n${body}`;
}

fs.rmSync(outDocs, { recursive: true, force: true });
fs.mkdirSync(outDocs, { recursive: true });
for (const f of pages) {
  const slug = slugOf(f) || "index";
  fs.writeFileSync(path.join(outDocs, `${slug}.md`), convert(fs.readFileSync(path.join(wiki, f), "utf8"), f));
}
fs.rmSync(outImages, { recursive: true, force: true });
fs.cpSync(path.join(wiki, "images"), outImages, { recursive: true });

// _Sidebar.md: "**Group**" lines start a group, "- [[Title]]" lines are entries; a bold [[Home]] line is skipped.
const sidebar = [];
for (const line of fs.readFileSync(path.join(wiki, "_Sidebar.md"), "utf8").split("\n")) {
  const group = line.match(/^\*\*([^[*]+)\*\*\s*$/);
  const item = line.match(/^\s*-\s*\[\[([^\]]+)\]\]/);
  if (group) sidebar.push({ label: group[1].trim(), items: [] });
  else if (item && sidebar.length) sidebar.at(-1).items.push({ label: item[1].trim(), slug: href(item[1]).slice(BASE.length + 1, -1) });
}
sidebar.unshift({ label: "Introduction", slug: "docs" });
fs.writeFileSync(path.join(site, "src/sidebar.generated.json"), JSON.stringify(sidebar, null, 2) + "\n");
console.log(`synced ${pages.length} pages and ${fs.readdirSync(outImages).length} images from docs/wiki`);
