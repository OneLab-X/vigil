# Maintaining this Wiki

The wiki source lives in the main repository under [`docs/wiki/`](https://github.com/OneLab-X/vigil/tree/main/docs/wiki)
and is published twice on every merge to `main`: to this wiki by the **Publish wiki** workflow, and as the
documentation of the website [onelab-x.github.io/vigil](https://onelab-x.github.io/vigil/docs/) by the **Website**
workflow (`site/`, built with Astro Starlight; preview locally with `pnpm --filter @vigil/site dev`). Edit pages through pull requests, not in
the wiki web editor — web edits are overwritten on the next sync.

- One Markdown file per page; the file name is the page title (`Event-Explorer.md` → *Event Explorer*).
- Link pages with `[[Page Title]]`; images with `![alt](images/name.webp)`.
- `_Sidebar.md` and `_Footer.md` appear on every page.

## Screenshots

Screenshots must come from **synthetic demo data only** — never from a database with real cloud data, real people or
real IPs.

```bash
# 1. a separate, empty demo database (next to your normal dev database)
psql -h 127.0.0.1 -p 54329 -U postgres -c "create database vigil_demo owner vigil_owner"
psql -h 127.0.0.1 -p 54329 -U postgres -d vigil_demo -c "create extension if not exists vector; create extension if not exists pgcrypto"
VIGIL_OWNER_DATABASE_URL=postgres://vigil_owner:vigil_owner_dev@127.0.0.1:54329/vigil_demo pnpm db:migrate

# 2. synthetic incidents, investigations, knowledge and settings
export VIGIL_DATABASE_URL=postgres://vigil_app:vigil_app_dev@127.0.0.1:54329/vigil_demo VIGIL_DATA_DIR=/tmp/vigil-demo
VIGIL_AGENTS_URL=http://127.0.0.1:18199 pnpm db:demo

# 3. demo API and web on other ports (own Next build dir, so `pnpm dev` keeps working)
PORT=8081 VIGIL_RUN_WORKER=0 VIGIL_AGENTS_URL=http://127.0.0.1:18199 pnpm --filter @vigil/api exec tsx src/server.ts &
VIGIL_API_URL=http://127.0.0.1:8081 VIGIL_NEXT_DIST_DIR=.next-demo pnpm --filter @vigil/web exec next dev -p 3101 &

# 4. capture with any Chromium-based browser (playwright-core installed outside the pnpm workspace)
mkdir -p /tmp/vigil-pw && npm i --prefix /tmp/vigil-pw playwright-core && cp scripts/wiki/capture-screenshots.mjs /tmp/vigil-pw/
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  node /tmp/vigil-pw/capture-screenshots.mjs http://127.0.0.1:3101 /tmp/vigil-demo/demo-credentials.json /tmp/vigil-shots
# 5. shrink to 1600 px WebP
for f in /tmp/vigil-shots/*.png; do sips --resampleWidth 1600 "$f" --out "$f" >/dev/null; cwebp -quiet -q 88 "$f" -o "docs/wiki/images/$(basename "${f%.png}").webp"; done
```

The second Next instance rewrites `apps/web/tsconfig.json` and `apps/web/next-env.d.ts` to point at `.next-demo`;
restore them afterwards with `git checkout -- apps/web/tsconfig.json apps/web/next-env.d.ts`.
Use `127.0.0.1:3101` (not `localhost`) so the demo session cookie does not replace your normal dev session.
Before committing, look at every image: no real names, emails, IPs, project IDs or secrets.
