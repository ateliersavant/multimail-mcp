#!/usr/bin/env node
// Builds the production wrangler config from the committed wrangler.jsonc plus the git-ignored deploy.local.json
// ({ "host": "mcp.example.com", "auditDbId": "<D1 database id>" }), applies the D1 migrations, then runs `wrangler deploy`.
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

const root = resolve(new URL("..", import.meta.url).pathname);
const localPath = resolve(root, "deploy.local.json");
if (!existsSync(localPath)) {
  console.error('deploy.local.json missing. Create it (git-ignored): {"host":"<public hostname>","auditDbId":"<D1 database id>"}');
  process.exit(1);
}
const local = JSON.parse(readFileSync(localPath, "utf8"));
const args = process.argv.slice(2);
// --workers-dev: serve on <name>.<account>.workers.dev instead of the custom domain (used until the zone is on Cloudflare).
const workersDev = args.includes("--workers-dev");
const passthrough = args.filter((a) => a !== "--workers-dev");
for (const k of workersDev ? ["auditDbId"] : ["host", "auditDbId"]) if (typeof local[k] !== "string" || local[k].length === 0) { console.error(`deploy.local.json: ${k} missing`); process.exit(1); }

const jsonc = readFileSync(resolve(root, "wrangler.jsonc"), "utf8");
const base = JSON.parse(jsonc.split("\n").filter((l) => !l.trim().startsWith("//")).join("\n"));
const prod = {
  ...base,
  main: resolve(root, base.main),
  workers_dev: workersDev,
  // Preview URLs would serve the Worker under per-version origins; tokens are audience-bound to PUBLIC_URL, so they
  // could not be used there, but there is no reason to expose them at all.
  preview_urls: false,
  ...(workersDev ? {} : { routes: [{ pattern: local.host, custom_domain: true }] }),
  d1_databases: base.d1_databases.map((d) => (d.binding === "AUDIT_DB" ? { ...d, database_id: local.auditDbId, migrations_dir: resolve(root, d.migrations_dir) } : d)),
};
delete prod.$schema;
mkdirSync(resolve(root, ".wrangler"), { recursive: true });
const out = resolve(root, ".wrangler/deploy.generated.json");
writeFileSync(out, JSON.stringify(prod, null, 2));
console.log(`Deploying ${base.name} to ${workersDev ? "workers.dev" : `https://${local.host}`} (config: ${out})`);
// The audit table must exist before the new code writes to it. Idempotent: applies only unapplied migrations.
const audit = prod.d1_databases.find((d) => d.binding === "AUDIT_DB");
const m = spawnSync("npx", ["wrangler", "d1", "migrations", "apply", audit.database_name, "--remote", "--config", out], { stdio: "inherit", cwd: root, env: { ...process.env, CI: "true" } });
if (m.status !== 0) { console.error("D1 migrations failed; not deploying."); process.exit(m.status ?? 1); }
const r = spawnSync("npx", ["wrangler", "deploy", "--config", out, ...passthrough], { stdio: "inherit", cwd: root });
process.exit(r.status ?? 1);
