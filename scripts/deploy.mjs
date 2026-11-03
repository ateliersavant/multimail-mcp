#!/usr/bin/env node
// Builds the production wrangler config from the committed wrangler.jsonc plus the git-ignored deploy.local.json
// ({ "host": "mcp.example.com", "kvId": "<kv namespace id>" }) and runs `wrangler deploy` on it.
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

const root = resolve(new URL("..", import.meta.url).pathname);
const localPath = resolve(root, "deploy.local.json");
if (!existsSync(localPath)) {
  console.error('deploy.local.json missing. Create it (git-ignored): {"host":"<public hostname>","kvId":"<OAUTH_KV namespace id>"}');
  process.exit(1);
}
const local = JSON.parse(readFileSync(localPath, "utf8"));
const args = process.argv.slice(2);
// --workers-dev: serve on <name>.<account>.workers.dev instead of the custom domain (used until the zone is on Cloudflare).
const workersDev = args.includes("--workers-dev");
const passthrough = args.filter((a) => a !== "--workers-dev");
for (const k of workersDev ? ["kvId"] : ["host", "kvId"]) if (typeof local[k] !== "string" || local[k].length === 0) { console.error(`deploy.local.json: ${k} missing`); process.exit(1); }

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
  kv_namespaces: [{ binding: "OAUTH_KV", id: local.kvId }],
};
delete prod.$schema;
mkdirSync(resolve(root, ".wrangler"), { recursive: true });
const out = resolve(root, ".wrangler/deploy.generated.json");
writeFileSync(out, JSON.stringify(prod, null, 2));
console.log(`Deploying ${base.name} to ${workersDev ? "workers.dev" : `https://${local.host}`} (config: ${out})`);
const r = spawnSync("npx", ["wrangler", "deploy", "--config", out, ...passthrough], { stdio: "inherit", cwd: root });
process.exit(r.status ?? 1);
