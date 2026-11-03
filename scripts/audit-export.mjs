#!/usr/bin/env node
// Exports the content-free audit log from the live D1 database (handoff §6: read via wrangler, no admin route).
// Usage: npm run audit:export -- [--days 7] [--format csv|json]
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(new URL("..", import.meta.url).pathname);
const args = process.argv.slice(2);
const opt = (name, fallback) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 && args[i + 1] !== undefined ? args[i + 1] : fallback;
};
const days = Number(opt("days", "7"));
const format = opt("format", "csv");
if (!Number.isInteger(days) || days < 1 || days > 90) { console.error("--days must be an integer from 1 to 90"); process.exit(1); }
if (!["csv", "json"].includes(format)) { console.error("--format must be csv or json"); process.exit(1); }

const jsonc = readFileSync(resolve(root, "wrangler.jsonc"), "utf8");
const base = JSON.parse(jsonc.split("\n").filter((l) => !l.trim().startsWith("//")).join("\n"));
const audit = base.d1_databases.find((d) => d.binding === "AUDIT_DB");
const db = audit.database_name;
// The committed config holds a placeholder id; the real one is in the git-ignored deploy.local.json (as for deploys).
const localPath = resolve(root, "deploy.local.json");
if (!existsSync(localPath)) { console.error('deploy.local.json missing: it must hold {"auditDbId": "<D1 database id>"}'); process.exit(1); }
const local = JSON.parse(readFileSync(localPath, "utf8"));
if (typeof local.auditDbId !== "string" || local.auditDbId === "") { console.error("deploy.local.json: auditDbId missing"); process.exit(1); }
mkdirSync(resolve(root, ".wrangler"), { recursive: true });
const configPath = resolve(root, ".wrangler/audit-export.generated.json");
writeFileSync(configPath, JSON.stringify({ name: base.name, d1_databases: [{ ...audit, database_id: local.auditDbId, migrations_dir: resolve(root, audit.migrations_dir) }] }, null, 2));
const since = new Date(Date.now() - days * 86_400_000).toISOString();
const columns = ["ts", "tool", "outcome", "tenant", "account", "from_address", "message_id", "thread_id", "draft_id", "recipient_count", "error_code", "client_id", "principal", "duration_ms"];
const sql = `SELECT ${columns.join(", ")} FROM audit WHERE ts >= '${since}' ORDER BY ts`;
const r = spawnSync("npx", ["wrangler", "d1", "execute", db, "--remote", "--json", "--config", configPath, "--command", sql], { cwd: root, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
if (r.status !== 0) { process.stderr.write(r.stderr || r.stdout); process.exit(r.status ?? 1); }
const rows = JSON.parse(r.stdout)[0]?.results ?? [];
if (format === "json") { process.stdout.write(JSON.stringify(rows, null, 2) + "\n"); process.exit(0); }
const cell = (v) => (v === null || v === undefined ? "" : /[",\n]/.test(String(v)) ? `"${String(v).replace(/"/g, '""')}"` : String(v));
process.stdout.write([columns.join(","), ...rows.map((row) => columns.map((c) => cell(row[c])).join(","))].join("\n") + "\n");
console.error(`${rows.length} audit row(s) since ${since}`);
