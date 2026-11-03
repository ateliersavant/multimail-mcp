#!/usr/bin/env node
// Handoff §6: each security guard is removed in turn; the suite MUST fail every time. A green suite with a guard
// removed is itself a failing build. Add a mutation whenever a new guard lands.
import { readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

const root = resolve(new URL("..", import.meta.url).pathname);
const MUTATIONS = [
  {
    id: "a-account-allowlist",
    file: "src/tenants/registry.ts",
    find: "if (!found) throw new UnknownAccountError(account);",
    replace: "if (!found) return [...this.byAddress.values()][0] as ResolvedMailbox;",
    projects: ["unit"],
  },
  {
    id: "principal-allowlist-authorize",
    file: "src/oauth/handlers.ts",
    find: "if (!isAllowedPrincipal(cfg.allowedPrincipals, principal.email)) {",
    replace: "if (false) {",
    projects: ["worker"],
  },
  {
    id: "principal-allowlist-mcp",
    file: "src/mcp/handler.ts",
    find: "if (!isAllowedPrincipal(cfg.allowedPrincipals, props.email)) {",
    replace: "if (false) {",
    projects: ["worker"],
  },
  {
    // A plaintext origin would put bearer tokens on the wire unencrypted.
    id: "public-url-must-be-https",
    file: "src/config.ts",
    find: 'if (u.protocol !== "https:" && !(u.protocol === "http:" && isLocal)) throw new Error("must be https (http only for localhost)");',
    replace: "void isLocal;",
    projects: ["unit"],
  },
  {
    // Unknown keys in the tenant file must be rejected (typo protection, e.g. "sendas").
    id: "tenant-unknown-keys",
    file: "src/tenants/validate.ts",
    find: 'for (const k of Object.keys(rawMailbox)) if (!MAILBOX_KEYS.has(k)) fail(`${mp}.${k}`, "unknown key");',
    replace: "void MAILBOX_KEYS;",
    projects: ["unit"],
  },
  {
    // A send-as address outside the tenant's domains is the structural cross-tenant guard.
    id: "send-as-domain-guard",
    file: "src/tenants/validate.ts",
    find: 'else if (!inTenant(s)) fail(sp, "domain is not one of this tenant\'s domains (cross-tenant send-as is impossible by construction)");',
    replace: "else if (false) {}",
    projects: ["unit"],
  },
  {
    id: "egress-allowlist",
    file: "src/net/egress.ts",
    find: 'if (prefixes === undefined) throw new EgressDeniedError("host not allowlisted", url);',
    replace: "if (prefixes === undefined) return;",
    projects: ["unit"],
  },
  {
    id: "id-token-signature",
    file: "src/auth/google.ts",
    find: 'if (!ok) throw new SignInError("id_token_bad_signature");',
    replace: "void ok;",
    projects: ["unit"],
  },
];

const only = process.argv.slice(2);
let failures = 0;
for (const m of MUTATIONS) {
  if (only.length && !only.includes(m.id)) continue;
  const path = resolve(root, m.file);
  const original = readFileSync(path, "utf8");
  if (original.split(m.find).length !== 2) { console.error(`✗ ${m.id}: anchor not found exactly once in ${m.file} — update the mutation`); failures++; continue; }
  writeFileSync(path, original.replace(m.find, m.replace));
  try {
    const args = ["vitest", "run", "--reporter=dot", ...m.projects.flatMap((p) => ["--project", p])];
    const r = spawnSync("npx", args, { cwd: root, encoding: "utf8" });
    const killed = r.status !== 0;
    console.log(`${killed ? "✓" : "✗"} ${m.id}: ${killed ? "tests failed as required" : "TESTS STILL PASS — guard is not pinned"}`);
    if (!killed) failures++;
  } finally {
    writeFileSync(path, original);
  }
}
if (failures) { console.error(`${failures} mutation(s) survived.`); process.exit(1); }
console.log("All mutations killed.");
