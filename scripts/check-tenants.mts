#!/usr/bin/env -S npx tsx
// Validates a tenant file the way the Worker does at boot, and prints the public view.
// Usage: npm run check:tenants -- path/to/tenants.json
import { readFileSync } from "node:fs";
import { TenantConfigError, TenantRegistry, loadTenantConfig } from "../src/tenants/index.js";

const path = process.argv[2] ?? "fixtures/tenants.example.json";
try {
  const cfg = loadTenantConfig(readFileSync(path, "utf8"));
  const reg = new TenantRegistry(cfg);
  console.log(`OK: ${path} — ${cfg.tenants.length} tenant(s), ${reg.publicView().reduce((n, t) => n + t.mailboxes.length, 0)} mailbox(es)`);
  for (const t of reg.publicView()) {
    console.log(`  ${t.id} (${t.label}) domains=${t.domains.join(",")}`);
    for (const m of t.mailboxes) console.log(`    ${m.address}  send-as: ${m.sendAs.join(", ")}`);
  }
} catch (e) {
  if (e instanceof TenantConfigError) {
    console.error(`INVALID: ${path}\n- ${e.issues.join("\n- ")}`);
    process.exit(1);
  }
  throw e;
}
