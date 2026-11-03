#!/usr/bin/env node
// Fails if any hostname under src/ is not in scripts/host-allowlist.json. Conservative on purpose:
// comments and strings count. Run in CI and before every deploy.
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const root = new URL("..", import.meta.url).pathname;
const allow = JSON.parse(readFileSync(join(root, "scripts/host-allowlist.json"), "utf8"));
const allowed = new Set(Object.values(allow).filter((v) => typeof v === "object").flatMap((m) => Object.keys(m)));

function* walk(dir) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) yield* walk(p);
    else if (/\.(ts|mts|js|mjs|json)$/.test(name)) yield p;
  }
}

const HOST = /https?:\/\/([a-z0-9][a-z0-9.-]*[a-z0-9])(?=[/:"'`\s)>\]]|$)/gi;
const violations = [];
for (const file of walk(join(root, "src"))) {
  const text = readFileSync(file, "utf8");
  text.split("\n").forEach((line, i) => {
    for (const m of line.matchAll(HOST)) {
      const host = m[1].toLowerCase();
      if (!allowed.has(host)) violations.push(`${relative(root, file)}:${i + 1}: ${host}`);
    }
  });
}
if (violations.length) {
  console.error("Egress check failed. Hosts not in scripts/host-allowlist.json:\n  " + violations.join("\n  "));
  process.exit(1);
}
console.log(`Egress check passed (${allowed.size} allowlisted hosts).`);
