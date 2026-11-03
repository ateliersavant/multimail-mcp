#!/usr/bin/env node
// Fails if any tracked file names a real company domain or address.
// The denylist is deliberately NOT in this repository, because it would itself name them. CI reads the
// FORBIDDEN_TERMS repository secret; local runs read the git-ignored `.forbidden-terms` file (one regex).
// Matches are reported as file:line only, so a public CI log never repeats the term.
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";

const fromEnv = (process.env.FORBIDDEN_TERMS ?? "").trim();
const fromFile = existsSync(".forbidden-terms") ? readFileSync(".forbidden-terms", "utf8").trim() : "";
const pattern = fromEnv || fromFile;

if (!pattern) {
  if (process.env.CI === "true" && process.env.GITHUB_EVENT_NAME === "push") {
    console.error("FORBIDDEN_TERMS secret is missing: a push is never allowed to pass without the real-name check.");
    process.exit(1);
  }
  console.log("Real-name check skipped: no FORBIDDEN_TERMS secret or .forbidden-terms file (expected for pull requests from forks).");
  process.exit(0);
}

let re;
try {
  re = new RegExp(pattern, "i");
} catch {
  console.error("FORBIDDEN_TERMS is not a valid regular expression.");
  process.exit(1);
}

const files = execFileSync("git", ["ls-files", "-z"], { encoding: "utf8" }).split("\0").filter(Boolean);
const hits = [];
for (const file of files) {
  if (file === "package-lock.json") continue;
  let text;
  try {
    text = readFileSync(file, "utf8");
  } catch {
    continue;
  }
  if (text.includes("\u0000")) continue;
  text.split("\n").forEach((line, i) => {
    if (re.test(line)) hits.push(`${file}:${i + 1}`);
  });
}
if (hits.length > 0) {
  console.error(`Real company name or address found (lines not printed):\n  ${hits.join("\n  ")}`);
  process.exit(1);
}
console.log(`Real-name check passed over ${files.length} tracked files.`);
