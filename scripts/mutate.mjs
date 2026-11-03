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
    // Without Google in form-action, browsers block the redirect after "Continue with Google".
    id: "consent-form-action",
    file: "src/oauth/handlers.ts",
    find: "const formActions = [GOOGLE_SIGN_IN_ORIGIN, ...(clientOrigin !== undefined ? [clientOrigin] : [])];",
    replace: "const formActions: string[] = [];",
    projects: ["worker"],
  },
  {
    // The Workers runtime rejects redirect: "error"; every outbound call to Google failed in production (3 Nov 2026).
    id: "egress-redirect-mode-runtime",
    file: "src/net/egress.ts",
    find: 'const safeInit: RequestInit = { ...init, redirect: "manual" };',
    replace: 'const safeInit: RequestInit = { ...init, redirect: "error" };',
    projects: ["worker"],
  },
  {
    // A followed redirect could carry a request off the allowlist.
    id: "egress-redirect-refused",
    file: "src/net/egress.ts",
    find: 'if (res.status >= 300 && res.status < 400) throw new EgressDeniedError("redirect refused", url);',
    replace: "void EgressDeniedError;",
    projects: ["unit"],
  },
  {
    // An expired grant, token or sign-in transaction must read as absent.
    id: "store-expired-rows",
    file: "src/store/oauth-store.ts",
    find: "if (row.expiration !== null && row.expiration <= this.nowSeconds()) {",
    replace: "if (false) {",
    projects: ["worker"],
  },
  {
    // Phase 1: the tool layer must refuse an unknown account itself, not fall back to any configured mailbox.
    id: "tool-account-allowlist",
    file: "src/mcp/tools/read.ts",
    find: "target = deps.registry.requireMailbox(account);",
    replace: "target = deps.registry.getMailbox(account) ?? (deps.registry.getMailbox(deps.registry.tenants[0].mailboxes[0].address));",
    projects: ["unit", "worker"],
  },
  {
    // Phase 1: HTML bodies must be stripped before they reach the model (threat T4).
    id: "html-stripping",
    file: "src/gmail/render.ts",
    find: "    text = stripHtml(html);",
    replace: "    text = normaliseWhitespace(html);",
    projects: ["unit"],
  },
  {
    // Phase 1: a Gmail error must never read as an empty mailbox (rule 6).
    id: "gmail-error-not-empty",
    file: "src/gmail/client.ts",
    find: "    if (!res.ok) {\n      const code = statusToCode(res.status);",
    replace: "    if (!res.ok) return {};\n    if (false) {\n      const code = statusToCode(res.status);",
    projects: ["unit"],
  },
  {
    // Phase 2, rule 4: the operator's send-as list is checked at send time too (a draft can be edited in Gmail).
    id: "send-as-allowlist",
    file: "src/gmail/sendas.ts",
    find: "  if (!allowlisted) {",
    replace: "  if (false) {",
    projects: ["unit"],
  },
  {
    // Phase 2, rule 4: an alias Gmail still has pending must never be used.
    id: "send-as-pending",
    file: "src/gmail/sendas.ts",
    find: '  else if (entry.verificationStatus === "pending") gmailStatus = "pending";',
    replace: '  else if (entry.verificationStatus === "pending") gmailStatus = "accepted";',
    projects: ["unit"],
  },
  {
    // Phase 2, rule 4: an address Gmail does not list would be silently rewritten to the primary address.
    id: "send-as-missing-in-gmail",
    file: "src/gmail/sendas.ts",
    find: '  if (entry === undefined) gmailStatus = "missing";',
    replace: '  if (entry === undefined) gmailStatus = "primary";',
    projects: ["unit"],
  },
  {
    // Phase 2, rule 4: the draft's From is verified again as it is at send time.
    id: "send-reverify-at-send-time",
    file: "src/mcp/tools/write.ts",
    find: "    requireSendAs(t, fromAddress, await deps.gmail.listSendAs(t));",
    replace: "    void requireSendAs;",
    projects: ["unit"],
  },
  {
    // Phase 2, rule 5: a draft already sent is refused, never sent or recreated.
    id: "sent-ledger",
    file: "src/mcp/tools/write.ts",
    find: "    const prior = await ledger.lookup(account, draftId);",
    replace: "    const prior = null;",
    projects: ["unit"],
  },
  {
    // Phase 2, rule 5: success needs the SENT label, never inference.
    id: "send-confirm-sent-label",
    file: "src/mcp/tools/write.ts",
    find: '    if (!labels.includes("SENT")) {',
    replace: "    if (false) {",
    projects: ["unit"],
  },
  {
    // Phase 2, rule 5: an ambiguous error must check the draft, not collapse into "failed" (which invites a resend).
    id: "send-ambiguous-probe",
    file: "src/mcp/tools/write.ts",
    find: "      const stillThere = await draftStillThere(t, draftId);",
    replace: "      const stillThere = true;",
    projects: ["unit"],
  },
  {
    // Phase 2: no header value may carry a line break (it would inject a Bcc or other header).
    id: "mime-header-injection",
    file: "src/gmail/mime.ts",
    find: '  if (/[\\r\\n\\0]/.test(value)) throw new MimeError("header_injection"',
    replace: '  if (false) throw new MimeError("header_injection"',
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
