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
    find: "    const claim = await ledger.claim(account, draftId, now());",
    replace: "    const claim = { claimed: true };",
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
    // Phase 3: the audit log must reach the durable D1 table, not only the short-lived log stream.
    id: "audit-durable-sink",
    file: "src/audit.ts",
    find: "  const sink = env.AUDIT_DB !== undefined ? new CompositeAuditSink(new ConsoleAuditSink(), new D1AuditSink(env.AUDIT_DB)) : new ConsoleAuditSink();",
    replace: "  const sink = new ConsoleAuditSink();",
    projects: ["worker"],
  },
  {
    // Phase 3: 90-day retention must actually delete old rows.
    id: "audit-retention",
    file: "src/audit.ts",
    find: 'const res = await db.prepare("DELETE FROM audit WHERE ts < ?1").bind(cutoff).run();',
    replace: 'const res = await db.prepare("DELETE FROM audit WHERE 0 AND ts < ?1").bind(cutoff).run();',
    projects: ["worker"],
  },
  {
    // Phase 3: no audit database, no service.
    id: "bindings-fail-closed",
    file: "src/bindings.ts",
    find: "  if (env.AUDIT_DB === undefined) issues.push(",
    replace: "  if (false) issues.push(",
    projects: ["unit"],
  },
  {
    // Phase 3: per-client request limit on /mcp.
    id: "mcp-rate-limit",
    file: "src/mcp/handler.ts",
    find: "  if (!rate.allowed) {",
    replace: "  if (false) {",
    projects: ["worker"],
  },
  {
    // Phase 3: per-principal sending limits.
    id: "send-rate-limit",
    file: "src/mcp/tools/write.ts",
    find: "    await limitSends();",
    replace: "    void limitSends;",
    projects: ["unit"],
  },
  {
    // Phase 3: the window arithmetic itself.
    id: "ratelimit-window",
    file: "src/guard/ratelimit.ts",
    find: "  if (count >= limit) return {",
    replace: "  if (false) return {",
    projects: ["unit", "worker"],
  },
  {
    id: "egress-allowlist",
    file: "src/net/egress.ts",
    find: 'if (rules === undefined) throw new EgressDeniedError("host not allowlisted", url);',
    replace: "if (rules === undefined) return;",
    projects: ["unit"],
  },
  {
    id: "id-token-signature",
    file: "src/auth/google.ts",
    find: 'if (!ok) throw new SignInError("id_token_bad_signature");',
    replace: "void ok;",
    projects: ["unit"],
  },
  // Phase 3, adversarial review fixes.
  {
    // Concurrent send_draft calls for one draft: exactly one claim may succeed.
    id: "send-claim-atomic",
    file: "src/store/oauth-store.ts",
    find: "if (row !== undefined && (row.expiration === null || row.expiration > this.nowSeconds())) return row.value;",
    replace: "void row;",
    projects: ["worker"],
  },
  {
    // Giving up a claim must never erase the record of a send that happened.
    id: "ledger-release-keeps-sent-durable",
    file: "src/store/oauth-store.ts",
    find: 'if (state === "sending") this.ctx.storage.sql.exec("DELETE FROM kv WHERE key = ?", key);',
    replace: 'this.ctx.storage.sql.exec("DELETE FROM kv WHERE key = ?", key);',
    projects: ["worker"],
  },
  {
    id: "ledger-release-keeps-sent-memory",
    file: "src/gmail/ledger.ts",
    find: 'if (parse(this.live(k))?.state === "sending") this.entries.delete(k);',
    replace: "this.entries.delete(k);",
    projects: ["unit"],
  },
  {
    // A draft must carry exactly one From header at send time.
    id: "send-single-from-header",
    file: "src/mcp/tools/write.ts",
    find: "const single = froms.length === 1 ? extractAddress(froms[0]) : undefined;",
    replace: "const single = extractAddress(froms[0]);",
    projects: ["unit"],
  },
  {
    // A From naming several mailboxes, or an unreadable one, is refused (not reduced to one address).
    id: "send-single-mailbox",
    file: "src/gmail/address.ts",
    find: "if (p.mailboxes.length !== 1 || p.unparsed.length > 0) return undefined;",
    replace: "if (p.mailboxes.length === 0) return undefined;",
    projects: ["unit"],
  },
  {
    id: "send-sender-matches-from",
    file: "src/mcp/tools/write.ts",
    find: "if (senders.some((s) => extractAddress(s) !== single)) {",
    replace: "if (false) {",
    projects: ["unit"],
  },
  {
    // A 404 from the send is ambiguous (the draft may have been sent), never "nothing was sent".
    id: "send-404-ambiguous",
    file: "src/mcp/tools/write.ts",
    find: "e.status >= 400 && e.status < 500 && e.status !== 404) {",
    replace: "e.status >= 400 && e.status < 500) {",
    projects: ["unit"],
  },
  {
    // A failed ledger write after a real send is reported with the send, never as an error.
    id: "send-ledger-failure-reported",
    file: "src/mcp/tools/write.ts",
    find: '      ledgerNote = " The server could not record this send',
    replace: '      throw e;\n      ledgerNote = " The server could not record this send',
    projects: ["unit"],
  },
  {
    // The model cannot add an HTML body the user never sees.
    id: "no-model-html",
    file: "src/mcp/tools/write.ts",
    find: "inputSchema: z.object({ account: Account, ...Content }).strict(),",
    replace: "inputSchema: z.object({ account: Account, ...Content }),",
    projects: ["unit"],
  },
  {
    // get_draft shows an HTML part a draft gained elsewhere.
    id: "draft-html-shown",
    file: "src/mcp/tools/write.ts",
    find: "htmlText: html?.text ?? null,",
    replace: "htmlText: null,",
    projects: ["unit"],
  },
  {
    // Display: the real address is shown however long the display name is.
    id: "display-real-address",
    file: "src/gmail/address.ts",
    find: "const name = m.name.length > MAX_NAME_CHARS ? `${m.name.slice(0, MAX_NAME_CHARS)}…` : m.name;",
    replace: "const name = m.name; if (name.length > MAX_NAME_CHARS) return name.slice(0, 2000);",
    projects: ["unit"],
  },
  {
    // A metadata-document client id on another host never reaches the OAuth library (which would fetch it).
    id: "client-metadata-host-screen",
    file: "src/index.ts",
    find: 'if (result === "client_host_not_allowed") {',
    replace: "if (false) {",
    projects: ["worker"],
  },
  {
    id: "client-metadata-host-check",
    file: "src/oauth/client-policy.ts",
    find: 'return u.port === "" && u.username === "" && u.password === "" && metadataHosts.has(u.hostname.toLowerCase());',
    replace: "return true;",
    projects: ["unit"],
  },
  {
    // Registration only for supported clients' redirect hosts and loopback.
    id: "registration-redirect-policy",
    file: "src/oauth/client-policy.ts",
    find: 'if (!Array.isArray(uris) || uris.length === 0 || !uris.every((u) => typeof u === "string" && redirectUriAllowed(u, redirectHosts))) {',
    replace: "if (false) {",
    projects: ["unit", "worker"],
  },
  {
    id: "register-rate-limit",
    file: "src/index.ts",
    find: "    if (!rate.allowed) {",
    replace: "    if (false) {",
    projects: ["worker"],
  },
  {
    // Sign-in: the account must be managed by the company's own Google Workspace.
    id: "workspace-domain",
    file: "src/oauth/handlers.ts",
    find: "if (!workspaceDomainMatches(principal.email, principal.hd, cfg.registry.tenants)) {",
    replace: "if (false) {",
    projects: ["worker"],
  },
  {
    // Egress: the method is part of every rule (gmail.modify could otherwise send or trash directly).
    id: "egress-method",
    file: "src/net/egress.ts",
    find: "if (!rules.some((r) => r.method === m && pathMatches(r.path, url.pathname)))",
    replace: "if (!rules.some((r) => pathMatches(r.path, url.pathname)))",
    projects: ["unit"],
  },
  {
    id: "egress-exact-path",
    file: "src/net/egress.ts",
    find: "if (want.length !== got.length) return false;",
    replace: "if (got.length < want.length) return false;",
    projects: ["unit"],
  },
  {
    // Configuration errors name variables, never values from the tenant file.
    id: "config-error-no-values",
    file: "src/tenants/validate.ts",
    find: 'throw new TenantConfigError(["$: not valid JSON (run npm run check:tenants on the file to see where)"]);',
    replace: "throw new TenantConfigError([`$: not valid JSON (${jsonText.slice(0, 40)})`]);",
    projects: ["unit"],
  },
  // Phase 2 organising tools: labels, archive, Trash.
  {
    // TRASH, SPAM, SENT, DRAFT and CHAT are never changed through modify_labels.
    id: "organise-label-not-allowed",
    file: "src/mcp/tools/organise.ts",
    find: 'if (why !== undefined) throw new OrganiseRefusal("label_not_allowed",',
    replace: 'if (false) throw new OrganiseRefusal("label_not_allowed",',
    projects: ["unit"],
  },
  {
    // Labels must exist in the mailbox; nothing is created or guessed.
    id: "organise-unknown-label",
    file: "src/mcp/tools/organise.ts",
    find: 'if (found === undefined) throw new OrganiseRefusal("unknown_label",',
    replace: 'if (found === undefined) continue; if (false) throw new OrganiseRefusal("unknown_label",',
    projects: ["unit"],
  },
  {
    id: "organise-single-target",
    file: "src/mcp/tools/organise.ts",
    find: "if ((input.thread_id === undefined) === (input.message_id === undefined))",
    replace: "if (input.thread_id === undefined && input.message_id === undefined)",
    projects: ["unit"],
  },
  {
    // A label change is confirmed by reading it back, never inferred from Gmail accepting it.
    id: "organise-confirm-labels",
    file: "src/mcp/tools/organise.ts",
    find: "const confirmed = after.length > 0 && after.every((l) => add.every((a) => l.includes(a.id)) && remove.every((r) => !l.includes(r.id)));",
    replace: "const confirmed = true;",
    projects: ["unit"],
  },
  {
    id: "organise-confirm-trash",
    file: "src/mcp/tools/organise.ts",
    find: 'const confirmed = after.length > 0 && after.every((l) => (action === "trash" ? l.includes("TRASH") : !l.includes("TRASH")));',
    replace: "const confirmed = true;",
    projects: ["unit"],
  },
  {
    id: "organise-rate-limit",
    file: "src/mcp/tools/organise.ts",
    find: 'if (!d.allowed) throw new OrganiseRefusal("rate_limited",',
    replace: 'if (false) throw new OrganiseRefusal("rate_limited",',
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
