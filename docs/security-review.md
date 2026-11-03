# Security review pack

For the independent reviewer. It says what the server does, where each security claim lives in the code, how to check it yourself in minutes, and what remains open. Nothing here identifies a real deployment; ask the operator for access to the live system.

## What it is

A remote MCP server on Cloudflare Workers. It lets AI clients (Claude, ChatGPT, Codex) read Gmail, draft, and send approved drafts from several Google Workspace mailboxes that belong to separate companies. Mailbox access uses Google domain-wide delegation with one service account per company and the single scope `gmail.modify`. Client access uses the server's own OAuth 2.1 layer, with Google sign-in restricted to an allowlist of principals.

## Where to look

| Area | Code | Tests |
|---|---|---|
| Client auth: OAuth 2.1, PRM, CIMD, DCR, PKCE, audience binding | `src/oauth/`, `src/index.ts` (library `@cloudflare/workers-oauth-provider`) | `test/worker/worker.test.ts`, `test/worker/handlers.test.ts` |
| Which clients may exist: metadata hosts, registration redirects, registration limit | `src/oauth/client-policy.ts`, `src/index.ts` | `test/unit/client-policy.test.ts`, `test/worker/worker.test.ts` |
| Google sign-in and principal allowlist | `src/auth/google.ts`, `src/auth/principals.ts`, `src/mcp/handler.ts` | `test/unit/google-signin.test.ts`, `test/unit/principals.test.ts` |
| Tenant isolation, account resolution | `src/tenants/` | `test/unit/tenants.test.ts`, `test/unit/read-tools.test.ts` |
| Delegated Gmail access | `src/gmail/delegation.ts`, `src/gmail/client.ts` | `test/unit/delegation.test.ts`, `test/worker/delegation-runtime.test.ts` |
| Reading, HTML stripping, address parsing, bounds | `src/gmail/render.ts`, `src/gmail/address.ts`, `src/mcp/tools/read.ts` | `test/unit/render.test.ts`, `test/unit/read-tools.test.ts` |
| Drafting and sending, send-as checks, three-state confirmation, sent-draft ledger | `src/mcp/tools/write.ts`, `src/gmail/sendas.ts`, `src/gmail/ledger.ts`, `src/store/oauth-store.ts` | `test/unit/write-tools.test.ts`, `test/unit/ledger.test.ts`, `test/worker/ledger-runtime.test.ts` |
| MIME building, header injection | `src/gmail/mime.ts` | `test/unit/mime.test.ts` |
| Egress allowlist | `src/net/egress.ts`, `scripts/check-egress.mjs` | `test/unit/egress.test.ts`, `test/worker/egress-runtime.test.ts` |
| OAuth state, rate limits | `src/store/`, `src/guard/ratelimit.ts` | `test/worker/store.test.ts`, `test/worker/ratelimit-runtime.test.ts`, `test/unit/ratelimit.test.ts` |
| Audit log | `src/audit.ts`, `migrations/0001_audit.sql` | `test/unit/audit.test.ts`, `test/worker/audit-d1.test.ts` |
| Fail-closed configuration | `src/config.ts`, `src/bindings.ts` | `test/unit/config.test.ts`, `test/unit/bindings.test.ts` |

## Check it yourself

```bash
npm ci
```

```bash
npm run verify
```

`verify` runs the typecheck, every test in Node and in the Workers runtime (including the adversarial review's tests), the egress check, the real-name check, the tenant-file check, and the mutation suite. The mutation suite (`scripts/mutate.mjs`) removes each security guard in turn and requires the tests to fail; a surviving mutation fails the build. Read the mutation list to see exactly which guards are pinned.

## Claims and their evidence

| Claim | Evidence |
|---|---|
| No implicit mailbox; unknown accounts refused before any Google call | `TenantRegistry.requireMailbox`, exact match; mutations `a-account-allowlist`, `tool-account-allowlist` |
| Companies never mix in one call | tenant validator (domains owned once, send-as inside the tenant); From and reply ids resolved in the mailbox's own scope; mutation `send-as-domain-guard` |
| No direct send; only an approved draft is sent | tool surface has no send-message tool (asserted in tests); `send_draft` description |
| From verified twice | operator list and Gmail "Send mail as", at draft time and again at send time on the untruncated headers; mutations `send-as-allowlist`, `send-as-pending`, `send-as-missing-in-gmail`, `send-reverify-at-send-time`, `send-single-from-header`, `send-single-mailbox`, `send-sender-matches-from` |
| Never a duplicate send; never success by inference | atomic claim, ledger and three outcomes; mutations `send-claim-atomic`, `sent-ledger`, `ledger-release-keeps-sent-durable`, `ledger-release-keeps-sent-memory`, `send-confirm-sent-label`, `send-ambiguous-probe`, `send-404-ambiguous`, `send-ledger-failure-reported` |
| The approved text is what recipients read | plain-text drafts only, HTML parts shown, real addresses always displayed; mutations `no-model-html`, `draft-html-shown`, `display-real-address` |
| No header injection | mutation `mime-header-injection` |
| Fail closed, and loud without leaking | config and bindings; configuration errors name variables, never values; mutations `public-url-must-be-https`, `tenant-unknown-keys`, `bindings-fail-closed`, `gmail-error-not-empty`, `config-error-no-values` |
| Content-free, durable audit for 90 days | closed field set, no content columns, retention job; mutations `audit-durable-sink`, `audit-retention` |
| Rate limits | per client token and per principal, atomic; mutations `mcp-rate-limit`, `send-rate-limit`, `ratelimit-window` |
| Egress only to the Google calls the server makes | single fetch wrapper with host, method and exact-path rules, redirects refused, CI host check; the OAuth library's metadata fetches screened by host; mutations `egress-allowlist`, `egress-method`, `egress-exact-path`, `egress-redirect-mode-runtime`, `egress-redirect-refused`, `client-metadata-host-screen`, `client-metadata-host-check` |
| Sign-in integrity | id_token signature and claims, principal allowlist at sign-in and on every call, the company's own Workspace (`hd`), consent form-action; mutations `id-token-signature`, `principal-allowlist-authorize`, `principal-allowlist-mcp`, `workspace-domain`, `consent-form-action` |
| Only supported clients | registration redirects to supported hosts or loopback, no client key URLs, registrations limited per address; mutations `registration-redirect-policy`, `register-rate-limit` |

## Residual risks the operator accepts

- A leaked service-account key reaches every mailbox of that company with `gmail.modify` reach, independently of this server, until rotated (runbook section 3).
- Tenant separation holds per call; an AI client can still copy content from one company into another company's draft across two calls. The tenant is echoed in every result and the human approves every send.
- Sending relies on the human reading the draft. A client configured to auto-approve tool calls weakens that control; the sending limits cap the damage (threat model T12).
- During a D1 outage, audit records reach only the short-lived log stream (T13).

## Adversarial review

An independent agent reviewed the code adversarially and had to prove each finding with a failing test. It confirmed nine. All nine are fixed, each fix is pinned by at least one mutation, and the proof tests now run with the suite (`test/adversarial/`).

| # | Severity | Finding | Fix |
|---|---|---|---|
| 1 | medium | A sender's display name longer than the 2000-character header cut pushed the real address out of view, so a message could appear to come from someone else. | Address headers parsed per RFC 5322 and shown mailbox by mailbox; long names are cut, addresses never; invisible characters removed. |
| 2 | medium | `create_draft` accepted an HTML body, which most mail clients display, while the approval preview and `get_draft` showed only the plain text. | The model can no longer write HTML (strict input schemas refuse it); `get_draft` shows any HTML part a draft gained elsewhere. |
| 3 | medium | Two concurrent `send_draft` calls for one draft could both reach Gmail: the in-flight marker was written several steps after it was read. A 404 at send was reported as "nothing was sent", and clearing the marker could erase a sent record. | An atomic claim in the Durable Object; a 404 is treated as possibly sent; releasing a claim never removes a sent record. |
| 4 | medium | The send-time From check read a truncated, first-only From, so a From with several mailboxes, a second From header, or a very long name could get a non-allowlisted address sent. | The untruncated headers are read: exactly one From header naming exactly one mailbox, and any Sender must match it. |
| 5 | low | When recording a completed send failed, the error said nothing was sent. | The send is reported with a do-not-resend note; internal errors no longer claim that nothing happened. |
| 6 | low | HTML stripping was quadratic on crafted input: one 160 kB email took seconds of CPU. | A linear forward scanner with input bounds. |
| 7 | low | An unauthenticated `/authorize` with a URL-shaped `client_id` made the Worker fetch any host through the OAuth library, outside the egress allowlist. | Every client id the library could resolve is screened at the Worker entry; metadata documents only from the supported clients' hosts. |
| 8 | low | Sign-in did not check the id_token's `hd`, although the threat model said it did. | The account must be managed by the company's own Workspace. |
| 9 | info | A JSON syntax error in the tenant file copied a fragment of the file into the Worker log. | The error names the variable only; `npm run check:tenants` shows the position locally. |

The review also raised points it could not prove with a test. Three were acted on:

- `SECURITY.md` said `gmail.modify` could not send directly. It can. The egress rules now name the exact method and path of each Gmail call the server makes, so direct send, trash and label changes are unreachable from the Worker, and the documents state the scope's real reach.
- Open Dynamic Client Registration let anyone register a look-alike client with any redirect. Registration now accepts only redirects to the supported clients' hosts or to loopback, refuses client key URLs, and is limited per source address.
- Long recipient and References lines are folded at 78 characters.

## Questions for the reviewer

1. Is the single `gmail.modify` scope the narrowest acceptable for draft-then-send?
2. Are the default sending limits (20 per hour, 100 per day per principal) right for this operator?
3. Is a log-stream-only fallback during a D1 outage acceptable, or should sending stop when the durable audit write fails?
4. Anything in the OAuth layer configuration (`src/oauth/options.ts`, `src/oauth/client-policy.ts`) you would tighten: token lifetimes, the supported-client host lists, DCR left enabled (now restricted to those hosts and loopback)?
5. Is requiring `hd` to match the company's own Workspace right, given that it refuses consumer Google accounts as principals outright?
