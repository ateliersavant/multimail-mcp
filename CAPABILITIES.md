# Capabilities

Every claim is graded. **verified** = exercised end-to-end against a real client or API in CI or by hand, with the date. **limited** = works with a stated caveat. **source-only** = implemented and unit-tested, not yet exercised against the real system. **design-only** = specified, no code.

Last updated: 2026-11-03 (Phase 2 drafting and sending deployed; first real draft-and-send from a Workspace alias confirmed in Sent; send-as status checked live on every connected mailbox).

| Capability | Grade | Notes |
|---|---|---|
| OAuth 2.1 layer (PRM, CIMD, DCR fallback, PKCE, revocation) | **verified** 2026-11-03 | Claude (web) connected through Client ID Metadata Documents: discovery, consent page, code exchange, bearer calls. DCR, revocation and audience binding exercised in the Workers test runtime only |
| Google sign-in restricted to `ALLOWED_PRINCIPALS` | limited | The allowed-principal path is **verified live** (2026-11-03). The refusal of a non-allowlisted account is tested with a fake Google and in the Workers runtime, not yet with a real second Google account |
| Tenant file validated at boot, fail closed | source-only | Phase 0: strict validator (unknown keys, domains owned once, send-as inside tenant, lowercase only); a bad file makes every request 503 |
| `list_accounts` | **verified** 2026-11-03 | Returned the fixture tenants to Claude (web) and to a Claude Code session using the same connector |
| Delegation token minting (one service account per tenant) | source-only | Phase 1: RS256 assertion signed with the tenant's key (read from the Cloudflare secret the tenant file names, imported non-extractable), exchanged at Google's token endpoint through the egress wrapper, cached per mailbox in memory. Tested against a fake Google in Node and in workerd. **Verified 2026-11-03** against two separate real Workspace tenants, each with its own service account and key |
| `list_labels` | **verified** 2026-11-03 | Called from Claude on one real mailbox in each of two tenants; each call used its own tenant's key and wrote a metadata-only audit record |
| `search_threads`, `get_thread`, `get_message` | source-only | Phase 1: every tool takes `account`, echoes `tenant` and `account`, refuses unknown accounts, bounds pages (25) and bodies (20k chars per message, 80k per thread, cuts flagged), strips HTML, lists attachments by metadata only, and turns every Gmail or credential failure into a loud error. Tested over MCP against a fake Gmail; not yet against a Workspace tenant |
| Drafts: create / update / get / list / delete | limited | `create_draft` **verified** 2026-11-03 on a real Workspace mailbox from an alias; update, get, list and delete tested against a fake Gmail only. Phase 2: RFC 5322 messages built by the server (RFC 2047 headers, base64 bodies, optional HTML alternative), header injection refused, addresses validated, recipients (50) and sizes bounded; replies join the original thread with sanitised In-Reply-To/References, and only from the mailbox that received the message. Tested over MCP against a fake Gmail |
| Send-as verification (Gmail list + allowlist) | **verified** 2026-11-03 | `check_send_as` run live on five real mailboxes: accepted, pending and unlisted aliases each reported correctly. Phase 2: the From must be on the mailbox's operator list AND in Gmail's "Send mail as" list as primary, `accepted`, or a Workspace alias on the company's own domains; `pending` and unlisted addresses are refused with the fix. Checked at draft time and again at send time. `check_send_as` reports the status of every allowed address |
| `send_draft` with three-state confirmation | **verified** 2026-11-03 | One real send from a Workspace alias, approved by the human, returned `sent_confirmed` and arrived. The `sent_unconfirmed` and `failed` paths are tested against a fake Gmail only. Phase 2: `sent_confirmed` only after reading the message back with the SENT label (a rewritten From is flagged); `sent_unconfirmed` when Gmail probably sent but it could not be confirmed (do not resend); `failed` only when nothing was sent (4xx, or the draft is provably still in Drafts). A durable ledger in the Durable Object refuses a second send of the same draft. Tested against a fake Gmail, including ambiguous server errors |
| Labels, archive, trash / untrash | design-only | Phase 2 |
| Content-free audit log | limited | Phase 1 writes one metadata-only record per tool call (tool, outcome, tenant, account, ids, error code, principal, client, duration) to the Worker log stream. The KV/D1 sink with 90-day retention and `wrangler` export is Phase 3 |
| Rate limits, bounded pages, egress gate | limited | Bounded page and body sizes and the egress gate (code + CI grep) are in. Per-token rate limits are Phase 3 |
| Claude web connector | **verified** 2026-11-03 | Custom connector added by URL, CIMD registration, Google sign-in, tools listed and called |
| Claude desktop / iPhone | design-only | Same connector; not yet opened on those apps |
| Claude Code | limited | Reached through the claude.ai connector (2026-11-03); the direct `claude mcp add` path with a loopback redirect not yet exercised |
| ChatGPT custom MCP server | design-only | Phase 4 |
| Codex | design-only | Phase 4 |

## Enforcement pinned by mutation tests

Account allowlist (registry) · account allowlist at the tool layer · principal allowlist at authorisation · principal allowlist on every MCP call · https-only public origin · tenant unknown-key rejection · send-as domain guard · consent-page form-action · egress redirect mode (Workers runtime) · egress redirect refusal · expired store rows · egress host allowlist · id_token signature · HTML stripping · Gmail errors never read as empty · send-as operator list · send-as pending refused · send-as missing in Gmail refused · From re-checked at send time · sent-draft ledger · SENT-label confirmation · ambiguous-send probe · header injection. Each guard is removed in turn by `npm run test:mutation`; the suite must fail every time.

## Does not

Direct send (only approved drafts are sent) · forward · cross-tenant operations · attachment upload or download · permanent delete · settings or filter changes · non-Google mail · multiple principals.
