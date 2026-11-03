# Capabilities

Every claim is graded. **verified** = exercised end-to-end against a real client or API in CI or by hand, with the date. **limited** = works with a stated caveat. **source-only** = implemented and unit-tested, not yet exercised against the real system. **design-only** = specified, no code.

Last updated: 2026-11-03 (Phase 1 read tools deployed; domain-wide delegation verified against two real Google Workspace tenants with `list_labels`; search and read not yet exercised on real mail).

| Capability | Grade | Notes |
|---|---|---|
| OAuth 2.1 layer (PRM, CIMD, DCR fallback, PKCE, revocation) | **verified** 2026-11-03 | Claude (web) connected through Client ID Metadata Documents: discovery, consent page, code exchange, bearer calls. DCR, revocation and audience binding exercised in the Workers test runtime only |
| Google sign-in restricted to `ALLOWED_PRINCIPALS` | limited | The allowed-principal path is **verified live** (2026-11-03). The refusal of a non-allowlisted account is tested with a fake Google and in the Workers runtime, not yet with a real second Google account |
| Tenant file validated at boot, fail closed | source-only | Phase 0: strict validator (unknown keys, domains owned once, send-as inside tenant, lowercase only); a bad file makes every request 503 |
| `list_accounts` | **verified** 2026-11-03 | Returned the fixture tenants to Claude (web) and to a Claude Code session using the same connector |
| Delegation token minting (one service account per tenant) | source-only | Phase 1: RS256 assertion signed with the tenant's key (read from the Cloudflare secret the tenant file names, imported non-extractable), exchanged at Google's token endpoint through the egress wrapper, cached per mailbox in memory. Tested against a fake Google in Node and in workerd. **Verified 2026-11-03** against two separate real Workspace tenants, each with its own service account and key |
| `list_labels` | **verified** 2026-11-03 | Called from Claude on one real mailbox in each of two tenants; each call used its own tenant's key and wrote a metadata-only audit record |
| `search_threads`, `get_thread`, `get_message` | source-only | Phase 1: every tool takes `account`, echoes `tenant` and `account`, refuses unknown accounts, bounds pages (25) and bodies (20k chars per message, 80k per thread, cuts flagged), strips HTML, lists attachments by metadata only, and turns every Gmail or credential failure into a loud error. Tested over MCP against a fake Gmail; not yet against a Workspace tenant |
| Drafts: create / update / get / list / delete | design-only | Phase 2 |
| Send-as verification (Gmail list + allowlist) | design-only | Phase 2 |
| `send_draft` with three-state confirmation | design-only | Phase 2 |
| Labels, archive, trash / untrash | design-only | Phase 2 |
| Content-free audit log | limited | Phase 1 writes one metadata-only record per tool call (tool, outcome, tenant, account, ids, error code, principal, client, duration) to the Worker log stream. The KV/D1 sink with 90-day retention and `wrangler` export is Phase 3 |
| Rate limits, bounded pages, egress gate | limited | Bounded page and body sizes and the egress gate (code + CI grep) are in. Per-token rate limits are Phase 3 |
| Claude web connector | **verified** 2026-11-03 | Custom connector added by URL, CIMD registration, Google sign-in, tools listed and called |
| Claude desktop / iPhone | design-only | Same connector; not yet opened on those apps |
| Claude Code | limited | Reached through the claude.ai connector (2026-11-03); the direct `claude mcp add` path with a loopback redirect not yet exercised |
| ChatGPT custom MCP server | design-only | Phase 4 |
| Codex | design-only | Phase 4 |

## Enforcement pinned by mutation tests

Account allowlist (registry) · account allowlist at the tool layer · principal allowlist at authorisation · principal allowlist on every MCP call · https-only public origin · tenant unknown-key rejection · send-as domain guard · consent-page form-action · egress redirect mode (Workers runtime) · egress redirect refusal · expired store rows · egress host allowlist · id_token signature · HTML stripping · Gmail errors never read as empty. Each guard is removed in turn by `npm run test:mutation`; the suite must fail every time.

## Does not

Direct send · forward · cross-tenant operations · attachment upload or download · permanent delete · settings or filter changes · non-Google mail · multiple principals.
