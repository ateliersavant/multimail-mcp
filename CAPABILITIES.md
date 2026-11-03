# Capabilities

Every claim is graded. **verified** = exercised end-to-end against a real client or API in CI or by hand, with the date. **limited** = works with a stated caveat. **source-only** = implemented and unit-tested, not yet exercised against the real system. **design-only** = specified, no code.

Last updated: 2026-11-03 (Phase 0 accepted: deployed on workers.dev, first real client connected).

| Capability | Grade | Notes |
|---|---|---|
| OAuth 2.1 layer (PRM, CIMD, DCR fallback, PKCE, revocation) | **verified** 2026-11-03 | Claude (web) connected through Client ID Metadata Documents: discovery, consent page, code exchange, bearer calls. DCR, revocation and audience binding exercised in the Workers test runtime only |
| Google sign-in restricted to `ALLOWED_PRINCIPALS` | limited | The allowed-principal path is **verified live** (2026-11-03). The refusal of a non-allowlisted account is tested with a fake Google and in the Workers runtime, not yet with a real second Google account |
| Tenant file validated at boot, fail closed | source-only | Phase 0: strict validator (unknown keys, domains owned once, send-as inside tenant, lowercase only); a bad file makes every request 503 |
| `list_accounts` | **verified** 2026-11-03 | Returned the fixture tenants to Claude (web) and to a Claude Code session using the same connector |
| Delegation token minting (one service account per tenant) | design-only | Phase 1 |
| `search_threads`, `get_thread`, `get_message`, `list_labels` | design-only | Phase 1 |
| Drafts: create / update / get / list / delete | design-only | Phase 2 |
| Send-as verification (Gmail list + allowlist) | design-only | Phase 2 |
| `send_draft` with three-state confirmation | design-only | Phase 2 |
| Labels, archive, trash / untrash | design-only | Phase 2 |
| Content-free audit log | design-only | Phase 3 |
| Rate limits, bounded pages, egress gate | design-only | Phase 3 |
| Claude web connector | **verified** 2026-11-03 | Custom connector added by URL, CIMD registration, Google sign-in, tools listed and called |
| Claude desktop / iPhone | design-only | Same connector; not yet opened on those apps |
| Claude Code | limited | Reached through the claude.ai connector (2026-11-03); the direct `claude mcp add` path with a loopback redirect not yet exercised |
| ChatGPT custom MCP server | design-only | Phase 4 |
| Codex | design-only | Phase 4 |

## Enforcement pinned by mutation tests

Account allowlist · principal allowlist at authorisation · principal allowlist on every MCP call · https-only public origin · tenant unknown-key rejection · send-as domain guard · consent-page form-action · egress redirect mode (Workers runtime) · egress redirect refusal · expired store rows · egress host allowlist · id_token signature. Each guard is removed in turn by `npm run test:mutation`; the suite must fail every time.

## Does not

Direct send · forward · cross-tenant operations · attachment upload or download · permanent delete · settings or filter changes · non-Google mail · multiple principals.
