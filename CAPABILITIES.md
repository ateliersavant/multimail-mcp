# Capabilities

Every claim is graded. **verified** = exercised end-to-end against a real client or API in CI or by hand, with the date. **limited** = works with a stated caveat. **source-only** = implemented and unit-tested, not yet exercised against the real system. **design-only** = specified, no code.

Last updated: 2026-11-03 (Phase 0 scaffold complete in source; nothing deployed or exercised by a real client yet).

| Capability | Grade | Notes |
|---|---|---|
| OAuth 2.1 layer (PRM, CIMD, DCR fallback, PKCE, revocation) | source-only | Phase 0: discovery documents, 401 challenge, DCR registration, consent page, token exchange and audience binding exercised in the Workers test runtime (2026-11-03); not yet exercised by a real client |
| Google sign-in restricted to `ALLOWED_PRINCIPALS` | source-only | Phase 0: id_token verification (RS256, iss, aud, exp, nonce, email_verified) and the allowlist gate unit-tested with a fake Google; the live Google round-trip awaits the OAuth client (operator step 4) |
| Tenant file validated at boot, fail closed | source-only | Phase 0: strict validator (unknown keys, domains owned once, send-as inside tenant, lowercase only); a bad file makes every request 503 |
| `list_accounts` | source-only | Phase 0: called over Streamable HTTP with a real token in the Workers test runtime; output carries no secret names |
| Delegation token minting (one service account per tenant) | design-only | Phase 1 |
| `search_threads`, `get_thread`, `get_message`, `list_labels` | design-only | Phase 1 |
| Drafts: create / update / get / list / delete | design-only | Phase 2 |
| Send-as verification (Gmail list + allowlist) | design-only | Phase 2 |
| `send_draft` with three-state confirmation | design-only | Phase 2 |
| Labels, archive, trash / untrash | design-only | Phase 2 |
| Content-free audit log | design-only | Phase 3 |
| Rate limits, bounded pages, egress gate | design-only | Phase 3 |
| Claude web / desktop / mobile connector | design-only | Phase 0 acceptance: needs the deployed Worker plus the Google OAuth client |
| Claude Code | design-only | Phase 0 acceptance: CIMD path with loopback redirect |
| ChatGPT custom MCP server | design-only | Phase 4 |
| Codex | design-only | Phase 4 |

## Enforcement pinned by mutation tests

Account allowlist · principal allowlist at authorisation · principal allowlist on every MCP call · https-only public origin · tenant unknown-key rejection · send-as domain guard · egress host allowlist · id_token signature. Each guard is removed in turn by `npm run test:mutation`; the suite must fail every time.

## Does not

Direct send · forward · cross-tenant operations · attachment upload or download · permanent delete · settings or filter changes · non-Google mail · multiple principals.
