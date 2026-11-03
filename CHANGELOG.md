# Changelog

## Unreleased

- Phase 0 scaffold: Cloudflare Worker with an OAuth 2.1 layer (`@cloudflare/workers-oauth-provider` 1.2.4: Protected Resource Metadata, Client ID Metadata Documents, Dynamic Client Registration fallback, PKCE, RFC 9207 `iss`, revocation), Sign in with Google restricted to an allowlist, strict fail-closed tenant file, single egress allowlist with redirects refused, content-free audit records, and an MCP v2 server (`@modelcontextprotocol/server` 2.4.0) exposing `list_accounts`.
- OAuth state in a Durable Object with SQLite storage (KV's cross-location lag refused a freshly issued code).
- Consent page `form-action` allows the Google hand-off and the client's origin; egress wrapper uses `redirect: "manual"` and refuses 3xx (the Workers runtime rejects `"error"`).
- Test suite: 85 tests across a Node project and a Workers-runtime project, plus a 12-mutation suite that removes each guard in turn.
- First real client (Claude web) connected on 2026-11-03.
- Documentation: README, SECURITY, CAPABILITIES (graded), threat model, operator setup, client setup.
