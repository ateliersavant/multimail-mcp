# Changelog

## Unreleased

- Phase 0 scaffold: Cloudflare Worker with an OAuth 2.1 layer (`@cloudflare/workers-oauth-provider` 1.2.4: Protected Resource Metadata, Client ID Metadata Documents, Dynamic Client Registration fallback, PKCE, RFC 9207 `iss`, revocation), Sign in with Google restricted to an allowlist, strict fail-closed tenant file, single egress allowlist with redirects refused, content-free audit records, and an MCP v2 server (`@modelcontextprotocol/server` 2.4.0) exposing `list_accounts`.
- OAuth state in a Durable Object with SQLite storage (KV's cross-location lag refused a freshly issued code).
- Consent page `form-action` allows the Google hand-off and the client's origin; egress wrapper uses `redirect: "manual"` and refuses 3xx (the Workers runtime rejects `"error"`).
- Test suite: a Node project and a Workers-runtime project, plus a mutation suite that removes each guard in turn (see CAPABILITIES.md for the current list).
- First real client (Claude web) connected on 2026-11-03.
- Phase 1 (read): domain-wide delegation token minting (RS256 assertion per mailbox, exchanged through the egress wrapper, cached in memory), tools `search_threads`, `get_thread`, `get_message`, `list_labels` (explicit `account`, `tenant` echoed, bounded pages and bodies, HTML stripped, attachments by metadata only, loud errors on any credential or Gmail failure), one content-free audit record per call, a fake Google/Gmail test double in both runtimes, and three more mutations (tool-layer account allowlist, HTML stripping, Gmail errors never empty). Not yet exercised against a Workspace tenant.
- Documentation: README, SECURITY, CAPABILITIES (graded), threat model, operator setup, client setup.
