# Changelog

## Unreleased

- Phase 0 scaffold: Cloudflare Worker with an OAuth 2.1 layer (`@cloudflare/workers-oauth-provider` 1.2.4: Protected Resource Metadata, Client ID Metadata Documents, Dynamic Client Registration fallback, PKCE, RFC 9207 `iss`, revocation), Sign in with Google restricted to an allowlist, strict fail-closed tenant file, single egress allowlist with redirects refused, content-free audit records, and an MCP v2 server (`@modelcontextprotocol/server` 2.4.0) exposing `list_accounts`.
- Test suite: 76 tests across a Node project and a Workers-runtime project, plus a mutation suite that removes each guard in turn.
- Documentation: README, SECURITY, CAPABILITIES (graded), threat model, operator setup, client setup.
