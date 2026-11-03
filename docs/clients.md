# Client setup

Each path below carries the date it was last **verified end-to-end** against this server. "unverified" means the steps come from the vendor's documentation as read on 2026-11-03 and have not yet been exercised here. Vendors change these flows often; if a step fails, check their current docs before assuming a server bug.

`<host>` is the Worker's public hostname. The MCP endpoint is always `https://<host>/mcp`.

## How clients authorise (all of them)

1. The client calls `/mcp` without a token and receives `401` with a `WWW-Authenticate` header pointing at `https://<host>/.well-known/oauth-protected-resource`.
2. It reads the authorization-server metadata, registers itself (Client ID Metadata Document first, Dynamic Client Registration as fallback, or a pre-registered client id) and starts an OAuth 2.1 code flow with PKCE and the `resource` parameter set to `https://<host>/mcp`.
3. The server redirects you to **Sign in with Google**. Only emails in the operator's allowlist receive a token; anyone else sees `403` and nothing else.
4. The client stores the access and refresh tokens and calls `/mcp` with `Authorization: Bearer`.

## Claude (web, desktop, iPhone / Android) — web verified 2026-11-03

1. Settings → Connectors → **Add custom connector**.
2. Name `multimail`, URL `https://<host>/mcp`. Leave client id/secret empty: Claude registers itself. (If your org requires fixed credentials, the operator can pre-register a client and give you its id/secret instead.)
3. Connect → Google sign-in → allow.
4. In a conversation, enable the connector and ask Claude to call `list_accounts`.

Claude's callback is `https://claude.ai/api/mcp/auth_callback`.

Claude keeps the tool list it fetched when the connector was connected. After the server gains tools (for example after an upgrade), open Settings, Connectors, this connector, and choose Disconnect then Connect; then start a new conversation. On Team/Enterprise plans an Owner adds the connector for the workspace.

## Claude Code — unverified

```bash
claude mcp add --transport http multimail https://<host>/mcp
```

Then inside Claude Code run `/mcp`, choose `multimail`, and complete the Google sign-in in the browser. Claude Code uses a Client ID Metadata Document that declares loopback redirect URIs; the server accepts `http://localhost/callback` and `http://127.0.0.1/callback` on any port.

## ChatGPT (web) — unverified

1. **Plugins → + → Add custom MCP server** (earlier UI: Settings → Apps & Connectors, in developer mode).
2. URL `https://<host>/mcp`, authentication OAuth.
3. Complete the Google sign-in.

ChatGPT prefers Client ID Metadata Documents and falls back to Dynamic Client Registration. Its redirect URI is `https://chatgpt.com/connector_platform_oauth_redirect` when the server emits RFC 9207 `iss` (this server does); otherwise it is a per-connection `https://chatgpt.com/connector/oauth/{callback_id}` shown on the server's management page. ChatGPT asks for confirmation before every write tool; that is expected.

## Codex (CLI, IDE extension, desktop app) — unverified

```bash
codex mcp add multimail --url https://<host>/mcp
```

```bash
codex mcp login multimail
```

All three Codex surfaces share this configuration. Codex selects Client ID Metadata Documents when the server advertises them, falls back to Dynamic Client Registration, or uses `--oauth-client-id` for a pre-registered client.

## Revoking a client

Sign out of the connector in the client, then (operator) revoke its tokens from the server's audit tooling. Removing the connector in the client does not by itself revoke tokens; the server's refresh tokens expire on their own schedule.
