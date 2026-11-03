# Client setup

The MCP endpoint is always `https://<host>/mcp`, where `<host>` is the Worker's public hostname.

Each client below has two kinds of evidence. **Live** means the whole path, Google sign-in included, was exercised against the running server on the date given. **Replayed** means the client's real, published Client ID Metadata Document (fetched 2026-11-03, kept in `test/fixtures/client-metadata/`) is run through the Worker in the test suite (`test/worker/clients.test.ts`) and reaches the consent page; the live sign-in has not been done yet. Vendors change these flows often. If a step fails, check their current docs before assuming a server bug.

## How clients authorise (all of them)

1. The client calls `/mcp` without a token and receives `401` with a `WWW-Authenticate` header naming the scope `mail` and pointing at `https://<host>/.well-known/oauth-protected-resource/mcp`.
2. It reads the authorization-server metadata and identifies itself with a **Client ID Metadata Document**: its `client_id` is the URL of a JSON document it publishes. The server accepts these documents only from the supported clients' hosts (`claude.ai`, `claude.com`, `chatgpt.com`). Dynamic Client Registration is the fallback, and only accepts redirects to those hosts or to loopback.
3. It starts an OAuth 2.1 code flow with PKCE and `resource=https://<host>/mcp`. The server shows a consent page naming the client and where it returns, then hands you to **Sign in with Google**.
4. Only an allow-listed Google account that is managed by the company's own Google Workspace receives a token. Anyone else is refused.
5. The client stores the access and refresh tokens and calls `/mcp` with `Authorization: Bearer`.

The server returns RFC 9207 `iss` in every authorization response, so ChatGPT and Codex use their stable callbacks rather than per-connection ones.

## Claude (web, desktop, iPhone and Android): live 2026-11-03 (web)

1. Settings → Connectors → **Add custom connector**.
2. Name `multimail`, URL `https://<host>/mcp`. Leave client id and secret empty: Claude identifies itself.
3. Connect → Google sign-in → allow.
4. In a conversation, enable the connector and ask Claude to call `list_accounts`.

| | |
|---|---|
| Metadata document | `https://claude.ai/oauth/mcp-oauth-client-metadata` |
| Callback | `https://claude.ai/api/mcp/auth_callback` |
| Client authentication | none (public client, PKCE) |

Claude keeps the tool list it fetched when the connector was connected. After the server gains or changes tools, open Settings → Connectors → this connector, choose **Disconnect** then **Connect**, and start a new conversation. On Team and Enterprise plans an Owner adds the connector for the workspace.

## Claude Code: replayed

```bash
claude mcp add --transport http multimail https://<host>/mcp
```

Then run `/mcp` inside Claude Code, choose `multimail`, and complete the Google sign-in in the browser.

| | |
|---|---|
| Metadata document | `https://claude.ai/oauth/claude-code-client-metadata` |
| Callback | `http://localhost/callback` or `http://127.0.0.1/callback`, on whatever port Claude Code listens on |
| Client authentication | none |

## ChatGPT (web): replayed

1. **Plugins → + → Add custom MCP server** (earlier UI: Settings → Apps & Connectors, in developer mode).
2. URL `https://<host>/mcp`, authentication OAuth. Leave client id and secret empty.
3. Complete the Google sign-in.

| | |
|---|---|
| Metadata document | `https://chatgpt.com/oauth/client.json` |
| Callback | `https://chatgpt.com/connector_platform_oauth_redirect` |
| Client authentication | `private_key_jwt`: ChatGPT signs a client assertion with keys published at `https://chatgpt.com/oauth/jwks.json`, which the server fetches to verify it |

ChatGPT asks for confirmation before every tool that changes something; that is expected.

## Codex (CLI, IDE extension, desktop app): replayed

```bash
codex mcp add multimail --url https://<host>/mcp
```

```bash
codex mcp login multimail
```

All three Codex surfaces share this configuration (`~/.codex/config.toml`). On a machine without a browser, add `--no-browser` to the login and paste the final redirect URL back into the terminal.

| | |
|---|---|
| Metadata document | `https://chatgpt.com/oauth/codex/client.json` |
| Callback | `http://127.0.0.1/callback` or `http://localhost/callback`, on a random port |
| Client authentication | none |

## A client that is not listed

A client whose metadata document is on another host, or that registers with a redirect to another host, is refused with `invalid_client` or `invalid_redirect_uri`. If you trust it, the operator adds its host (runbook section 11).

## Revoking a client

Disconnect it in the client. To cut it off at the server at once, use the runbook: the emergency stop (section 1) refuses every call within seconds, and section 4 revokes every token. Removing a connector in the client does not by itself revoke its tokens; refresh tokens expire after 7 days without use and 30 days at most.
