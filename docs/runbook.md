# Runbook

What to do when something goes wrong, fastest first. Every command runs from the repository root on the operator's machine. `<host>`, `<project>`, `<sa-email>` and `<key-id>` are your own values; set them as shell variables first rather than typing them into a command.

## 1. Emergency stop: nobody can use the server (seconds)

Replace the principal allowlist with an address that cannot sign in. Every MCP call is refused with 403 at once (the allowlist is re-checked on every call) and no new sign-in can complete.

```bash
printf '%s' 'revoked@example.invalid' | npx wrangler secret put ALLOWED_PRINCIPALS
```

To restore, put the real address(es) back the same way. Nothing else changes; clients reconnect on their own.

## 2. Cut mailbox access for one company (minutes)

In that company's Google Admin Console, open Security, then Access and data control, then API controls, then **Manage Domain Wide Delegation**, and delete the entry for the service account's client ID. Google stops issuing delegated tokens for that company; tokens already minted expire within an hour. The other companies are unaffected.

## 3. A service-account key may have leaked

1. Revoke it in Google Cloud immediately:

```bash
gcloud iam service-accounts keys delete "$KEY_ID" --iam-account="$SA_EMAIL" --project="$PROJECT"
```

2. Create the replacement straight into Cloudflare (never shown, temp file shredded):

```bash
f=$(mktemp) && gcloud iam service-accounts keys create "$f" --iam-account="$SA_EMAIL" --project="$PROJECT" && npx wrangler secret put "$SECRET_NAME" < "$f"; rm -P "$f"
```

3. Confirm exactly one key remains:

```bash
gcloud iam service-accounts keys list --iam-account="$SA_EMAIL" --project="$PROJECT" --managed-by=user
```

4. Review what happened during the exposure window (section 6). Domain-wide delegation means the leaked key could reach every mailbox in that company, independently of this server.

## 4. Revoke every client session and token

Use when a client token may be stolen or a device is lost.

1. Emergency stop (section 1) first.
2. Move to a fresh store: change `STORE_NAME` in `src/store/consistent-kv.ts` (for example `oauth-v1` to `oauth-v2`), then deploy. Every registered client, grant, token and rate-limit window is left behind at once. The sent-draft ledger is reset too, which is safe: a sent draft no longer exists in Gmail.
3. Restore the allowlist, then reconnect each client (Claude, ChatGPT, Codex) and sign in again.

Single-client revocation through the OAuth revocation endpoint is also available to clients that support it.

## 5. Rotate the Google sign-in client secret

In Google Cloud, Credentials, open the OAuth client, add a new secret, then:

```bash
npx wrangler secret put GOOGLE_CLIENT_SECRET
```

Delete the old secret in Google Cloud after the next successful sign-in. Existing MCP tokens are unaffected.

## 6. Investigate: the audit log

Every tool call, authorisation and refusal is a metadata-only row in the D1 database `multimail-mcp-audit` (no subjects, bodies or recipient addresses). Rows are kept 90 days; a daily scheduled job deletes older ones.

```bash
npm run audit:export -- --days 7
```

```bash
npm run audit:export -- --days 30 --format json
```

Useful filters on the CSV: `tool=send_draft` (every send with its draft, message, From and recipient count), `outcome=refused` with `error_code` (`principal_not_allowed`, `rate_limited`, `send_as_not_allowed`, `already_sent`…), and `principal`/`client_id` to follow one client. The live log stream carries the same records:

```bash
npx wrangler tail multimail-mcp --format json
```

## 7. Something sent that should not have

1. Emergency stop (section 1).
2. Find it: `npm run audit:export -- --days 2`, filter `tool=send_draft`, note `account`, `message_id`, `client_id`.
3. Look at the message in that mailbox's Sent folder. Gmail cannot unsend after delivery; follow up with the recipient.
4. If a client acted without human approval, disconnect it (section 4) and check that client's tool-approval settings before reconnecting.

## 8. Bad deploy

```bash
npx wrangler deployments list --name multimail-mcp
```

```bash
npx wrangler rollback --name multimail-mcp
```

`rollback` returns to the previous version (add a version id to choose one). Secrets and stored data are not touched.

## 9. Remove a mailbox or an alias

Edit the git-ignored `tenants.json`, validate, upload:

```bash
npm run check:tenants -- tenants.json
```

```bash
npx wrangler secret put TENANTS_JSON < tenants.json
```

The change applies to the next request. To cut a mailbox off at Google's side as well, use section 2 for that company.

## 10. Limits

| Limit | Default | Where |
|---|---|---|
| MCP requests per client token | 120 per minute | `src/guard/ratelimit.ts` (`MCP_RATE_LIMIT_PER_MINUTE` overrides, 5 to 10 000) |
| Drafts created or updated per principal | 120 per hour | `src/guard/ratelimit.ts` |
| Emails sent per principal, all mailboxes together | 20 per hour, 100 per day | `src/guard/ratelimit.ts` |
| Label, archive and Trash changes per principal | 300 per hour | `src/guard/ratelimit.ts` |
| Client registrations per source address | 10 per hour | `src/oauth/client-policy.ts` (`REGISTER_RATE_LIMIT_PER_HOUR` overrides, 1 to 1 000) |

A client over its limit gets HTTP 429 with `Retry-After`; an over-limit send is refused before Gmail is called and the draft stays unchanged. Every refusal is in the audit log as `rate_limited`.

## 11. A client cannot connect

The server accepts client metadata documents only from the supported clients' hosts (`claude.ai`, `claude.com`, `chatgpt.com`), and registrations only with redirects to those hosts or to loopback. A client outside that set fails with `invalid_client` or `invalid_redirect_uri`, and the audit log shows `client_host_not_allowed`. If the client is one you trust, add its host (host name only, comma-separated for several):

```bash
printf '%s' "$CLIENT_HOST" | npx wrangler secret put CLIENT_METADATA_HOSTS
```

```bash
printf '%s' "$CLIENT_HOST" | npx wrangler secret put CLIENT_REDIRECT_HOSTS
```

The first is for a client that identifies itself with a metadata document URL, the second for one that registers with a redirect on its own host. A bad entry stops the server with a configuration error naming the variable, so check the connection right after.
