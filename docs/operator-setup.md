# Operator setup

Everything a human must do outside the code, in order. Claude Code prepares and verifies; it never performs Admin Console or Google Cloud console steps and never asks for a Google password.

Conventions: `<TENANT>` is a tenant id from your tenant file in upper snake case (`EXAMPLE_STUDIO`), `<host>` is your Worker's public hostname.

## 0. Test tenant (before Phase 1)

A throwaway Google Workspace tenant carries all development. No real mail ever enters it.

1. Register a cheap new domain with no link to any real company (any registrar).
2. Sign up for Google Workspace on the lowest tier with **one** user (for example `ada@<test-domain>`), verify the domain with the TXT record the wizard gives you.
3. Add a **domain alias** in the Admin Console (Account → Domains → Manage domains → Add a domain → "User alias domain"). This is what lets Phase 2 confirm how Gmail reports `verificationStatus` for Workspace-managed aliases.
4. Create **two** service accounts for this tenant (step 2 below, twice) and authorise both (step 3). The server configures them as two logical tenants, `test-a` and `test-b`, which exercises every cross-tenant guard without a second subscription.
5. After launch, suspend the subscription rather than deleting it; it is the regression environment.

## 1. Google Cloud project

1. https://console.cloud.google.com → New project, name `multimail-mcp`. Put it in your organisation if you have one.
2. APIs & Services → Library → **Gmail API** → Enable.
3. **Key-creation policy check.** Organisations created on or after 3 May 2024 enforce `iam.managed.disableServiceAccountKeyCreation` by default, and step 2 below then fails. Sign in once and let Claude Code read the result:

```bash
gcloud auth login
```

```bash
gcloud organizations list --format='table(displayName,name,createTime)'
```

```bash
gcloud org-policies describe constraints/iam.managed.disableServiceAccountKeyCreation --project=<PROJECT_ID> --effective
```

   If it reports `enforce: true`, an Organization Policy Administrator applies a project-level exception:

```yaml
# policy.yaml
name: projects/<PROJECT_ID>/policies/iam.managed.disableServiceAccountKeyCreation
spec:
  rules:
    - enforce: false
```

```bash
gcloud org-policies set-policy policy.yaml
```

   Record the exception here with the date. Revisit it when Workload Identity Federation for domain-wide delegation becomes practical from Workers.

## 2. One service account per tenant

For each tenant (each real company, plus two for the test tenant):

1. IAM & Admin → Service Accounts → Create. Name `multimail-<tenant>`. **Grant no roles.** Domain-wide delegation needs none.
2. Open the service account → copy its **Unique ID** (a long number). This is the "Client ID" the Admin Console asks for.
3. Keys → Add key → Create new key → **JSON** → download.
4. Store it as a Cloudflare secret and delete the file in the same breath:

```bash
npx wrangler secret put SA_<TENANT> < ~/Downloads/<keyfile>.json && rm -P ~/Downloads/<keyfile>.json
```

   The tenant file refers to the secret by **name** (`"serviceAccountSecret": "SA_<TENANT>"`). The key itself exists only inside Cloudflare.

## 3. Domain-wide delegation (per Workspace tenant)

1. https://admin.google.com → Security → Access and data control → API controls → **Manage Domain Wide Delegation** → Add new.
2. Client ID: the service account's Unique ID from step 2.
3. OAuth scopes: exactly one line:

```
https://www.googleapis.com/auth/gmail.modify
```

4. Authorise. Repeat per tenant (a Workspace tenant that owns several domains needs only one authorisation).

Why one scope: `drafts.send` does not accept `gmail.send` (that scope only enables direct `messages.send`, which this server refuses to offer), and reading the Send-as list is already covered by `gmail.modify`. Fewer scopes, smaller blast radius.

## 4. OAuth client for the sign-in layer (needed for Phase 0 acceptance)

This is the identity check in front of the server: "is this Claude / ChatGPT / Codex session acting for an allowed person?" It has nothing to do with mailbox access.

1. In the same Google Cloud project: Google Auth Platform (APIs & Services → OAuth consent screen).
   - Audience / user type: **Internal**. This removes the verification audit and the 7-day testing expiry, and limits sign-in to your own Workspace.
   - App name `multimail-mcp`; support email yours.
   - Scopes: only `openid` and `email`.
2. Credentials → Create credentials → **OAuth client ID** → Web application.
   - Authorised redirect URIs: `https://<host>/callback` (and `http://localhost:8787/callback` for local development).
3. Copy the client ID and secret into Cloudflare:

```bash
npx wrangler secret put GOOGLE_CLIENT_ID
```

```bash
npx wrangler secret put GOOGLE_CLIENT_SECRET
```

4. Set the principal allowlist (comma-separated emails; usually one). It is a secret because it is a real address and must not sit in the repo:

```bash
npx wrangler secret put ALLOWED_PRINCIPALS
```

## 5. Cloudflare

1. One account. Log in once on this Mac:

```bash
npx wrangler login
```

2. A KV namespace for OAuth state (clients, grants, tokens). Give it a project-specific title; the binding inside the Worker is always `OAUTH_KV`, but **never share a namespace with another OAuth server on the same account** (each namespace holds that server's tokens and grants):

```bash
npx wrangler kv namespace create multimail-mcp-oauth
```

   Keep the returned id for `deploy.local.json` (step 3).
3. Custom hostname and KV id live in a git-ignored `deploy.local.json` next to `package.json`, so no real hostname ever enters the repository:

```json
{ "host": "<host>", "kvId": "<id printed by the kv namespace create command>" }
```

   `npm run deploy` runs the full verification (typecheck, tests, egress check, tenant check, mutation suite), merges that file into the committed `wrangler.jsonc`, and deploys with a custom domain route. The zone for `<host>` must be on this Cloudflare account; the first deploy creates the DNS record.
4. The public origin is a secret for the same reason (it is a real hostname):

```bash
npx wrangler secret put PUBLIC_URL
```

   Value: `https://<host>` exactly, no path and no trailing slash.
5. The tenant file is delivered as a secret so that no real address lives in the repository or the dashboard config:

```bash
npx wrangler secret put TENANTS_JSON < tenants.json
```

   `tenants.json` is git-ignored. Validate it locally first with `npm run check:tenants -- tenants.json`. A missing or invalid secret makes every request answer `503`; the Worker logs name the variable and the JSON path, never the value.

### Secrets checklist

| Secret | Set in step | Purpose |
|---|---|---|
| `PUBLIC_URL` | 5.4 | canonical origin; derives the MCP resource `…/mcp` and the Google redirect `…/callback` |
| `TENANTS_JSON` | 5.5 | tenant file |
| `ALLOWED_PRINCIPALS` | 4.4 | who may authorise clients |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | 4.3 | sign-in layer |
| `SA_<TENANT>` (one per tenant) | 2.4 | service-account keys (Phase 1 onwards) |

## 6. Rotation

- Service-account key: create a new key (step 2.3), `wrangler secret put` it, deploy, then delete the old key in Google Cloud. Order matters; the Worker must never hold a deleted key.
- Google OAuth client secret: rotate in Credentials, `wrangler secret put GOOGLE_CLIENT_SECRET`, deploy. Existing MCP tokens stay valid; only new sign-ins use the new secret.
- Revoke all client tokens: clear the OAuth KV namespace (documented command in `docs/runbook.md`, Phase 3).
- Any key used during development is rotated before the first real tenant is connected (handoff Phase 5).

## 7. GitHub

1. Create the repository privately and push `main`:

```bash
gh repo create <owner>/multimail-mcp --private --source . --remote origin --push
```

2. Settings → Code security: enable **Private vulnerability reporting** (SECURITY.md points reporters there) and **Secret scanning** with push protection.
3. Settings → Branches: protect `main` (require the `ci` workflow, no force pushes).
4. Before the repository is ever made public: `gitleaks git .` over the full history, and a last read of the tree for anything that names a real tenant.
