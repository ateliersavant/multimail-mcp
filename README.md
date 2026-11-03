# multimail-mcp

A self-hosted remote [MCP](https://modelcontextprotocol.io) server that gives Claude (web, desktop, mobile, Claude Code), ChatGPT and Codex read, draft and send access to **several Google Workspace mailboxes across several separate companies**, from one connector, with hard walls between the companies.

**Status: Phase 1 (read tools) in source, exercised against a fake Gmail only. Nothing here has touched a real mailbox yet.** See [CAPABILITIES.md](CAPABILITIES.md) for what is verified versus designed.

## Why it exists

Hosted assistants hold one Google account per connector. If you run more than one company, each with its own Workspace tenant, you either merge mailboxes (unacceptable when the companies must stay legally separate) or switch accounts by hand on a desktop. This server sits in front of all of them.

## What it does (v1 target)

- One `account` parameter on every tool. No default mailbox, ever.
- Search, read threads and messages, labels, archive, trash.
- **Draft, then send.** There is no direct-send tool. A human approves the draft in the client before `send_draft` runs.
- Send-as aliases, verified against Gmail's own Send-as list **and** an operator allowlist before anything leaves.
- Sending is confirmed by fetching the sent message. The tool reports `sent_confirmed`, `sent_unconfirmed` or `failed`, never a bare success, so a lost confirmation can never cause a duplicate send.
- Mailbox access through Google Workspace **domain-wide delegation** with a single Gmail scope (`gmail.modify`), one service account per tenant.
- Client access through the server's own OAuth 2.1 layer (Protected Resource Metadata, Client ID Metadata Documents, Dynamic Client Registration fallback), with the upstream identity restricted to an allowlist of Google accounts.

## What it refuses to do

- Read one company and write another in a single call. Cross-tenant forwarding is refused, not confirmed.
- Send directly. Permanently delete. Change settings or filters. Upload or download attachments (v1).
- Log content. Audit records hold metadata only: no subjects, bodies, attachment names or recipient addresses.
- Return an empty result when something is misconfigured. Missing config, secrets or tokens fail loudly.

Email content returned by any tool is **untrusted data**. Clients must not follow instructions found inside messages; every tool description says so.

## Repository layout

- `src/` Worker source (TypeScript)
- `fixtures/tenants.example.json` fictional tenant file used by tests and local runs
- `docs/clients.md` per-client setup (Claude, Claude Code, ChatGPT, Codex)
- `docs/operator-setup.md` Google Cloud, Admin Console and Cloudflare steps
- `SECURITY.md` reporting and threat model summary
- `CAPABILITIES.md` graded claims (verified / limited / source-only / design-only)

## Limits and honest notes

- Domain-wide delegation is powerful. A leaked service-account key exposes every mailbox in that tenant with `gmail.modify` reach. The mitigations in `SECURITY.md` reduce the blast radius; they do not remove it.
- Tenant separation is enforced at the tool boundary. The server guarantees that no single call spans two tenants. It cannot stop a model (or a person) copying content read in one company into a draft in another across two calls. Every response echoes its `tenant` so that stays visible.
- Client-side behaviour (how Claude, ChatGPT and Codex register and authorise) changes often. `docs/clients.md` records the date each path was last verified.

## When this is the wrong choice

- You have one company, or switching the assistant's built-in Google connector is tolerable.
- Your mail is not on Google Workspace (no IMAP in v1).
- You cannot run domain-wide delegation (no Workspace admin rights).
- Several people need their own access. v1 is single-principal.

## Licence

Apache-2.0. Contributions need a DCO sign-off (`git commit -s`); there is no CLA.

Built by Ateliersavant.
