# Threat model (one page)

Scope: the Worker, its OAuth layer, its Durable Object state, the Google credentials it holds, and the clients that call it. Out of scope: Google's own infrastructure, the end user's device, and the clients' internal security.

## Assets

1. Service-account JSON keys (one per tenant) — the crown jewels: each grants `gmail.modify` over every mailbox in its tenant.
2. Client access and refresh tokens issued by this server.
3. The principal allowlist and the tenant file (which mailboxes exist, which aliases may send).
4. Mail content in transit through the Worker (never stored, never logged).
5. The audit log (metadata only).

## Threats and controls

| # | Threat | Likelihood | Impact | Controls | Residual |
|---|---|---|---|---|---|
| T1 | Service-account key leaks (repo, laptop, Cloudflare account) | low | **critical** | Keys only in Cloudflare secrets; never on disk after upload; one key per tenant; single scope `gmail.modify`; key-creation org policy respected; rotation runbook; gitleaks in CI and on history before any publication | A leaked key still reads and sends (via draft) across the tenant until rotated. Stated in SECURITY.md. |
| T2 | Client token theft or replay | medium | high | Access tokens short-lived and audience-bound (RFC 8707) to this server; refresh tokens rotate; revocation endpoint; tokens never in URLs | A stolen live access token works until expiry. |
| T3 | Unauthorised person authorises a client | medium | high | Upstream identity is Google sign-in; principal must be in `ALLOWED_PRINCIPALS` (checked on every authorisation, `email_verified` required, `hd`/domain checked); otherwise 403 and no token | None beyond Google account compromise of an allowed principal. |
| T4 | Prompt injection in an email body makes the model act | **high** | high | Bodies returned as untrusted text, HTML stripped, no attachment fetch; every tool description warns the model; no tool can send without a human-approved draft; no forwarding; no cross-tenant writes; telemetry content-free | The model can still *draft* bad content; the human approval step is the control. |
| T5 | Cross-tenant leakage | low | **critical** | Every tool takes one `account`; tenant resolved from config only; `from` and reply references outside the tenant refused; domains cannot belong to two tenants (validated at boot); each tenant has its own service account | A model may copy content across two calls. Visible through the `tenant` echo; not preventable server-side. |
| T6 | Send-as spoofing | low | high | `from` must be in Gmail's Send-as list for that mailbox **and** in the operator allowlist; `pending` refused; Workspace-managed aliases accepted only on tenant domains | Relies on Gmail reporting `verificationStatus` correctly; confirmed in Phase 2. |
| T7 | Duplicate send after a lost confirmation | medium | medium | Three-state outcome; `sent_unconfirmed` carries the message id and a do-not-resend instruction; a resent draft id returns an explicit error | None if clients surface the instruction; mutation-tested. |
| T8 | Log or audit leakage | medium | high | Audit module accepts a closed field set; content keys cannot be written; error codes are short enums; Workers logs carry the same records | Cloudflare account compromise exposes metadata (who mailed whom-count, when). |
| T9 | Dependency or build compromise | low | high | Lockfile pinned; `npm ci`; egress allowlist in code and CI grep; redirects refused; minimal dependency set | A compromised dependency that stays inside the egress allowlist could still misuse Gmail. |
| T10 | Denial of service / quota exhaustion | medium | low | Per-token rate limits; bounded page sizes and body sizes; fail closed on quota errors (never an empty "no mail") | Availability only. |
| T11 | Configuration error (wrong mailbox, typo in alias) | medium | medium | Tenant file validated at boot with unknown-key rejection; refuses to start on any issue; `check:tenants` before deploy | None material. |

## Trust boundaries

- Browser ↔ Worker (sign-in, OAuth redirects): TLS, PKCE, `state`, RFC 9207 `iss`.
- Client ↔ Worker (`/mcp`): bearer tokens, audience validation.
- Worker ↔ Google: service-account JWT assertions minted per request (short-lived), Gmail API over TLS, egress allowlist.
- Operator ↔ Cloudflare: account security is out of scope but decisive for T1 and T8; enable 2FA and restrict API tokens.

## What would change this model

Adding a second principal (multi-user), attachment handling, or a direct-send tool would each reopen T3, T4 and T6 respectively and require a new review.
