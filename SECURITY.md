# Security

## Reporting

Use GitHub's **private vulnerability reporting** on this repository (Security tab → Report a vulnerability) with a description and reproduction. Please do not open a public issue for a vulnerability. We acknowledge within three working days.

## Threat model (summary)

| Threat | Control |
|---|---|
| Leaked service-account key | One key per tenant, held only in Cloudflare secrets; single `gmail.modify` scope (no direct `messages.send`, no settings writes); documented rotation; **residual risk: every mailbox in that tenant is exposed with `gmail.modify` reach** |
| Leaked client access token | Short-lived access tokens bound to this server as audience (RFC 8707); refresh tokens rotate; revocation endpoint |
| Unauthorised principal | Upstream identity is Sign in with Google (`openid email`); only emails in `ALLOWED_PRINCIPALS` receive a token; everyone else gets 403 |
| Prompt injection through email bodies | Bodies are returned as untrusted data; HTML stripped; every tool description warns the model; no tool can act on content without a human-approved draft |
| Cross-tenant leakage | Every tool acts on exactly one `account`; `from` and reply references from another tenant are refused; the limit (two-call copy by the model) is documented, not hidden |
| Send-as spoofing | `from` must be in Gmail's Send-as list for that mailbox **and** in the operator allowlist; unverified aliases refused; Gmail's silent rewrite to the primary address is therefore unreachable |
| Duplicate send | Three-state send outcome; a retried `send_draft` on a sent draft returns an explicit error |
| Log leakage | Telemetry is content-free by construction (metadata only) |
| Dependency compromise | Pinned lockfile, CI audit, egress limited in code to Google OAuth and Gmail hosts with a CI grep for anything else |

## Enforcement is tested

A mutation suite disables each guard in turn (account allowlist, send-as check, cross-tenant guard, send verification, three-state outcome). Each mutation must make the test suite fail. A green suite with a guard removed is itself a failing build.

## Status

Phase 0. No real tenant is connected until an independent security review signs off.
