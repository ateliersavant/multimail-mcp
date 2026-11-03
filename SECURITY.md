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

## Repository safeguards

- Secret scanning with push protection, Dependabot alerts and security updates, and private vulnerability reporting are enabled.
- `main` is protected: the `verify` and `secrets` checks are required, force pushes and deletion are blocked, history is linear.
- GitHub Actions may run only GitHub-owned actions, with a read-only token; workflows from forks wait for maintainer approval.
- CI scans the full git history with a pinned, checksum-verified gitleaks on every push, and checks the tree against a private denylist of real company names (held as an encrypted repository secret, reported as file and line only).
- Nothing in this repository can deploy or configure a running server: deployments are made by the operator with their own Cloudflare credentials, which never touch GitHub.

## Enforcement is tested

A mutation suite disables each guard in turn (account allowlist in the registry and at the tool layer, HTML stripping, Gmail errors read as empty, the egress and principal gates; from Phase 2 the send-as check, cross-tenant guard, send verification and three-state outcome). Each mutation must make the test suite fail. A green suite with a guard removed is itself a failing build.

## Status

Phase 1 (read tools) in source, tested against a fake Gmail. No real tenant is connected until an independent security review signs off.
