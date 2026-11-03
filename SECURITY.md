# Security

## Reporting

Use GitHub's **private vulnerability reporting** on this repository (Security tab → Report a vulnerability) with a description and reproduction. Please do not open a public issue for a vulnerability. We acknowledge within three working days.

## Threat model (summary)

| Threat | Control |
|---|---|
| Leaked service-account key | One key per tenant, held only in Cloudflare secrets; single `gmail.modify` scope (no settings changes, no permanent deletion); documented rotation; **residual risk: every mailbox in that tenant is exposed with `gmail.modify` reach, which includes reading, sending directly and moving mail to Trash** |
| Leaked client access token | Short-lived access tokens bound to this server as audience (RFC 8707); refresh tokens rotate; revocation endpoint |
| Unauthorised principal | Upstream identity is Sign in with Google (`openid email`); only emails in `ALLOWED_PRINCIPALS` receive a token, and only from an account managed by that company's own Google Workspace (`hd`); everyone else is refused |
| Prompt injection through email bodies | Bodies are returned as untrusted data; HTML stripped; sender addresses parsed per RFC 5322 so a display name never hides the real address; every tool description warns the model; no tool can act on content without a human-approved draft; drafts are plain text only, so what the human approves is what recipients read |
| Cross-tenant leakage | Every tool acts on exactly one `account`; `from` and reply references from another tenant are refused; the limit (two-call copy by the model) is documented, not hidden |
| Send-as spoofing | `from` must be in Gmail's Send-as list for that mailbox **and** in the operator allowlist; unverified aliases refused; Gmail's silent rewrite to the primary address is therefore unreachable |
| Duplicate send | Three-state send outcome; `failed` only when provably nothing was sent; an atomic claim lets one send of a draft through at a time; a durable ledger refuses a second send of the same draft |
| Runaway or hijacked client | 120 requests per minute per client token; 20 sends per hour and 100 per day per principal; 120 drafts per hour; counted atomically; every refusal audited |
| Sending without real approval | No direct send; only drafts the human was shown can be sent; sending limits; every send audited (see the threat model, T12) |
| Malicious or look-alike OAuth client | Client metadata documents are accepted only from the supported clients' hosts (the server never fetches one from anywhere else); open registration accepts only redirects to those hosts or to loopback, so an authorisation code cannot be sent to a stranger; registrations limited per source address |
| Log leakage | Telemetry is content-free by construction (metadata only); the durable audit table has no column that could hold content; 90-day retention |
| Dependency compromise | Pinned lockfile, CI audit, egress limited in code to the exact Google requests the server makes (method and path: no direct send, no trash, no label changes), redirects refused, a CI grep for any other host |

## Repository safeguards

- Secret scanning with push protection, Dependabot alerts and security updates, and private vulnerability reporting are enabled.
- `main` is protected: the `verify` and `secrets` checks are required, force pushes and deletion are blocked, history is linear.
- GitHub Actions may run only GitHub-owned actions, with a read-only token; workflows from forks wait for maintainer approval.
- CI scans the full git history with a pinned, checksum-verified gitleaks on every push, and checks the tree against a private denylist of real company names (held as an encrypted repository secret, reported as file and line only).
- Nothing in this repository can deploy or configure a running server: deployments are made by the operator with their own Cloudflare credentials, which never touch GitHub.

## Enforcement is tested

A mutation suite disables each guard in turn (account allowlist in the registry and at the tool layer, HTML stripping, Gmail errors read as empty, the egress host, method and path rules, the principal and Workspace-domain gates, the send-as checks at draft and send time, the single-From and Sender checks, the atomic send claim and the sent-draft ledger, SENT-label confirmation, the ambiguous-send probe, header injection, plain-text-only drafts, the client metadata and registration policies, the durable audit sink and its retention, and the request, sending and registration limits). Each mutation must make the test suite fail. A green suite with a guard removed is itself a failing build.

## Incident response

`docs/runbook.md`: emergency stop in seconds, cutting one company off, key and secret rotation, revoking every client token, audit export.

## Status

Reading, drafting and sending are deployed and in use. Phase 3 hardening is complete: durable audit log, rate limits, runbook, and an adversarial review whose nine confirmed findings are fixed and kept as regression tests (`docs/security-review.md`). An independent human security review follows.
