/**
 * Rule 4: a From address must pass two independent checks before a draft is created or sent.
 *  1. It is on the operator's send-as list for that mailbox in the tenant file (which, by construction, only holds
 *     addresses on that tenant's domains: cross-tenant sending is impossible).
 *  2. Gmail itself lists it under "Send mail as" for that mailbox, and either it is the primary address, or its
 *     verification is `accepted`, or (Google documents `verificationStatus` as applying only to custom "from"
 *     aliases) it is unspecified and the address is on one of the tenant's own domains.
 * Gmail silently rewrites an unaccepted From to the primary address; these checks make that substitution unreachable.
 */
import type { GmailSendAs } from "./client.js";
import type { ResolvedMailbox } from "../tenants/registry.js";

export type SendAsRefusal = "send_as_not_allowed" | "send_as_not_in_gmail" | "send_as_pending" | "send_as_unverified";
export type GmailSendAsStatus = "primary" | "accepted" | "workspace_alias" | "pending" | "unverified" | "missing";

export class SendAsError extends Error {
  constructor(
    readonly code: SendAsRefusal,
    message: string,
  ) {
    super(message);
    this.name = "SendAsError";
  }
}

export interface SendAsDecision {
  readonly address: string;
  readonly allowlisted: boolean;
  readonly gmailStatus: GmailSendAsStatus;
  readonly usable: boolean;
  /** Gmail's display name for this address, when it has one; used in the From header. */
  readonly displayName?: string;
  readonly reason: string;
  readonly refusal?: SendAsRefusal;
}

function domainOf(address: string): string {
  return address.slice(address.lastIndexOf("@") + 1);
}

export function assessSendAs(target: ResolvedMailbox, address: string, gmail: readonly GmailSendAs[]): SendAsDecision {
  const mailbox = target.mailbox.address;
  const allowlisted = target.mailbox.sendAs.includes(address);
  const entry = gmail.find((e) => e.sendAsEmail.toLowerCase() === address);
  const displayName = entry?.displayName !== undefined && entry.displayName.trim() !== "" ? entry.displayName : undefined;
  const named = displayName !== undefined ? { displayName } : {};

  let gmailStatus: GmailSendAsStatus;
  if (entry === undefined) gmailStatus = "missing";
  else if (entry.isPrimary) gmailStatus = "primary";
  else if (entry.verificationStatus === "accepted") gmailStatus = "accepted";
  else if (entry.verificationStatus === "pending") gmailStatus = "pending";
  else if (target.tenant.domains.includes(domainOf(address))) gmailStatus = "workspace_alias";
  else gmailStatus = "unverified";

  if (!allowlisted) {
    return { address, allowlisted, gmailStatus, usable: false, refusal: "send_as_not_allowed", reason: `${address} is not on the send-as list for ${mailbox} (call list_accounts for the allowed addresses). Sending from another mailbox's or another company's address is refused.`, ...named };
  }
  switch (gmailStatus) {
    case "primary":
    case "accepted":
    case "workspace_alias":
      return { address, allowlisted, gmailStatus, usable: true, reason: "Allowed by the operator and accepted by Gmail.", ...named };
    case "missing":
      return { address, allowlisted, gmailStatus, usable: false, refusal: "send_as_not_in_gmail", reason: `Gmail does not list ${address} under "Send mail as" for ${mailbox}, so it would replace the From with the mailbox's own address. Fix it in Gmail, signed in as ${mailbox}: Settings, See all settings, Accounts, "Send mail as", Add another email address.`, ...named };
    case "pending":
      return { address, allowlisted, gmailStatus, usable: false, refusal: "send_as_pending", reason: `Gmail lists ${address} for ${mailbox} but its verification is still pending. Complete the verification in Gmail first.`, ...named };
    default:
      return { address, allowlisted, gmailStatus, usable: false, refusal: "send_as_unverified", reason: `Gmail has not verified ${address} for ${mailbox} and it is not on one of this company's domains.`, ...named };
  }
}

/** Throws SendAsError unless both checks pass. */
export function requireSendAs(target: ResolvedMailbox, address: string, gmail: readonly GmailSendAs[]): SendAsDecision {
  const d = assessSendAs(target, address, gmail);
  if (!d.usable) throw new SendAsError(d.refusal ?? "send_as_unverified", d.reason);
  return d;
}
