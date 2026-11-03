import type { Mailbox, PublicTenant, Tenant, TenantConfig } from "./types.js";

/** Rule 1: an unknown or unlisted account is refused. */
export class UnknownAccountError extends Error {
  constructor(account: string) {
    super(`Unknown account "${account}". Only configured mailboxes may be used; call list_accounts to see them.`);
    this.name = "UnknownAccountError";
  }
}

export interface ResolvedMailbox {
  readonly tenant: Tenant;
  readonly mailbox: Mailbox;
}

/**
 * Read-only index over a validated TenantConfig. Every tool resolves its `account`
 * through `requireMailbox`; nothing else may look up tenants.
 */
export class TenantRegistry {
  private readonly byAddress: ReadonlyMap<string, ResolvedMailbox>;
  readonly tenants: readonly Tenant[];

  constructor(config: TenantConfig) {
    const map = new Map<string, ResolvedMailbox>();
    for (const tenant of config.tenants) {
      for (const mailbox of tenant.mailboxes) map.set(mailbox.address, { tenant, mailbox });
    }
    this.byAddress = map;
    this.tenants = config.tenants;
  }

  /** Exact-match lookup. No trimming, no case folding: the config is lowercase by contract. */
  getMailbox(account: string): ResolvedMailbox | undefined {
    return this.byAddress.get(account);
  }

  requireMailbox(account: unknown): ResolvedMailbox {
    if (typeof account !== "string") throw new UnknownAccountError(String(account));
    const found = this.byAddress.get(account);
    if (!found) throw new UnknownAccountError(account);
    return found;
  }

  /** Operator allowlist check only. Gmail's own Send-as verification happens at send time in addition. */
  isAllowedSendAs(account: string, from: string): boolean {
    const found = this.byAddress.get(account);
    return found !== undefined && found.mailbox.sendAs.includes(from);
  }

  /** The list_accounts view: never includes secret names. */
  publicView(): readonly PublicTenant[] {
    return this.tenants.map((t) => ({
      id: t.id,
      label: t.label,
      domains: t.domains,
      mailboxes: t.mailboxes.map((m) => ({ address: m.address, sendAs: m.sendAs })),
    }));
  }
}
