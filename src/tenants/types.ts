/** A mailbox the server may act on, and the From addresses it may use. */
export interface Mailbox {
  /** Primary address of the Gmail mailbox (the user impersonated under delegation). */
  readonly address: string;
  /**
   * Operator allowlist of From addresses for this mailbox. Must contain `address`.
   * This is the SECOND allowlist: Gmail's own Send-as list is checked at send time as well.
   */
  readonly sendAs: readonly string[];
}

/** One Google Workspace tenant (one company). */
export interface Tenant {
  readonly id: string;
  readonly label: string;
  /** Every domain (primary, secondary, alias) that belongs to this Workspace tenant. */
  readonly domains: readonly string[];
  /** NAME of the Cloudflare secret that holds this tenant's service-account JSON key. Never the key. */
  readonly serviceAccountSecret: string;
  readonly mailboxes: readonly Mailbox[];
}

export interface TenantConfig {
  readonly tenants: readonly Tenant[];
}

/** What list_accounts returns: no secret names. */
export interface PublicTenant {
  readonly id: string;
  readonly label: string;
  readonly domains: readonly string[];
  readonly mailboxes: readonly { readonly address: string; readonly sendAs: readonly string[] }[];
}
