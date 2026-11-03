export type { Mailbox, PublicTenant, Tenant, TenantConfig } from "./types.js";
export { TenantConfigError, loadTenantConfig, parseTenantConfig, splitAddress } from "./validate.js";
export { TenantRegistry, UnknownAccountError } from "./registry.js";
