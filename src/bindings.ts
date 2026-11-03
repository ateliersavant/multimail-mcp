import { ConfigError } from "./config.js";

/** Rule 6 for platform bindings: without the store or the audit database the Worker serves nothing (503), loudly. */
export function requireBindings(env: { readonly OAUTH_STORE?: unknown; readonly AUDIT_DB?: unknown }): void {
  const issues: string[] = [];
  if (env.OAUTH_STORE === undefined) issues.push("OAUTH_STORE: Durable Object binding missing (see wrangler.jsonc)");
  if (env.AUDIT_DB === undefined) issues.push("AUDIT_DB: D1 binding missing (see wrangler.jsonc); the audit log cannot be kept");
  if (issues.length > 0) throw new ConfigError(issues);
}
