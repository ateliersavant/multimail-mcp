/**
 * Fail-closed configuration (rule 6). Every secret and setting is checked at first use; any issue
 * stops the Worker from serving anything. Issues name variables, never values.
 */
import type { GoogleSignInConfig } from "./auth/google.js";
import { PrincipalConfigError, parseAllowedPrincipals } from "./auth/principals.js";
import { parseLimit } from "./guard/ratelimit.js";
import { DEFAULT_METADATA_HOSTS, DEFAULT_REDIRECT_HOSTS, DEFAULT_REGISTER_PER_HOUR, parseHostList, type ClientPolicy } from "./oauth/client-policy.js";
import { TenantConfigError, TenantRegistry, loadTenantConfig } from "./tenants/index.js";

/** Bindings and secrets the Worker expects. Secrets are set with `wrangler secret put`, never in wrangler.jsonc. */
export interface ConfigEnv {
  /** Public https origin of this Worker (scheme + host only): no path, no trailing slash. */
  readonly PUBLIC_URL?: string;
  /** Secret: the full tenant file as JSON text. */
  readonly TENANTS_JSON?: string;
  /** Secret: comma-separated lowercase emails allowed to authorise clients. */
  readonly ALLOWED_PRINCIPALS?: string;
  /** Secret: Google OAuth web client for the sign-in layer (scopes openid email). */
  readonly GOOGLE_CLIENT_ID?: string;
  readonly GOOGLE_CLIENT_SECRET?: string;
  /** Optional: extra hosts (comma-separated) allowed to serve Client ID Metadata Documents, on top of the defaults. */
  readonly CLIENT_METADATA_HOSTS?: string;
  /** Optional: extra https redirect hosts (comma-separated) allowed at client registration, on top of the defaults and loopback. */
  readonly CLIENT_REDIRECT_HOSTS?: string;
  /** Optional: client registrations per source address per hour (default 10). */
  readonly REGISTER_RATE_LIMIT_PER_HOUR?: string;
}

export interface AppConfig {
  readonly publicUrl: URL;
  /** Canonical MCP resource identifier (RFC 8707): `${PUBLIC_URL}/mcp`. */
  readonly mcpResource: string;
  readonly registry: TenantRegistry;
  readonly allowedPrincipals: ReadonlySet<string>;
  readonly google: GoogleSignInConfig;
  readonly clients: ClientPolicy;
}

export class ConfigError extends Error {
  readonly issues: readonly string[];
  constructor(issues: readonly string[]) {
    super(`Refusing to start: ${issues.length} configuration issue${issues.length === 1 ? "" : "s"}:\n- ${issues.join("\n- ")}`);
    this.name = "ConfigError";
    this.issues = issues;
  }
}

function nonEmpty(env: ConfigEnv, key: keyof ConfigEnv, issues: string[]): string | undefined {
  const v = env[key];
  if (typeof v !== "string" || v.trim().length === 0) {
    issues.push(`${key}: missing (set it with \`wrangler secret put ${key}\`)`);
    return undefined;
  }
  return v;
}

export function parsePublicUrl(raw: string): URL {
  const u = new URL(raw);
  const isLocal = u.hostname === "localhost" || u.hostname === "127.0.0.1";
  if (u.protocol !== "https:" && !(u.protocol === "http:" && isLocal)) throw new Error("must be https (http only for localhost)");
  if (u.pathname !== "/" || u.search !== "" || u.hash !== "" || u.username !== "" || u.password !== "") throw new Error("must be a bare origin with no path, query, fragment or credentials");
  return u;
}

export function loadConfig(env: ConfigEnv): AppConfig {
  const issues: string[] = [];
  let publicUrl: URL | undefined;
  const rawUrl = nonEmpty(env, "PUBLIC_URL", issues);
  if (rawUrl !== undefined) {
    try {
      publicUrl = parsePublicUrl(rawUrl);
    } catch (e) {
      issues.push(`PUBLIC_URL: ${e instanceof Error ? e.message : "invalid"}`);
    }
  }

  let registry: TenantRegistry | undefined;
  const tenantsJson = nonEmpty(env, "TENANTS_JSON", issues);
  if (tenantsJson !== undefined) {
    try {
      registry = new TenantRegistry(loadTenantConfig(tenantsJson));
    } catch (e) {
      if (e instanceof TenantConfigError) issues.push(...e.issues.map((i) => `TENANTS_JSON ${i}`));
      else issues.push("TENANTS_JSON: unreadable");
    }
  }

  let allowedPrincipals: ReadonlySet<string> | undefined;
  try {
    allowedPrincipals = parseAllowedPrincipals(env.ALLOWED_PRINCIPALS);
  } catch (e) {
    issues.push(e instanceof PrincipalConfigError ? e.message : "ALLOWED_PRINCIPALS: invalid");
  }

  const clientId = nonEmpty(env, "GOOGLE_CLIENT_ID", issues);
  const clientSecret = nonEmpty(env, "GOOGLE_CLIENT_SECRET", issues);

  const metadataHosts = parseHostList(DEFAULT_METADATA_HOSTS, env.CLIENT_METADATA_HOSTS, "CLIENT_METADATA_HOSTS");
  if (typeof metadataHosts === "string") issues.push(metadataHosts);
  const redirectHosts = parseHostList(DEFAULT_REDIRECT_HOSTS, env.CLIENT_REDIRECT_HOSTS, "CLIENT_REDIRECT_HOSTS");
  if (typeof redirectHosts === "string") issues.push(redirectHosts);

  if (issues.length > 0 || typeof metadataHosts === "string" || typeof redirectHosts === "string" || publicUrl === undefined || registry === undefined || allowedPrincipals === undefined || clientId === undefined || clientSecret === undefined) {
    throw new ConfigError(issues);
  }
  const origin = publicUrl.origin;
  return {
    publicUrl,
    mcpResource: `${origin}/mcp`,
    registry,
    allowedPrincipals,
    google: { clientId, clientSecret, redirectUri: `${origin}/callback` },
    clients: { metadataHosts, redirectHosts, registerPerHour: parseLimit(env.REGISTER_RATE_LIMIT_PER_HOUR, DEFAULT_REGISTER_PER_HOUR, 1, 1000) },
  };
}

/** One parse per isolate per env object; a ConfigError is NOT cached so a fixed secret takes effect on the next request. */
const cache = new WeakMap<object, AppConfig>();
export function getConfig(env: ConfigEnv): AppConfig {
  const hit = cache.get(env);
  if (hit !== undefined) return hit;
  const cfg = loadConfig(env);
  cache.set(env, cfg);
  return cfg;
}
