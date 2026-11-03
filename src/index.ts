import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import { AUDIT_RETENTION_DAYS, auditFor, purgeAudit } from "./audit.js";
import { requireBindings } from "./bindings.js";
import { ConfigError, getConfig } from "./config.js";
import { handleMcp, type ResourceContext } from "./mcp/handler.js";
import { GOOGLE_EGRESS, createEgressFetch } from "./net/egress.js";
import { DurableRateLimiter } from "./guard/ratelimit.js";
import { screenClientIds } from "./oauth/client-policy.js";
import { createDefaultHandler, type HandlerEnv } from "./oauth/handlers.js";
import { buildProviderOptions } from "./oauth/options.js";
import { withConsistentStore, type ProviderEnv } from "./store/env.js";

export { OAuthStore } from "./store/oauth-store.js";

const egressFetch = createEgressFetch(GOOGLE_EGRESS);
const pages = createDefaultHandler({ fetch: egressFetch, audit: (env) => auditFor(env as { readonly AUDIT_DB?: D1Database }) });

/** One provider per public origin (per isolate). The resource URL is part of the provider's configuration, so it cannot be built before env is known. */
const providers = new Map<string, OAuthProvider<ProviderEnv>>();
function providerFor(env: ProviderEnv): OAuthProvider<ProviderEnv> {
  const cfg = getConfig(env);
  let p = providers.get(cfg.mcpResource);
  if (p === undefined) {
    p = new OAuthProvider<ProviderEnv>(
      buildProviderOptions<ProviderEnv>(cfg, {
        api: { fetch: (request, e, ctx) => handleMcp(request, e, ctx as ResourceContext) },
        pages: { fetch: (request, e) => pages.fetch(request, e as unknown as HandlerEnv) },
      }),
    );
    providers.set(cfg.mcpResource, p);
  }
  return p;
}

export default {
  async fetch(request, env, ctx): Promise<Response> {
    try {
      requireBindings(env);
      const refused = await screen(request, env);
      if (refused !== undefined) return refused;
      const storeEnv = withConsistentStore(env);
      return await providerFor(storeEnv).fetch(request, storeEnv, ctx);
    } catch (e) {
      if (e instanceof ConfigError) {
        // Rule 6: loud, and never an empty success. Issues name variables and JSON paths, never values.
        console.error(JSON.stringify({ config_error: e.issues }));
        return new Response("Service misconfigured; see Worker logs.", { status: 503, headers: { "cache-control": "no-store" } });
      }
      throw e;
    }
  },

  /** Daily (wrangler.jsonc triggers): enforce the audit retention period. */
  async scheduled(_controller, env, ctx): Promise<void> {
    ctx.waitUntil(runRetention(env));
  },
} satisfies ExportedHandler<Env>;

function oauthRefusal(status: number, error: string, description: string, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify({ error, error_description: description }), { status, headers: { "content-type": "application/json", "cache-control": "no-store", ...extra } });
}

/**
 * Before the OAuth library sees a request: client ids naming a metadata document must be on an allowed host, and
 * registrations are limited per source address. Refusals are audited by code only (the values are attacker-chosen).
 */
async function screen(request: Request, env: Env): Promise<Response | undefined> {
  const cfg = getConfig(env);
  const audit = auditFor(env);
  const result = await screenClientIds(request, cfg.clients.metadataHosts);
  if (result === "body_too_large") return oauthRefusal(413, "invalid_request", "Request body too large.");
  if (result === "client_host_not_allowed") {
    await audit.record({ tool: "oauth", outcome: "refused", errorCode: "client_host_not_allowed" });
    return oauthRefusal(400, "invalid_client", "This server accepts client metadata documents only from supported clients.");
  }
  if (request.method === "POST" && new URL(request.url).pathname === "/oauth/register") {
    const source = request.headers.get("cf-connecting-ip") ?? "unknown";
    const rate = await new DurableRateLimiter(env.OAUTH_STORE).hit(`register:${source}`, cfg.clients.registerPerHour, 3600);
    if (!rate.allowed) {
      await audit.record({ tool: "oauth", outcome: "refused", errorCode: "register_rate_limited" });
      return oauthRefusal(429, "invalid_request", `Too many client registrations from this address. Retry in ${rate.retryAfterSeconds} s.`, { "retry-after": String(rate.retryAfterSeconds) });
    }
  }
  return undefined;
}

export async function runRetention(env: Env, nowMs: number = Date.now()): Promise<number> {
  requireBindings(env);
  const deleted = await purgeAudit(env.AUDIT_DB, nowMs);
  console.log(JSON.stringify({ audit_retention: { deleted, keepDays: AUDIT_RETENTION_DAYS } }));
  return deleted;
}
