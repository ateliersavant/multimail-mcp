import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import { Audit, ConsoleAuditSink } from "./audit.js";
import { ConfigError, getConfig } from "./config.js";
import { handleMcp, type ResourceContext } from "./mcp/handler.js";
import { GOOGLE_EGRESS, createEgressFetch } from "./net/egress.js";
import { createDefaultHandler, type HandlerEnv } from "./oauth/handlers.js";
import { buildProviderOptions } from "./oauth/options.js";
import { withConsistentStore, type ProviderEnv } from "./store/env.js";

export { OAuthStore } from "./store/oauth-store.js";

const egressFetch = createEgressFetch(GOOGLE_EGRESS);
const pages = createDefaultHandler({ fetch: egressFetch, audit: new Audit(new ConsoleAuditSink()) });

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
} satisfies ExportedHandler<Env>;
