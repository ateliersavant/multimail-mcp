import { createMcpHandler, type AuthInfo, type McpHttpHandler } from "@modelcontextprotocol/server";
import type { OAuthResourceAuth } from "@cloudflare/workers-oauth-provider";
import { auditFor } from "../audit.js";
import { isAllowedPrincipal } from "../auth/principals.js";
import { getConfig, type ConfigEnv } from "../config.js";
import { GmailClient } from "../gmail/client.js";
import { DelegationTokenSource } from "../gmail/delegation.js";
import { DurableSendLedger } from "../gmail/ledger.js";
import { DEFAULT_LIMITS, DurableRateLimiter, parseLimit, type Limits } from "../guard/ratelimit.js";
import type { OAuthStore } from "../store/oauth-store.js";
import { GOOGLE_EGRESS, createEgressFetch } from "../net/egress.js";
import { buildMcpServer, type McpServerDeps } from "./server.js";

/** What completeAuthorization stored in the grant; decrypted into ctx.props by the OAuth host. */
export interface TokenProps {
  readonly email: string;
  readonly sub: string;
}

export function isTokenProps(v: unknown): v is TokenProps {
  return typeof v === "object" && v !== null && typeof (v as { email?: unknown }).email === "string" && typeof (v as { sub?: unknown }).sub === "string";
}

/** The execution context the OAuth host hands to the protected API handler. */
export type ResourceContext = ExecutionContext & { readonly props?: unknown; readonly auth?: OAuthResourceAuth };

/** The only fetch the mailbox layer gets: host and path allowlisted, redirects refused. */
const egressFetch = createEgressFetch(GOOGLE_EGRESS);
const handlers = new WeakMap<object, McpHttpHandler>();
const depsCache = new WeakMap<object, McpServerDeps & { readonly limits: Limits }>();

/** What the Worker actually passes here: config strings plus the store-backed OAUTH_KV, the store and the audit database. */
type McpEnv = ConfigEnv & {
  readonly OAUTH_KV?: KVNamespace;
  readonly OAUTH_STORE?: DurableObjectNamespace<OAuthStore>;
  readonly AUDIT_DB?: D1Database;
  /** Optional override of the per-client request limit (tests use a small value). */
  readonly MCP_RATE_LIMIT_PER_MINUTE?: string;
};

/** Per isolate per env: the delegation token cache lives here, so tokens are reused across requests and die with the isolate. */
function depsFor(env: McpEnv): McpServerDeps & { readonly limits: Limits } {
  const hit = depsCache.get(env);
  if (hit !== undefined) return hit;
  const tokens = new DelegationTokenSource({ secrets: env as Readonly<Record<string, unknown>>, fetch: egressFetch });
  const limits: Limits = { ...DEFAULT_LIMITS, mcpPerMinute: parseLimit(env.MCP_RATE_LIMIT_PER_MINUTE, DEFAULT_LIMITS.mcpPerMinute, 5, 10_000) };
  // The send ledger and the rate limiter both live in the strongly consistent OAuth Durable Object. If it is ever
  // absent, send_draft refuses to send (fail closed); the Worker entry refuses to start without it anyway.
  const deps = {
    gmail: new GmailClient({ fetch: egressFetch, tokens }),
    audit: auditFor(env),
    limits,
    ...(env.OAUTH_STORE !== undefined ? { ledger: new DurableSendLedger(env.OAUTH_STORE), rateLimiter: new DurableRateLimiter(env.OAUTH_STORE) } : {}),
  };
  depsCache.set(env, deps);
  return deps;
}

function handlerFor(env: McpEnv): McpHttpHandler {
  const cached = handlers.get(env);
  if (cached !== undefined) return cached;
  const cfg = getConfig(env);
  const deps = depsFor(env);
  const handler = createMcpHandler(
    (ctx) => {
      const principal = ctx.authInfo?.extra?.["principal"];
      const clientId = ctx.authInfo?.clientId;
      // Fail closed: the HTTP layer always sets these; if they are missing something upstream is wrong.
      if (typeof principal !== "string" || typeof clientId !== "string") throw new Error("MCP request without an authenticated identity");
      return buildMcpServer(cfg, { principal, clientId }, deps);
    },
    { onerror: (e) => console.error(JSON.stringify({ mcp_error: e.name })) },
  );
  handlers.set(env, handler);
  return handler;
}

/** `/mcp`: only reachable through the OAuth host, which has already validated the bearer token and its audience. */
export async function handleMcp(request: Request, env: McpEnv, ctx: ResourceContext): Promise<Response> {
  const cfg = getConfig(env);
  const deps = depsFor(env);
  const auth = ctx.auth;
  const props = ctx.props;
  if (auth === undefined || !isTokenProps(props)) return new Response("Unauthorized", { status: 401 });

  // The principal allowlist is re-checked on every call, so removing an address revokes access immediately.
  if (!isAllowedPrincipal(cfg.allowedPrincipals, props.email)) {
    await deps.audit.record({ tool: "mcp", outcome: "refused", errorCode: "principal_not_allowed", principal: props.email, clientId: auth.clientId });
    return new Response("Forbidden", { status: 403 });
  }

  // Per client token (principal + OAuth client): a runaway or hijacked client cannot hammer the mailboxes.
  if (deps.rateLimiter === undefined) return new Response("Service misconfigured; see Worker logs.", { status: 503 });
  const rate = await deps.rateLimiter.hit(`mcp:${props.email}:${auth.clientId ?? "unknown"}`, deps.limits.mcpPerMinute, 60);
  if (!rate.allowed) {
    await deps.audit.record({ tool: "mcp", outcome: "refused", errorCode: "rate_limited", principal: props.email, clientId: auth.clientId });
    const message = `Rate limit: at most ${deps.limits.mcpPerMinute} requests per minute for this client. Retry in ${rate.retryAfterSeconds} s. Nothing was done.`;
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32029, message } }), { status: 429, headers: { "content-type": "application/json", "retry-after": String(rate.retryAfterSeconds) } });
  }

  const authInfo: AuthInfo = {
    token: auth.token,
    clientId: auth.clientId ?? "unknown",
    scopes: auth.scope,
    resource: new URL(cfg.mcpResource),
    extra: { principal: props.email, sub: props.sub },
    ...(auth.expiresAt !== undefined ? { expiresAt: auth.expiresAt } : {}),
  };
  return handlerFor(env).fetch(request, { authInfo });
}
