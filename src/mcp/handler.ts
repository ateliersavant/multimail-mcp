import { createMcpHandler, type AuthInfo, type McpHttpHandler } from "@modelcontextprotocol/server";
import type { OAuthResourceAuth } from "@cloudflare/workers-oauth-provider";
import { Audit, ConsoleAuditSink } from "../audit.js";
import { isAllowedPrincipal } from "../auth/principals.js";
import { getConfig, type ConfigEnv } from "../config.js";
import { GmailClient } from "../gmail/client.js";
import { DelegationTokenSource } from "../gmail/delegation.js";
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

const audit = new Audit(new ConsoleAuditSink());
/** The only fetch the mailbox layer gets: host and path allowlisted, redirects refused. */
const egressFetch = createEgressFetch(GOOGLE_EGRESS);
const handlers = new WeakMap<object, McpHttpHandler>();

/** Per isolate per env: the delegation token cache lives here, so tokens are reused across requests and die with the isolate. */
function depsFor(env: ConfigEnv): McpServerDeps {
  const tokens = new DelegationTokenSource({ secrets: env as Readonly<Record<string, unknown>>, fetch: egressFetch });
  return { gmail: new GmailClient({ fetch: egressFetch, tokens }), audit };
}

function handlerFor(env: ConfigEnv): McpHttpHandler {
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
export async function handleMcp(request: Request, env: ConfigEnv, ctx: ResourceContext): Promise<Response> {
  const cfg = getConfig(env);
  const auth = ctx.auth;
  const props = ctx.props;
  if (auth === undefined || !isTokenProps(props)) return new Response("Unauthorized", { status: 401 });

  // The principal allowlist is re-checked on every call, so removing an address revokes access immediately.
  if (!isAllowedPrincipal(cfg.allowedPrincipals, props.email)) {
    await audit.record({ tool: "mcp", outcome: "refused", errorCode: "principal_not_allowed", principal: props.email, clientId: auth.clientId });
    return new Response("Forbidden", { status: 403 });
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
