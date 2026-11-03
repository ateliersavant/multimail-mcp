import type { OAuthProviderOptions } from "@cloudflare/workers-oauth-provider";
import type { AppConfig } from "../config.js";

export const SCOPE_MAIL = "mail";

export interface ProviderHandlers<Env> {
  readonly api: { fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> };
  readonly pages: { fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> };
}

/** The OAuth 2.1 layer, built to the 2026-07-28 MCP authorization spec. See handoff §3 and docs/threat-model.md. */
export function buildProviderOptions<Env>(cfg: AppConfig, handlers: ProviderHandlers<Env>): OAuthProviderOptions<Env> {
  return {
    apiRoute: "/mcp",
    apiHandler: handlers.api,
    defaultHandler: handlers.pages,
    authorizeEndpoint: "/authorize",
    tokenEndpoint: "/oauth/token", // also RFC 7009 revocation
    clientRegistrationEndpoint: "/oauth/register", // Dynamic Client Registration: fallback for clients without CIMD
    clientIdMetadataDocumentEnabled: true, // Client ID Metadata Documents: what Claude, ChatGPT and Codex try first
    scopesSupported: [SCOPE_MAIL, "offline_access"],
    requiredScopes: [SCOPE_MAIL],
    resourceMetadata: {
      resource: cfg.mcpResource, // RFC 8707 audience; exact match enforced by the library
      authorization_servers: [cfg.publicUrl.origin],
      resource_name: "multimail-mcp",
    },
    accessTokenTTL: 60 * 60, // 1 h
    refreshTokenTTL: 30 * 24 * 60 * 60, // 30 d hard cap
    refreshTokenIdleTTL: 7 * 24 * 60 * 60, // 7 d without use
    clientRegistrationTTL: 90 * 24 * 60 * 60,
    onError: ({ code, status }) => {
      console.warn(JSON.stringify({ oauth_error: code, status })); // content-free
    },
  };
}
