/**
 * Everything on the Worker that is not /mcp and not an OAuth protocol endpoint:
 * the consent page, the hand-off to Google, the Google callback, a health check and a root page.
 */
import { AuthorizationError, authorizationErrorRedirect, type OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import type { Audit } from "../audit.js";
import { GOOGLE_AUTHORIZATION_ENDPOINT, GoogleJwks, SignInError, beginGoogleSignIn, completeGoogleSignIn } from "../auth/google.js";
import { isAllowedPrincipal } from "../auth/principals.js";
import { getConfig, type ConfigEnv } from "../config.js";
import { EgressDeniedError, type FetchLike } from "../net/egress.js";
import { escapeHtml, page } from "./html.js";

export type HandlerEnv = ConfigEnv & { readonly OAUTH_PROVIDER: OAuthHelpers };

/** Where "Continue with Google" lands after the consent POST; must be allowed by the page's form-action. */
const GOOGLE_SIGN_IN_ORIGIN = new URL(GOOGLE_AUTHORIZATION_ENDPOINT).origin;

interface UpstreamData {
  readonly codeVerifier: string;
  readonly nonce: string;
}

export interface DefaultHandlerDeps {
  readonly fetch: FetchLike;
  readonly audit: Audit;
  readonly now?: () => number;
}

export function createDefaultHandler(deps: DefaultHandlerDeps): { fetch(request: Request, env: HandlerEnv): Promise<Response> } {
  const now = deps.now ?? (() => Date.now());
  const jwks = new GoogleJwks(deps.fetch, now);

  async function authorizeGet(request: Request, env: HandlerEnv): Promise<Response> {
    const oauth = env.OAUTH_PROVIDER;
    let authRequest;
    try {
      authRequest = await oauth.parseAuthRequest(request);
    } catch (e) {
      if (e instanceof AuthorizationError) return e.redirectTo !== undefined ? Response.redirect(e.redirectTo, 302) : page("Invalid request", `<h1>Invalid authorization request</h1><p>${escapeHtml(e.description)}</p>`, 400);
      throw e;
    }
    const client = await oauth.lookupClient(authRequest.clientId);
    if (client === null) return page("Unknown client", "<h1>Unknown client</h1><p>This client is not registered with this server.</p>", 400);
    const desc = await oauth.describeConsent(authRequest);
    const consent = await oauth.beginConsent(authRequest);
    const body = `
<h1>Connect a client to multimail-mcp</h1>
<p>A client is asking for access to your mailboxes through this server. If you did not start this from your own assistant, choose <strong>Deny</strong>.</p>
<dl>
  <dt>Client</dt><dd>${escapeHtml(desc.clientName)}${desc.clientUri ? ` &middot; <code>${escapeHtml(desc.clientUri)}</code>` : ""}</dd>
  <dt>Returns to</dt><dd><code>${escapeHtml(desc.redirectHost)}</code>${desc.redirectIsLoopback ? " (an app on your own computer)" : ""}</dd>
  <dt>Scope</dt><dd><code>${escapeHtml(desc.scope.join(" ") || "(default)")}</code></dd>
</dl>
<p class="warn">Approving continues to Google sign-in. Only an allow-listed Google account can finish; everyone else is refused.</p>
<form method="post" action="/authorize">
  <input type="hidden" name="handle" value="${escapeHtml(consent.handle)}">
  <button class="primary" name="decision" value="approve">Continue with Google</button>
  <button name="decision" value="deny">Deny</button>
</form>`;
    let clientOrigin: string | undefined;
    try {
      const o = new URL(desc.redirectUri).origin;
      if (o !== "null") clientOrigin = o;
    } catch {
      clientOrigin = undefined;
    }
    const formActions = [GOOGLE_SIGN_IN_ORIGIN, ...(clientOrigin !== undefined ? [clientOrigin] : [])];
    return page("Connect a client", body, 200, consent.headers, { formActions });
  }

  async function authorizePost(request: Request, env: HandlerEnv): Promise<Response> {
    const oauth = env.OAUTH_PROVIDER;
    const cfg = getConfig(env);
    const form = await request.formData();
    const handle = form.get("handle");
    const decision = form.get("decision");
    if (typeof handle !== "string" || handle.length === 0) return page("Invalid request", "<h1>Missing consent handle</h1>", 400);
    if (decision === "deny") {
      let denied;
      try {
        denied = await oauth.denyConsent(request, handle, { description: "The user denied access" });
      } catch (e) {
        if (e instanceof AuthorizationError) return page("Consent expired", `<h1>This consent step is no longer valid</h1><p>${escapeHtml(e.description)}</p>`, 400);
        throw e;
      }
      denied.headers.set("location", denied.redirectTo);
      return new Response(null, { status: 302, headers: denied.headers });
    }
    if (decision !== "approve") return page("Invalid request", "<h1>Unknown decision</h1>", 400);
    let approved;
    try {
      approved = await oauth.approveConsent(request, handle);
    } catch (e) {
      if (e instanceof AuthorizationError) return page("Consent expired", `<h1>This consent step is no longer valid</h1><p>${escapeHtml(e.description)}</p>`, 400);
      throw e;
    }
    const draft = await beginGoogleSignIn(cfg.google); // fresh nonce + PKCE verifier; state is replaced by the library's
    const upstream = await oauth.beginUpstream(approved.request, { data: { codeVerifier: draft.codeVerifier, nonce: draft.nonce } satisfies UpstreamData, headers: approved.headers });
    const google = await beginGoogleSignIn(cfg.google, { state: upstream.state });
    // Re-use the first draft's verifier/nonce (stored upstream) by rebuilding the URL with them:
    const url = new URL(google.url);
    url.searchParams.set("nonce", draft.nonce);
    url.searchParams.set("code_challenge", await challengeOf(draft.codeVerifier));
    upstream.headers.set("location", url.toString());
    return new Response(null, { status: 302, headers: upstream.headers });
  }

  async function callback(request: Request, env: HandlerEnv): Promise<Response> {
    const oauth = env.OAUTH_PROVIDER;
    const cfg = getConfig(env);
    let resumed;
    try {
      resumed = await oauth.finishUpstream<UpstreamData>(request);
    } catch {
      return page("Sign-in expired", "<h1>Sign-in session expired</h1><p>Start the connection again from your client.</p>", 400);
    }
    const { request: original, data, headers } = resumed;
    const params = new URL(request.url).searchParams;
    const redirectWithError = (code: "access_denied" | "server_error", description: string): Response => {
      headers.set("location", authorizationErrorRedirect(original, code, description));
      return new Response(null, { status: 302, headers });
    };
    if (params.get("error") !== null) {
      await deps.audit.record({ tool: "authorize", outcome: "refused", errorCode: "google_denied", clientId: original.clientId });
      return redirectWithError("access_denied", "Google sign-in was cancelled");
    }
    const code = params.get("code");
    if (code === null || typeof data?.codeVerifier !== "string" || typeof data?.nonce !== "string") return redirectWithError("server_error", "missing code");

    let principal;
    try {
      principal = await completeGoogleSignIn(cfg.google, { code, codeVerifier: data.codeVerifier, nonce: data.nonce }, { fetch: deps.fetch, jwks, now });
    } catch (e) {
      const errorCode = e instanceof SignInError ? e.code : e instanceof EgressDeniedError ? "egress_denied" : "sign_in_failed";
      if (!(e instanceof SignInError)) {
        // Unexpected failure: log its type and the runtime's message (infrastructure text, never mail content).
        console.error(JSON.stringify({ sign_in_exception: e instanceof Error ? e.name : typeof e, detail: e instanceof Error ? e.message.slice(0, 200) : undefined }));
      }
      await deps.audit.record({ tool: "authorize", outcome: "error", errorCode, clientId: original.clientId });
      return redirectWithError("server_error", "Google sign-in could not be verified");
    }

    // The gate. Nothing below runs for anyone who is not on the allowlist.
    if (!isAllowedPrincipal(cfg.allowedPrincipals, principal.email)) {
      await deps.audit.record({ tool: "authorize", outcome: "refused", errorCode: "principal_not_allowed", principal: principal.email, clientId: original.clientId });
      return redirectWithError("access_denied", "This Google account is not allowed to use this server");
    }

    const { redirectTo } = await oauth.completeAuthorization({
      request: original,
      userId: principal.sub,
      metadata: { email: principal.email },
      scope: original.scope,
      props: { email: principal.email, sub: principal.sub },
    });
    await deps.audit.record({ tool: "authorize", outcome: "ok", principal: principal.email, clientId: original.clientId });
    headers.set("location", redirectTo);
    return new Response(null, { status: 302, headers });
  }

  return {
    async fetch(request: Request, env: HandlerEnv): Promise<Response> {
      const url = new URL(request.url);
      const path = url.pathname;
      if (path === "/authorize" && request.method === "GET") return authorizeGet(request, env);
      if (path === "/authorize" && request.method === "POST") return authorizePost(request, env);
      if (path === "/callback" && request.method === "GET") return callback(request, env);
      if (path === "/healthz") {
        getConfig(env); // throws ConfigError -> 503 at the top level
        return new Response("ok", { headers: { "cache-control": "no-store" } });
      }
      if (path === "/" && request.method === "GET") {
        return page(
          "multimail-mcp",
          `<h1>multimail-mcp</h1><p>A multi-tenant Gmail MCP server. Connect a client to <code>${escapeHtml(url.origin)}/mcp</code>. There is nothing to see here in a browser.</p>`,
        );
      }
      return new Response("Not found", { status: 404 });
    },
  };
}

async function challengeOf(verifier: string): Promise<string> {
  const { sha256b64url } = await import("../auth/encoding.js");
  return sha256b64url(verifier);
}
