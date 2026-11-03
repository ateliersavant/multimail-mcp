import { beforeAll, describe, expect, it, vi } from "vitest";
import { env as workerEnv } from "cloudflare:workers";
import type { AuthRequest, ClientInfo, ConsentDescription, OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import { AuthorizationError } from "@cloudflare/workers-oauth-provider";
import { Audit, type AuditRecord, type AuditSink } from "../../src/audit.js";
import { b64urlEncode, sha256b64url, utf8 } from "../../src/auth/encoding.js";
import { createDefaultHandler, type HandlerEnv } from "../../src/oauth/handlers.js";

const tenants = workerEnv.TENANTS_JSON;
const CLIENT_ID = "test-client-id.apps.googleusercontent.com";
const NOW = Date.UTC(2026, 10, 3, 12, 0, 0);
const KID = "k1";
let privateKey: CryptoKey;
let jwkPublic: JsonWebKey & { kid?: string };

beforeAll(async () => {
  const pair = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  privateKey = pair.privateKey;
  jwkPublic = await crypto.subtle.exportKey("jwk", pair.publicKey);
});

async function idTokenFor(email: string, nonce: string): Promise<string> {
  const nowSec = Math.floor(NOW / 1000);
  const header = b64urlEncode(utf8(JSON.stringify({ alg: "RS256", kid: KID, typ: "JWT" })));
  const payload = b64urlEncode(utf8(JSON.stringify({ iss: "https://accounts.google.com", aud: CLIENT_ID, sub: `sub-${email}`, email, email_verified: true, iat: nowSec - 5, exp: nowSec + 3600, nonce })));
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, privateKey, utf8(`${header}.${payload}`)));
  return `${header}.${payload}.${b64urlEncode(sig)}`;
}

const authRequest: AuthRequest = {
  responseType: "code",
  clientId: "client-1",
  redirectUri: "https://client.example.test/cb",
  scope: ["mail"],
  state: "state-1",
  codeChallenge: "c",
  codeChallengeMethod: "S256",
  resource: "https://mcp.example.test/mcp",
  issuer: "https://mcp.example.test",
};
const clientInfo: ClientInfo = { clientId: "client-1", redirectUris: [authRequest.redirectUri], clientName: "Evil <script>alert(1)</script> Client", clientUri: "https://client.example.test", tokenEndpointAuthMethod: "none" };
const consentDescription: ConsentDescription = { clientId: "client-1", clientName: clientInfo.clientName ?? "", clientUri: "https://client.example.test", redirectUri: authRequest.redirectUri, redirectHost: "client.example.test", redirectIsLoopback: false, scope: ["mail"] };

interface Fakes {
  helpers: OAuthHelpers;
  calls: { completeAuthorization: unknown[]; approveConsent: unknown[]; denyConsent: unknown[]; beginUpstream: unknown[] };
  upstreamData: { codeVerifier: string; nonce: string } | undefined;
}

function fakes(over: Partial<Record<keyof OAuthHelpers, unknown>> = {}): Fakes {
  const calls: Fakes["calls"] = { completeAuthorization: [], approveConsent: [], denyConsent: [], beginUpstream: [] };
  const state: { upstreamData: Fakes["upstreamData"] } = { upstreamData: undefined };
  const helpers = {
    parseAuthRequest: async () => authRequest,
    lookupClient: async () => clientInfo,
    describeConsent: async () => consentDescription,
    beginConsent: async () => ({ handle: "handle-1", headers: new Headers({ "set-cookie": "__Host-consent=abc; Secure; HttpOnly; Path=/" }) }),
    approveConsent: async (_r: Request, handle: string) => { calls.approveConsent.push(handle); return { request: authRequest, headers: new Headers({ "set-cookie": "__Host-consent=; Max-Age=0" }) }; },
    denyConsent: async (_r: Request, handle: string) => { calls.denyConsent.push(handle); return { request: authRequest, redirectTo: `${authRequest.redirectUri}?error=access_denied&state=state-1`, headers: new Headers() }; },
    beginUpstream: async (_a: AuthRequest, opts?: { data?: unknown; headers?: Headers }) => { calls.beginUpstream.push(opts?.data); state.upstreamData = opts?.data as Fakes["upstreamData"]; return { state: "upstream-state-1", headers: new Headers(opts?.headers) }; },
    finishUpstream: async () => ({ request: authRequest, data: state.upstreamData, headers: new Headers({ "set-cookie": "__Host-oauth-upstream=; Max-Age=0" }) }),
    completeAuthorization: async (opts: unknown) => { calls.completeAuthorization.push(opts); return { redirectTo: `${authRequest.redirectUri}?code=authcode-1&state=state-1` }; },
    ...over,
  } as unknown as OAuthHelpers;
  return { helpers, calls, get upstreamData() { return state.upstreamData; } };
}

function googleFetch(emailForCode: Record<string, string>) {
  return vi.fn(async (input: Request | URL | string, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url === "https://www.googleapis.com/oauth2/v3/certs") return new Response(JSON.stringify({ keys: [{ ...jwkPublic, kid: KID, alg: "RS256", use: "sig" }] }), { headers: { "cache-control": "max-age=3600" } });
    if (url === "https://oauth2.googleapis.com/token") {
      const form = new URLSearchParams(String(init?.body));
      const email = emailForCode[form.get("code") ?? ""];
      if (email === undefined) return new Response(JSON.stringify({ error: "invalid_grant" }), { status: 400 });
      // the nonce the handler stored upstream must be the one in the id_token
      const nonce = form.get("__nonce__") ?? pendingNonce;
      return new Response(JSON.stringify({ id_token: await idTokenFor(email, nonce) }));
    }
    throw new Error(`unexpected fetch ${url}`);
  });
}
let pendingNonce = "";

function env(helpers: OAuthHelpers): HandlerEnv {
  return { OAUTH_PROVIDER: helpers, PUBLIC_URL: "https://mcp.example.test", TENANTS_JSON: tenants, ALLOWED_PRINCIPALS: "ada@example-studio.test", GOOGLE_CLIENT_ID: CLIENT_ID, GOOGLE_CLIENT_SECRET: "s" };
}

function harness(f: Fakes, emailForCode: Record<string, string> = {}) {
  const written: AuditRecord[] = [];
  const sink: AuditSink = { write: async (r) => { written.push(r); } };
  const fetch = googleFetch(emailForCode);
  const handler = createDefaultHandler({ fetch, audit: new Audit(sink, () => new Date(NOW)), now: () => NOW });
  return { handler, written, fetch, e: env(f.helpers) };
}

async function approveToGoogle(f: Fakes): Promise<URL> {
  const { handler, e } = harness(f);
  const res = await handler.fetch(new Request("https://mcp.example.test/authorize", { method: "POST", body: new URLSearchParams({ handle: "handle-1", decision: "approve" }), headers: { "content-type": "application/x-www-form-urlencoded" } }), e);
  expect(res.status).toBe(302);
  const loc = new URL(res.headers.get("location") ?? "");
  return loc;
}

describe("GET /authorize (consent page)", () => {
  it("renders the client, escapes it, and carries the consent transaction headers", async () => {
    const f = fakes();
    const { handler, e } = harness(f);
    const res = await handler.fetch(new Request("https://mcp.example.test/authorize?client_id=client-1"), e);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Evil &lt;script&gt;alert(1)&lt;/script&gt; Client");
    expect(html).not.toContain("<script>");
    expect(html).toContain('name="handle" value="handle-1"');
    expect(html).toContain("client.example.test");
    expect(res.headers.get("set-cookie")).toContain("__Host-consent=abc");
    expect(res.headers.get("content-security-policy")).toContain("default-src 'none'");
  });

  it("returns 400 for an unknown client and follows AuthorizationError redirects", async () => {
    const unknown = fakes({ lookupClient: async () => null });
    expect((await harness(unknown).handler.fetch(new Request("https://mcp.example.test/authorize?client_id=x"), env(unknown.helpers))).status).toBe(400);
    const bad = fakes({ parseAuthRequest: async () => { throw new AuthorizationError("invalid_request", { description: "nope", redirectUri: "https://client.example.test/cb", state: "s" }); } });
    const res = await harness(bad).handler.fetch(new Request("https://mcp.example.test/authorize"), env(bad.helpers));
    expect([302, 400]).toContain(res.status);
  });
});

describe("POST /authorize", () => {
  it("approve: records consent, stores verifier+nonce upstream, and sends the browser to Google with the library's state", async () => {
    const f = fakes();
    const loc = await approveToGoogle(f);
    expect(f.calls.approveConsent).toEqual(["handle-1"]);
    expect(loc.origin + loc.pathname).toBe("https://accounts.google.com/o/oauth2/v2/auth");
    expect(loc.searchParams.get("state")).toBe("upstream-state-1");
    expect(loc.searchParams.get("client_id")).toBe(CLIENT_ID);
    expect(loc.searchParams.get("scope")).toBe("openid email");
    expect(loc.searchParams.get("redirect_uri")).toBe("https://mcp.example.test/callback");
    const data = f.upstreamData;
    expect(data?.codeVerifier.length).toBeGreaterThanOrEqual(43);
    expect(loc.searchParams.get("nonce")).toBe(data?.nonce);
    expect(loc.searchParams.get("code_challenge")).toBe(await sha256b64url(data?.codeVerifier ?? ""));
    expect(loc.searchParams.get("code_challenge_method")).toBe("S256");
  });

  it("deny: never touches upstream and redirects back with access_denied", async () => {
    const f = fakes();
    const { handler, e } = harness(f);
    const res = await handler.fetch(new Request("https://mcp.example.test/authorize", { method: "POST", body: new URLSearchParams({ handle: "handle-1", decision: "deny" }), headers: { "content-type": "application/x-www-form-urlencoded" } }), e);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toContain("error=access_denied");
    expect(f.calls.denyConsent).toEqual(["handle-1"]);
    expect(f.calls.beginUpstream).toHaveLength(0);
  });

  it("rejects a missing handle or unknown decision", async () => {
    const f = fakes();
    const { handler, e } = harness(f);
    for (const body of [{ decision: "approve" }, { handle: "h", decision: "maybe" }]) {
      const res = await handler.fetch(new Request("https://mcp.example.test/authorize", { method: "POST", body: new URLSearchParams(body), headers: { "content-type": "application/x-www-form-urlencoded" } }), e);
      expect(res.status).toBe(400);
    }
  });
});

describe("GET /callback", () => {
  async function callbackAfterApprove(f: Fakes, query: string, emailForCode: Record<string, string>) {
    await approveToGoogle(f);
    pendingNonce = f.upstreamData?.nonce ?? "";
    const h = harness(f, emailForCode);
    const res = await h.handler.fetch(new Request(`https://mcp.example.test/callback?${query}`), h.e);
    return { res, ...h };
  }

  it("allowed principal: completes the authorization with the Google sub and email as props", async () => {
    const f = fakes();
    const { res, written } = await callbackAfterApprove(f, "code=good&state=upstream-state-1", { good: "ada@example-studio.test" });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("https://client.example.test/cb?code=authcode-1&state=state-1");
    expect(f.calls.completeAuthorization).toHaveLength(1);
    expect(f.calls.completeAuthorization[0]).toMatchObject({ userId: "sub-ada@example-studio.test", scope: ["mail"], props: { email: "ada@example-studio.test", sub: "sub-ada@example-studio.test" } });
    expect(written.at(-1)).toMatchObject({ tool: "authorize", outcome: "ok", principal: "ada@example-studio.test", clientId: "client-1" });
  });

  it("principal not on the allowlist: no authorization is completed, client gets access_denied, audit says why", async () => {
    const f = fakes();
    const { res, written } = await callbackAfterApprove(f, "code=mallory&state=upstream-state-1", { mallory: "mallory@example-labs.test" });
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("location") ?? "");
    expect(loc.origin + loc.pathname).toBe("https://client.example.test/cb");
    expect(loc.searchParams.get("error")).toBe("access_denied");
    expect(loc.searchParams.get("state")).toBe("state-1");
    expect(f.calls.completeAuthorization).toHaveLength(0);
    expect(written.at(-1)).toMatchObject({ outcome: "refused", errorCode: "principal_not_allowed", principal: "mallory@example-labs.test" });
  });

  it("Google cancelled: access_denied without calling Google's token endpoint", async () => {
    const f = fakes();
    const { res, fetch } = await callbackAfterApprove(f, "error=access_denied&state=upstream-state-1", {});
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toContain("error=access_denied");
    expect(f.calls.completeAuthorization).toHaveLength(0);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("Google rejects the code: server_error, nothing completed, content-free audit code", async () => {
    const f = fakes();
    const { res, written } = await callbackAfterApprove(f, "code=unknown&state=upstream-state-1", {});
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toContain("error=server_error");
    expect(f.calls.completeAuthorization).toHaveLength(0);
    expect(written.at(-1)).toMatchObject({ outcome: "error", errorCode: "token_exchange_failed" });
  });

  it("no upstream transaction (expired or forged): 400 and nothing completed", async () => {
    const f = fakes({ finishUpstream: async () => { throw new Error("no cookie"); } });
    const { handler, e } = harness(f);
    const res = await handler.fetch(new Request("https://mcp.example.test/callback?code=x&state=y"), e);
    expect(res.status).toBe(400);
    expect(f.calls.completeAuthorization).toHaveLength(0);
  });
});

describe("other routes", () => {
  it("serves / and /healthz, 404s the rest", async () => {
    const { handler, e } = harness(fakes());
    expect((await handler.fetch(new Request("https://mcp.example.test/"), e)).status).toBe(200);
    expect((await handler.fetch(new Request("https://mcp.example.test/healthz"), e)).status).toBe(200);
    expect((await handler.fetch(new Request("https://mcp.example.test/nope"), e)).status).toBe(404);
  });
});
