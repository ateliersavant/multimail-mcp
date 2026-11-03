/**
 * docs/threat-model.md T3: "principal must be in ALLOWED_PRINCIPALS (checked on every authorisation, `email_verified`
 * required, `hd`/domain checked)". verifyGoogleIdToken (src/auth/google.ts) only copies `hd` into the principal, and
 * nothing reads it (src/oauth/handlers.ts callback checks the email only). An id_token for an allow-listed address on
 * one of the tenants' Workspace domains, but issued for an account that is NOT managed by that Workspace (no `hd`,
 * e.g. a consumer Google account registered on that address, or a different `hd`), is accepted.
 */
import { beforeAll, describe, expect, it, vi } from "vitest";
import { env as workerEnv } from "cloudflare:workers";
import type { AuthRequest, OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import { Audit, type AuditRecord } from "../../src/audit.js";
import { b64urlEncode, utf8 } from "../../src/auth/encoding.js";
import { createDefaultHandler, type HandlerEnv } from "../../src/oauth/handlers.js";

const CLIENT_ID = "test-client-id.apps.googleusercontent.com";
const NOW = Date.UTC(2026, 10, 3, 12, 0, 0);
const KID = "k1";
let privateKey: CryptoKey;
let jwkPublic: JsonWebKey;

beforeAll(async () => {
  const pair = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  privateKey = pair.privateKey;
  jwkPublic = await crypto.subtle.exportKey("jwk", pair.publicKey);
});

const authRequest: AuthRequest = { responseType: "code", clientId: "client-1", redirectUri: "https://client.example.test/cb", scope: ["mail"], state: "st", codeChallenge: "c", codeChallengeMethod: "S256", resource: "https://mcp.example.test/mcp", issuer: "https://mcp.example.test" };

async function signIn(extraClaims: Record<string, unknown>): Promise<{ completed: unknown[]; written: AuditRecord[]; location: string | null }> {
  const completed: unknown[] = [];
  const upstream = { codeVerifier: "v".repeat(64), nonce: "nonce-1" };
  const helpers = {
    finishUpstream: async () => ({ request: authRequest, data: upstream, headers: new Headers() }),
    completeAuthorization: async (opts: unknown) => {
      completed.push(opts);
      return { redirectTo: `${authRequest.redirectUri}?code=authcode&state=st` };
    },
  } as unknown as OAuthHelpers;
  const fetch = vi.fn(async (input: Request | URL | string) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url === "https://www.googleapis.com/oauth2/v3/certs") return new Response(JSON.stringify({ keys: [{ ...jwkPublic, kid: KID, alg: "RS256", use: "sig" }] }), { headers: { "cache-control": "max-age=3600" } });
    if (url === "https://oauth2.googleapis.com/token") {
      const nowSec = Math.floor(NOW / 1000);
      const header = b64urlEncode(utf8(JSON.stringify({ alg: "RS256", kid: KID, typ: "JWT" })));
      const payload = b64urlEncode(utf8(JSON.stringify({ iss: "https://accounts.google.com", aud: CLIENT_ID, sub: "consumer-sub-1", email: "ada@example-studio.test", email_verified: true, iat: nowSec - 5, exp: nowSec + 3600, nonce: upstream.nonce, ...extraClaims })));
      const sig = new Uint8Array(await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, privateKey, utf8(`${header}.${payload}`)));
      return new Response(JSON.stringify({ id_token: `${header}.${payload}.${b64urlEncode(sig)}` }));
    }
    throw new Error(`unexpected fetch ${url}`);
  });
  const written: AuditRecord[] = [];
  const handler = createDefaultHandler({ fetch, audit: new Audit({ write: async (r) => { written.push(r); } }, () => new Date(NOW)), now: () => NOW });
  const e: HandlerEnv = { OAUTH_PROVIDER: helpers, PUBLIC_URL: "https://mcp.example.test", TENANTS_JSON: workerEnv.TENANTS_JSON, ALLOWED_PRINCIPALS: "ada@example-studio.test", GOOGLE_CLIENT_ID: CLIENT_ID, GOOGLE_CLIENT_SECRET: "s" };
  const res = await handler.fetch(new Request("https://mcp.example.test/callback?code=c&state=x"), e);
  return { completed, written, location: res.headers.get("location") };
}

describe("Google sign-in: the hd (Workspace domain) check the threat model promises", () => {
  it("refuses an allow-listed address on a tenant's Workspace domain when the token has no hd (not a Workspace-managed account)", async () => {
    expect((await signIn({ hd: "example-studio.test" })).completed).toHaveLength(1); // precondition: the managed account is accepted
    const { completed, location } = await signIn({});
    expect({ completed: completed.length, location }).toMatchObject({ completed: 0 });
  });

  it("refuses an allow-listed address when hd names a different domain", async () => {
    const { completed } = await signIn({ hd: "attacker.test" });
    expect(completed).toHaveLength(0);
  });
});
