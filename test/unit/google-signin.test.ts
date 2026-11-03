import { beforeAll, describe, expect, it, vi } from "vitest";
import { b64urlEncode, utf8 } from "../../src/auth/encoding.js";
import { GoogleJwks, SignInError, beginGoogleSignIn, completeGoogleSignIn, verifyGoogleIdToken } from "../../src/auth/google.js";

// A throwaway RSA key pair stands in for Google's signing key.
let privateKey: CryptoKey;
type Jwk = JsonWebKey & { kid?: string };
let jwkPublic: Jwk;
const KID = "test-kid-1";
const CLIENT_ID = "client-123.apps.googleusercontent.com";
const NOW = Date.UTC(2026, 10, 3, 10, 0, 0);
const nowFn = () => NOW;

beforeAll(async () => {
  const pair = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  privateKey = pair.privateKey;
  jwkPublic = await crypto.subtle.exportKey("jwk", pair.publicKey);
});

async function mint(claims: Record<string, unknown>, opts: { alg?: string; kid?: string; signer?: CryptoKey; tamper?: boolean } = {}): Promise<string> {
  const header = b64urlEncode(utf8(JSON.stringify({ alg: opts.alg ?? "RS256", kid: opts.kid ?? KID, typ: "JWT" })));
  const payload = b64urlEncode(utf8(JSON.stringify(claims)));
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, opts.signer ?? privateKey, utf8(`${header}.${payload}`)));
  const tampered = opts.tamper ? b64urlEncode(utf8(JSON.stringify({ ...claims, email: "mallory@example-labs.test" }))) : payload;
  return `${header}.${tampered}.${b64urlEncode(sig)}`;
}

function goodClaims(over: Record<string, unknown> = {}): Record<string, unknown> {
  const nowSec = Math.floor(NOW / 1000);
  return { iss: "https://accounts.google.com", aud: CLIENT_ID, sub: "1234567890", email: "Ada@example-studio.test", email_verified: true, hd: "example-studio.test", iat: nowSec - 10, exp: nowSec + 3600, nonce: "nonce-abc", ...over };
}

function jwksFetch(keys: Jwk[] = [{ ...jwkPublic, kid: KID, alg: "RS256", use: "sig" }]) {
  return vi.fn(async (input: Request | URL | string) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    expect(url).toBe("https://www.googleapis.com/oauth2/v3/certs");
    return new Response(JSON.stringify({ keys }), { headers: { "content-type": "application/json", "cache-control": "public, max-age=3600" } });
  });
}

describe("beginGoogleSignIn", () => {
  it("builds a PKCE S256 authorisation URL with openid email only and fresh state/nonce", async () => {
    const cfg = { clientId: CLIENT_ID, clientSecret: "s", redirectUri: "https://mcp.example.test/callback" };
    const a = await beginGoogleSignIn(cfg);
    const b = await beginGoogleSignIn(cfg);
    const u = new URL(a.url);
    expect(u.origin + u.pathname).toBe("https://accounts.google.com/o/oauth2/v2/auth");
    expect(u.searchParams.get("scope")).toBe("openid email");
    expect(u.searchParams.get("response_type")).toBe("code");
    expect(u.searchParams.get("code_challenge_method")).toBe("S256");
    expect(u.searchParams.get("redirect_uri")).toBe(cfg.redirectUri);
    expect(u.searchParams.get("state")).toBe(a.state);
    expect(u.searchParams.get("nonce")).toBe(a.nonce);
    expect(a.state).not.toBe(b.state);
    expect(a.nonce).not.toBe(b.nonce);
    expect(a.codeVerifier.length).toBeGreaterThanOrEqual(43);
    expect(a.url).not.toContain("gmail"); // never a Gmail scope on the sign-in layer
  });
});

describe("verifyGoogleIdToken", () => {
  it("accepts a correctly signed token and lowercases the email", async () => {
    const jwks = new GoogleJwks(jwksFetch(), nowFn);
    const p = await verifyGoogleIdToken(await mint(goodClaims()), { clientId: CLIENT_ID, nonce: "nonce-abc" }, jwks, nowFn);
    expect(p).toEqual({ email: "ada@example-studio.test", sub: "1234567890", hd: "example-studio.test" });
  });

  it("accepts the bare 'accounts.google.com' issuer form too", async () => {
    const jwks = new GoogleJwks(jwksFetch(), nowFn);
    await expect(verifyGoogleIdToken(await mint(goodClaims({ iss: "accounts.google.com" })), { clientId: CLIENT_ID, nonce: "nonce-abc" }, jwks, nowFn)).resolves.toBeDefined();
  });

  const cases: [string, () => Promise<string>, string][] = [
    ["tampered payload", () => mint(goodClaims(), { tamper: true }), "id_token_bad_signature"],
    ["wrong audience", () => mint(goodClaims({ aud: "other-client" })), "id_token_bad_audience"],
    ["audience list with extra entry", () => mint(goodClaims({ aud: [CLIENT_ID, "other"] })), "id_token_bad_audience"],
    ["wrong issuer", () => mint(goodClaims({ iss: "https://evil.example.test" })), "id_token_bad_issuer"],
    ["expired", () => mint(goodClaims({ exp: Math.floor(NOW / 1000) - 120 })), "id_token_expired"],
    ["issued in the future", () => mint(goodClaims({ iat: Math.floor(NOW / 1000) + 600 })), "id_token_not_yet_valid"],
    ["wrong nonce", () => mint(goodClaims({ nonce: "other" })), "id_token_bad_nonce"],
    ["missing nonce", () => mint(goodClaims({ nonce: undefined })), "id_token_bad_nonce"],
    ["email not verified", () => mint(goodClaims({ email_verified: false })), "email_not_verified"],
    ["email_verified as string", () => mint(goodClaims({ email_verified: "true" })), "email_not_verified"],
    ["missing email", () => mint(goodClaims({ email: undefined })), "email_missing"],
    ["alg none", () => mint(goodClaims(), { alg: "none" }), "id_token_bad_alg"],
    ["alg HS256", () => mint(goodClaims(), { alg: "HS256" }), "id_token_bad_alg"],
    ["unknown kid", () => mint(goodClaims(), { kid: "nope" }), "id_token_unknown_key"],
  ];
  for (const [name, make, code] of cases) {
    it(`rejects: ${name} (${code})`, async () => {
      const jwks = new GoogleJwks(jwksFetch(), nowFn);
      await expect(verifyGoogleIdToken(await make(), { clientId: CLIENT_ID, nonce: "nonce-abc" }, jwks, nowFn)).rejects.toMatchObject({ name: "SignInError", code });
    });
  }

  it("rejects a token signed by a different key even if the kid matches", async () => {
    const other = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
    const jwks = new GoogleJwks(jwksFetch(), nowFn);
    await expect(verifyGoogleIdToken(await mint(goodClaims(), { signer: other.privateKey }), { clientId: CLIENT_ID, nonce: "nonce-abc" }, jwks, nowFn)).rejects.toMatchObject({ code: "id_token_bad_signature" });
  });

  it("rejects garbage without throwing anything but SignInError", async () => {
    const jwks = new GoogleJwks(jwksFetch(), nowFn);
    for (const junk of ["", "a.b", "a.b.c", "!!.!!.!!", `${b64urlEncode(utf8("{}"))}.${b64urlEncode(utf8("{}"))}.x`]) {
      await expect(verifyGoogleIdToken(junk, { clientId: CLIENT_ID, nonce: "n" }, jwks, nowFn)).rejects.toBeInstanceOf(SignInError);
    }
  });

  it("caches the JWKS and refreshes once on an unknown kid", async () => {
    const f = jwksFetch();
    const jwks = new GoogleJwks(f, nowFn);
    await verifyGoogleIdToken(await mint(goodClaims()), { clientId: CLIENT_ID, nonce: "nonce-abc" }, jwks, nowFn);
    await verifyGoogleIdToken(await mint(goodClaims()), { clientId: CLIENT_ID, nonce: "nonce-abc" }, jwks, nowFn);
    expect(f).toHaveBeenCalledTimes(1);
    await expect(verifyGoogleIdToken(await mint(goodClaims(), { kid: "rotated" }), { clientId: CLIENT_ID, nonce: "nonce-abc" }, jwks, nowFn)).rejects.toMatchObject({ code: "id_token_unknown_key" });
    expect(f).toHaveBeenCalledTimes(2);
  });
});

describe("completeGoogleSignIn", () => {
  const cfg = { clientId: CLIENT_ID, clientSecret: "shh", redirectUri: "https://mcp.example.test/callback" };

  it("posts the code with the PKCE verifier to the token endpoint and returns the verified principal", async () => {
    const idToken = await mint(goodClaims());
    const jwksF = jwksFetch();
    const fetchImpl = vi.fn(async (input: Request | URL | string, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url === "https://oauth2.googleapis.com/token") {
        expect(init?.method).toBe("POST");
        const form = new URLSearchParams(String(init?.body));
        expect(form.get("grant_type")).toBe("authorization_code");
        expect(form.get("code")).toBe("the-code");
        expect(form.get("code_verifier")).toBe("the-verifier");
        expect(form.get("client_id")).toBe(CLIENT_ID);
        expect(form.get("client_secret")).toBe("shh");
        expect(form.get("redirect_uri")).toBe(cfg.redirectUri);
        return new Response(JSON.stringify({ id_token: idToken, access_token: "ya29.x", expires_in: 3599, token_type: "Bearer" }), { headers: { "content-type": "application/json" } });
      }
      return jwksF(input);
    });
    const p = await completeGoogleSignIn(cfg, { code: "the-code", codeVerifier: "the-verifier", nonce: "nonce-abc" }, { fetch: fetchImpl, jwks: new GoogleJwks(fetchImpl, nowFn), now: nowFn });
    expect(p.email).toBe("ada@example-studio.test");
  });

  it("fails closed when Google rejects the code or omits the id_token", async () => {
    const rejecting = vi.fn(async () => new Response(JSON.stringify({ error: "invalid_grant" }), { status: 400 }));
    await expect(completeGoogleSignIn(cfg, { code: "c", codeVerifier: "v", nonce: "n" }, { fetch: rejecting, jwks: new GoogleJwks(rejecting, nowFn), now: nowFn })).rejects.toMatchObject({ code: "token_exchange_failed" });
    const noId = vi.fn(async () => new Response(JSON.stringify({ access_token: "x" }), { status: 200 }));
    await expect(completeGoogleSignIn(cfg, { code: "c", codeVerifier: "v", nonce: "n" }, { fetch: noId, jwks: new GoogleJwks(noId, nowFn), now: nowFn })).rejects.toMatchObject({ code: "id_token_missing" });
  });
});
