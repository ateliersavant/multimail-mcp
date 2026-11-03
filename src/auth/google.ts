/**
 * Sign in with Google for the server's own OAuth layer. Scopes `openid email` only.
 * The Worker never sees a Google password; it verifies the id_token Google signs and keeps the email.
 */
import { b64urlDecode, randomToken, sha256b64url, utf8 } from "./encoding.js";
import type { FetchLike } from "../net/egress.js";

export const GOOGLE_AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"; // browser redirect only
export const GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
export const GOOGLE_JWKS_URI = "https://www.googleapis.com/oauth2/v3/certs";
const GOOGLE_ISSUERS: ReadonlySet<string> = new Set(["https://accounts.google.com", "accounts.google.com"]);

export interface GoogleSignInConfig {
  readonly clientId: string;
  readonly clientSecret: string;
  readonly redirectUri: string;
}

export interface SignInStart {
  readonly url: string;
  readonly state: string;
  readonly nonce: string;
  readonly codeVerifier: string;
}

export interface Principal {
  readonly email: string;
  readonly sub: string;
  readonly hd?: string;
}

export type SignInErrorCode =
  | "token_exchange_failed"
  | "id_token_missing"
  | "id_token_malformed"
  | "id_token_bad_alg"
  | "id_token_unknown_key"
  | "id_token_bad_signature"
  | "id_token_bad_issuer"
  | "id_token_bad_audience"
  | "id_token_expired"
  | "id_token_not_yet_valid"
  | "id_token_bad_nonce"
  | "email_missing"
  | "email_not_verified";

/** Content-free by construction: the message is the code. Audit logs record `code`. */
export class SignInError extends Error {
  constructor(readonly code: SignInErrorCode) {
    super(code);
    this.name = "SignInError";
  }
}

/** Builds the Google authorisation URL with PKCE (S256), a fresh state and a fresh nonce. */
export async function beginGoogleSignIn(cfg: GoogleSignInConfig, opts: { readonly state?: string; readonly loginHint?: string } = {}): Promise<SignInStart> {
  const state = opts.state ?? randomToken();
  const loginHint = opts.loginHint;
  const nonce = randomToken();
  const codeVerifier = randomToken(48);
  const url = new URL(GOOGLE_AUTHORIZATION_ENDPOINT);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", cfg.clientId);
  url.searchParams.set("redirect_uri", cfg.redirectUri);
  url.searchParams.set("scope", "openid email");
  url.searchParams.set("state", state);
  url.searchParams.set("nonce", nonce);
  url.searchParams.set("code_challenge", await sha256b64url(codeVerifier));
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("access_type", "online");
  url.searchParams.set("prompt", "select_account");
  if (loginHint !== undefined) url.searchParams.set("login_hint", loginHint);
  return { url: url.toString(), state, nonce, codeVerifier };
}

interface Jwk {
  readonly kty: string;
  readonly kid?: string;
  readonly alg?: string;
  readonly use?: string;
  readonly n?: string;
  readonly e?: string;
}

/** Fetches and caches Google's signing keys, honouring Cache-Control max-age (Google sends hours). */
export class GoogleJwks {
  private keys: ReadonlyMap<string, Jwk> = new Map();
  private expiresAt = 0;
  constructor(private readonly fetchImpl: FetchLike, private readonly now: () => number = () => Date.now()) {}

  async get(kid: string, allowRefresh = true): Promise<Jwk | undefined> {
    if (this.now() >= this.expiresAt) await this.refresh();
    const k = this.keys.get(kid);
    if (k !== undefined || !allowRefresh) return k;
    // Unknown kid: Google may have rotated; refresh once.
    await this.refresh();
    return this.keys.get(kid);
  }

  private async refresh(): Promise<void> {
    const res = await this.fetchImpl(GOOGLE_JWKS_URI, { method: "GET" });
    if (!res.ok) throw new SignInError("id_token_unknown_key");
    const body = (await res.json()) as { keys?: Jwk[] };
    const map = new Map<string, Jwk>();
    for (const k of body.keys ?? []) if (k.kid !== undefined && k.kty === "RSA") map.set(k.kid, k);
    this.keys = map;
    const cc = res.headers.get("cache-control") ?? "";
    const m = /max-age=(\d+)/.exec(cc);
    const ttl = m ? Math.min(Number(m[1]), 24 * 3600) : 3600;
    this.expiresAt = this.now() + ttl * 1000;
  }
}

interface IdTokenClaims {
  readonly iss?: unknown;
  readonly aud?: unknown;
  readonly exp?: unknown;
  readonly iat?: unknown;
  readonly nonce?: unknown;
  readonly sub?: unknown;
  readonly email?: unknown;
  readonly email_verified?: unknown;
  readonly hd?: unknown;
}

function decodeSegment<T>(seg: string, code: SignInErrorCode): T {
  try {
    return JSON.parse(new TextDecoder().decode(b64urlDecode(seg))) as T;
  } catch {
    throw new SignInError(code);
  }
}

/**
 * Verifies a Google id_token: RS256 signature against the JWKS, issuer, audience, time window,
 * nonce, and a verified email. Returns the principal or throws a SignInError.
 */
export async function verifyGoogleIdToken(
  idToken: string,
  expected: { readonly clientId: string; readonly nonce: string },
  jwks: GoogleJwks,
  now: () => number = () => Date.now(),
): Promise<Principal> {
  const parts = idToken.split(".");
  if (parts.length !== 3) throw new SignInError("id_token_malformed");
  const [h, p, s] = parts as [string, string, string];
  const header = decodeSegment<{ alg?: unknown; kid?: unknown; typ?: unknown }>(h, "id_token_malformed");
  if (header.alg !== "RS256" || typeof header.kid !== "string") throw new SignInError("id_token_bad_alg");
  const jwk = await jwks.get(header.kid);
  if (jwk === undefined || jwk.n === undefined || jwk.e === undefined) throw new SignInError("id_token_unknown_key");
  let key: CryptoKey;
  try {
    const material: JsonWebKey = { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true };
    key = await crypto.subtle.importKey("jwk", material, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  } catch {
    throw new SignInError("id_token_unknown_key");
  }
  let sig: Uint8Array<ArrayBuffer>;
  try {
    sig = b64urlDecode(s);
  } catch {
    throw new SignInError("id_token_malformed");
  }
  const ok = await crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, key, sig, utf8(`${h}.${p}`));
  if (!ok) throw new SignInError("id_token_bad_signature");

  const c = decodeSegment<IdTokenClaims>(p, "id_token_malformed");
  if (typeof c.iss !== "string" || !GOOGLE_ISSUERS.has(c.iss)) throw new SignInError("id_token_bad_issuer");
  const aud = Array.isArray(c.aud) ? c.aud : [c.aud];
  if (!(aud.length === 1 && aud[0] === expected.clientId)) throw new SignInError("id_token_bad_audience");
  const nowSec = Math.floor(now() / 1000);
  if (typeof c.exp !== "number" || c.exp <= nowSec - 60) throw new SignInError("id_token_expired");
  if (typeof c.iat !== "number" || c.iat > nowSec + 300) throw new SignInError("id_token_not_yet_valid");
  if (typeof c.nonce !== "string" || c.nonce !== expected.nonce) throw new SignInError("id_token_bad_nonce");
  if (typeof c.email !== "string" || c.email.length === 0 || typeof c.sub !== "string") throw new SignInError("email_missing");
  if (c.email_verified !== true) throw new SignInError("email_not_verified");
  const principal: Principal = typeof c.hd === "string" ? { email: c.email.toLowerCase(), sub: c.sub, hd: c.hd } : { email: c.email.toLowerCase(), sub: c.sub };
  return principal;
}

/** Exchanges the authorisation code (with the PKCE verifier) and returns the verified principal. */
export async function completeGoogleSignIn(
  cfg: GoogleSignInConfig,
  input: { readonly code: string; readonly codeVerifier: string; readonly nonce: string },
  deps: { readonly fetch: FetchLike; readonly jwks: GoogleJwks; readonly now?: () => number },
): Promise<Principal> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: input.code,
    client_id: cfg.clientId,
    client_secret: cfg.clientSecret,
    redirect_uri: cfg.redirectUri,
    code_verifier: input.codeVerifier,
  });
  const res = await deps.fetch(GOOGLE_TOKEN_ENDPOINT, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body,
  });
  if (!res.ok) throw new SignInError("token_exchange_failed");
  const json = (await res.json()) as { id_token?: unknown };
  if (typeof json.id_token !== "string") throw new SignInError("id_token_missing");
  return verifyGoogleIdToken(json.id_token, { clientId: cfg.clientId, nonce: input.nonce }, deps.jwks, deps.now);
}
