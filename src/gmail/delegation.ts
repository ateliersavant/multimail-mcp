/**
 * Mailbox auth (handoff §3): Google Workspace domain-wide delegation. One service account per tenant. For every
 * call the server mints a short-lived access token that impersonates exactly the mailbox named by `account`, by
 * signing a JWT assertion with that tenant's key and exchanging it at Google's token endpoint.
 *
 * The key is read from the Cloudflare secret whose NAME the tenant file gives; it is imported as a non-extractable
 * CryptoKey and never copied anywhere else. Tokens live only in this isolate's memory and are never logged or
 * returned to a client. Every outbound call goes through the egress wrapper handed in by the caller.
 */
import { b64urlEncode, utf8 } from "../auth/encoding.js";
import type { FetchLike } from "../net/egress.js";
import type { ResolvedMailbox } from "../tenants/registry.js";

/** The single scope requested under delegation (handoff §3). Never widened. */
export const GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.modify";
export const GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
const JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";
/** Google caps assertions at one hour. */
const ASSERTION_TTL_S = 3600;
/** Tokens are refreshed this long before Google's stated expiry, so a token never expires mid-request. */
const REFRESH_MARGIN_MS = 60_000;

export type DelegationErrorCode = "service_account_secret_missing" | "service_account_key_invalid" | "delegation_token_refused" | "delegation_token_malformed";

/**
 * Rule 6: loud. `message` is written for the model and the operator and names the tenant and mailbox, never the
 * secret's name or any key material. `detail` is for the Worker log only (a secret name, Google's error code).
 */
export class DelegationError extends Error {
  constructor(
    readonly code: DelegationErrorCode,
    readonly tenantId: string,
    message: string,
    readonly detail?: string,
  ) {
    super(message);
    this.name = "DelegationError";
  }
}

export interface ServiceAccountKey {
  readonly clientEmail: string;
  readonly privateKeyPem: string;
}

const PEM_HEADER = "-----BEGIN PRIVATE KEY-----";
const PEM_FOOTER = "-----END PRIVATE KEY-----";

/**
 * Validates the JSON key file Google issues for a service account. Only the two fields the exchange needs are kept.
 * Error messages describe the shape of the problem and never quote the input.
 */
export function parseServiceAccountKey(text: string): ServiceAccountKey {
  let decoded: unknown;
  try {
    decoded = JSON.parse(text);
  } catch {
    throw new Error("not valid JSON");
  }
  if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) throw new Error("not a JSON object");
  const key = decoded as Record<string, unknown>;
  if (key["type"] !== "service_account") throw new Error('"type" is not "service_account"');
  const clientEmail = key["client_email"];
  if (typeof clientEmail !== "string" || !clientEmail.includes("@")) throw new Error('"client_email" missing');
  const pem = key["private_key"];
  if (typeof pem !== "string" || !pem.includes(PEM_HEADER) || !pem.includes(PEM_FOOTER)) throw new Error('"private_key" is not a PKCS#8 PEM block');
  const tokenUri = key["token_uri"];
  if (tokenUri !== undefined && tokenUri !== GOOGLE_TOKEN_ENDPOINT) throw new Error('"token_uri" is not Google\'s token endpoint');
  return { clientEmail, privateKeyPem: pem };
}

function pemToDer(pem: string): ArrayBuffer {
  const start = pem.indexOf(PEM_HEADER) + PEM_HEADER.length;
  const end = pem.indexOf(PEM_FOOTER);
  const b64 = pem.slice(start, end).replace(/\s+/g, "");
  if (!/^[A-Za-z0-9+/]+=*$/.test(b64)) throw new Error("PEM body is not base64");
  const bin = atob(b64);
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

/** Imports the key for signing only; it can never be exported again. */
export async function importServiceAccountKey(key: ServiceAccountKey): Promise<CryptoKey> {
  return crypto.subtle.importKey("pkcs8", pemToDer(key.privateKeyPem), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
}

export interface AssertionClaims {
  readonly iss: string;
  readonly sub: string;
  readonly scope: string;
  readonly aud: string;
  readonly iat: number;
  readonly exp: number;
}

/** RS256 JWT: `{alg,typ}` header, the claims, signature over `header.payload`. */
export async function signAssertion(key: CryptoKey, claims: AssertionClaims): Promise<string> {
  const header = b64urlEncode(utf8(JSON.stringify({ alg: "RS256", typ: "JWT" })));
  const payload = b64urlEncode(utf8(JSON.stringify(claims)));
  const sig = await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, key, utf8(`${header}.${payload}`));
  return `${header}.${payload}.${b64urlEncode(new Uint8Array(sig))}`;
}

export interface DelegationDeps {
  /** The Worker env (or any record): secrets are read by the NAME in the tenant file, at call time. */
  readonly secrets: Readonly<Record<string, unknown>>;
  /** Must be the egress-checked fetch. */
  readonly fetch: FetchLike;
  readonly now?: () => number;
}

interface LoadedKey {
  readonly clientEmail: string;
  readonly key: CryptoKey;
}

interface CachedToken {
  readonly token: string;
  readonly expiresAt: number;
}

/** Google's error codes that have a known operator meaning; anything else is reported as the code alone. */
const REFUSAL_HINTS: Readonly<Record<string, string>> = {
  unauthorized_client: "The service account is not authorised for domain-wide delegation with the Gmail scope in this tenant's Admin Console, or the mailbox is not in that tenant.",
  invalid_grant: "The mailbox may not exist in this tenant, the service-account key may have been revoked, or the Worker's clock is off.",
  invalid_client: "The service-account key is not recognised by Google (deleted or rotated).",
};

/**
 * Mints and caches delegated access tokens, one per mailbox. Thread-safe within an isolate: concurrent calls for the
 * same mailbox share one exchange. A token is used until a minute before Google's stated expiry.
 */
export class DelegationTokenSource {
  private readonly keys = new Map<string, LoadedKey>();
  private readonly tokens = new Map<string, CachedToken>();
  private readonly inflight = new Map<string, Promise<string>>();
  private readonly now: () => number;

  constructor(private readonly deps: DelegationDeps) {
    this.now = deps.now ?? (() => Date.now());
  }

  private static cacheKey(target: ResolvedMailbox): string {
    return `${target.tenant.id}\u0000${target.mailbox.address}`;
  }

  /** Returns a bearer token that acts as `target.mailbox.address`, minting one if the cache has none that is still fresh. */
  async tokenFor(target: ResolvedMailbox): Promise<string> {
    const k = DelegationTokenSource.cacheKey(target);
    const cached = this.tokens.get(k);
    if (cached !== undefined && cached.expiresAt - REFRESH_MARGIN_MS > this.now()) return cached.token;
    const pending = this.inflight.get(k);
    if (pending !== undefined) return pending;
    const p = this.mint(target)
      .then((t) => {
        this.tokens.set(k, t);
        return t.token;
      })
      .finally(() => this.inflight.delete(k));
    this.inflight.set(k, p);
    return p;
  }

  /** Drops the cached token for a mailbox (after Gmail answered 401, for example) so the next call mints a fresh one. */
  invalidate(target: ResolvedMailbox): void {
    this.tokens.delete(DelegationTokenSource.cacheKey(target));
  }

  private async loadKey(target: ResolvedMailbox): Promise<LoadedKey> {
    const secretName = target.tenant.serviceAccountSecret;
    const hit = this.keys.get(secretName);
    if (hit !== undefined) return hit;
    const raw = this.deps.secrets[secretName];
    if (typeof raw !== "string" || raw.trim().length === 0) {
      throw new DelegationError(
        "service_account_secret_missing",
        target.tenant.id,
        `Tenant "${target.tenant.id}" has no service-account key configured on this server, so mailbox ${target.mailbox.address} cannot be opened. This is an operator configuration error, not an empty mailbox.`,
        secretName,
      );
    }
    let loaded: LoadedKey;
    try {
      const parsed = parseServiceAccountKey(raw);
      loaded = { clientEmail: parsed.clientEmail, key: await importServiceAccountKey(parsed) };
    } catch (e) {
      throw new DelegationError(
        "service_account_key_invalid",
        target.tenant.id,
        `The service-account key configured for tenant "${target.tenant.id}" is malformed, so mailbox ${target.mailbox.address} cannot be opened. This is an operator configuration error, not an empty mailbox.`,
        `${secretName}: ${e instanceof Error ? e.message : "invalid"}`,
      );
    }
    this.keys.set(secretName, loaded);
    return loaded;
  }

  private async mint(target: ResolvedMailbox): Promise<CachedToken> {
    const { clientEmail, key } = await this.loadKey(target);
    const iat = Math.floor(this.now() / 1000);
    const assertion = await signAssertion(key, { iss: clientEmail, sub: target.mailbox.address, scope: GMAIL_SCOPE, aud: GOOGLE_TOKEN_ENDPOINT, iat, exp: iat + ASSERTION_TTL_S });
    const res = await this.deps.fetch(GOOGLE_TOKEN_ENDPOINT, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: new URLSearchParams({ grant_type: JWT_BEARER, assertion }),
    });
    if (!res.ok) {
      let code = "unknown";
      try {
        const body = (await res.json()) as { error?: unknown };
        if (typeof body.error === "string" && /^[a-z_]{1,64}$/.test(body.error)) code = body.error;
      } catch {
        code = "unknown";
      }
      const hint = REFUSAL_HINTS[code];
      throw new DelegationError(
        "delegation_token_refused",
        target.tenant.id,
        `Google refused to issue a delegated token for ${target.mailbox.address} (HTTP ${res.status}, ${code}).${hint !== undefined ? ` ${hint}` : ""} No mail was read.`,
        code,
      );
    }
    let body: { access_token?: unknown; expires_in?: unknown };
    try {
      body = (await res.json()) as typeof body;
    } catch {
      throw new DelegationError("delegation_token_malformed", target.tenant.id, `Google's token response for ${target.mailbox.address} was not JSON. No mail was read.`);
    }
    if (typeof body.access_token !== "string" || body.access_token.length === 0 || typeof body.expires_in !== "number" || !(body.expires_in > 0)) {
      throw new DelegationError("delegation_token_malformed", target.tenant.id, `Google's token response for ${target.mailbox.address} had no usable access token. No mail was read.`);
    }
    return { token: body.access_token, expiresAt: this.now() + Math.floor(body.expires_in) * 1000 };
  }
}
