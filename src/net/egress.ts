/**
 * The ONLY way this Worker talks to the outside world. Every outbound request must pass
 * an explicit host + path-prefix allowlist, must be https, and may not follow redirects
 * (a redirect could leave the allowlist). CI additionally greps the source for any other host.
 */
export class EgressDeniedError extends Error {
  constructor(reason: string, url: URL) {
    super(`Egress denied (${reason}): ${url.origin}${url.pathname}`);
    this.name = "EgressDeniedError";
  }
}

/** host -> allowed path prefixes. A prefix of "/" allows every path on that host. */
export type EgressPolicy = ReadonlyMap<string, readonly string[]>;

/** Everything v1 needs from Google, and nothing else. */
export const GOOGLE_EGRESS: EgressPolicy = new Map<string, readonly string[]>([
  ["oauth2.googleapis.com", ["/token", "/revoke"]], // sign-in code exchange, delegation token minting, revocation
  ["www.googleapis.com", ["/oauth2/v3/certs"]], // JWKS for id_token verification, nothing else on this host
  ["gmail.googleapis.com", ["/gmail/v1/users/"]], // Gmail API
  // accounts.google.com is where the user's BROWSER goes to sign in; the Worker never fetches it.
]);

export type FetchLike = (input: Request | URL | string, init?: RequestInit) => Promise<Response>;

function toUrl(input: Request | URL | string): URL {
  if (input instanceof Request) return new URL(input.url);
  if (input instanceof URL) return input;
  return new URL(input);
}

export function assertEgressAllowed(url: URL, policy: EgressPolicy): void {
  if (url.protocol !== "https:") throw new EgressDeniedError("not https", url);
  if (url.username !== "" || url.password !== "") throw new EgressDeniedError("credentials in url", url);
  if (url.port !== "") throw new EgressDeniedError("non-default port", url);
  const prefixes = policy.get(url.hostname);
  if (prefixes === undefined) throw new EgressDeniedError("host not allowlisted", url);
  // A prefix matches only on a path boundary: "/token" allows "/token" and "/token/x", never "/tokeninfo".
  // A prefix that ends in "/" (a collection) allows anything beneath it.
  const matches = (p: string): boolean => url.pathname === p || (p.endsWith("/") ? url.pathname.startsWith(p) : url.pathname.startsWith(`${p}/`));
  if (!prefixes.some(matches)) throw new EgressDeniedError("path not allowlisted", url);
}

/**
 * Wraps a fetch so that every call is checked against `policy`. Redirects are turned into
 * errors rather than followed. The returned function is what the rest of the code imports as `fetch`.
 */
export function createEgressFetch(policy: EgressPolicy, underlying: FetchLike = globalThis.fetch): FetchLike {
  return async (input, init) => {
    const url = toUrl(input);
    assertEgressAllowed(url, policy);
    const safeInit: RequestInit = { ...init, redirect: "error" };
    if (input instanceof Request) {
      return underlying(new Request(input, safeInit));
    }
    return underlying(url.toString(), safeInit);
  };
}
