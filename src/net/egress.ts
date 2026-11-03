/**
 * The ONLY way this Worker's own code talks to the outside world. Every outbound request must match an explicit
 * host + method + path rule, must be https, and may not follow redirects (a redirect could leave the allowlist).
 * CI additionally greps the source for any other host.
 *
 * The rules name each Gmail call this server makes and nothing more. The `gmail.modify` scope would also let a token
 * send a message directly, trash single messages, import or insert mail, or change many messages at once; none of
 * those paths is reachable from here. Labels and Trash are reachable only per thread or message, through the
 * organising tools.
 */
export class EgressDeniedError extends Error {
  constructor(reason: string, url: URL) {
    super(`Egress denied (${reason}): ${url.origin}${url.pathname}`);
    this.name = "EgressDeniedError";
  }
}

export type EgressMethod = "GET" | "POST" | "PUT" | "DELETE";

export interface EgressRule {
  readonly method: EgressMethod;
  /** An exact path, where a `{name}` segment matches exactly one path segment (see SEGMENT). */
  readonly path: string;
}

/** host -> the only requests allowed to it. */
export type EgressPolicy = ReadonlyMap<string, readonly EgressRule[]>;

const MAILBOX = "/gmail/v1/users/{mailbox}";
const gmail = (method: EgressMethod, rest: string): EgressRule => ({ method, path: `${MAILBOX}/${rest}` });

/** Everything v1 needs from Google, and nothing else. */
export const GOOGLE_EGRESS: EgressPolicy = new Map<string, readonly EgressRule[]>([
  // Sign-in code exchange and delegation token minting.
  ["oauth2.googleapis.com", [{ method: "POST", path: "/token" }]],
  // Google's signing keys, to verify sign-in id_tokens.
  ["www.googleapis.com", [{ method: "GET", path: "/oauth2/v3/certs" }]],
  [
    "gmail.googleapis.com",
    [
      gmail("GET", "threads"),
      gmail("GET", "threads/{id}"),
      gmail("GET", "messages/{id}"),
      gmail("GET", "labels"),
      gmail("GET", "settings/sendAs"),
      gmail("GET", "drafts"),
      gmail("POST", "drafts"),
      gmail("GET", "drafts/{id}"),
      gmail("PUT", "drafts/{id}"),
      gmail("DELETE", "drafts/{id}"),
      gmail("POST", "drafts/send"),
      gmail("POST", "threads/{id}/modify"),
      gmail("POST", "messages/{id}/modify"),
      gmail("POST", "threads/{id}/trash"),
      gmail("POST", "threads/{id}/untrash"),
    ],
  ],
  // accounts.google.com is where the user's BROWSER goes to sign in; the Worker never fetches it.
]);

/** One path segment: unreserved characters and percent-escapes, but never an escaped slash or backslash. */
const SEGMENT = /^(?:[A-Za-z0-9._~+-]|%(?!2[Ff]|5[Cc])[0-9A-Fa-f]{2})+$/;

function pathMatches(pattern: string, path: string): boolean {
  const want = pattern.split("/");
  const got = path.split("/");
  if (want.length !== got.length) return false;
  return want.every((w, i) => {
    const g = got[i] ?? "";
    return w.startsWith("{") && w.endsWith("}") ? SEGMENT.test(g) : w === g;
  });
}

export type FetchLike = (input: Request | URL | string, init?: RequestInit) => Promise<Response>;

function toUrl(input: Request | URL | string): URL {
  if (input instanceof Request) return new URL(input.url);
  if (input instanceof URL) return input;
  return new URL(input);
}

export function assertEgressAllowed(url: URL, policy: EgressPolicy, method: string = "GET"): void {
  if (url.protocol !== "https:") throw new EgressDeniedError("not https", url);
  if (url.username !== "" || url.password !== "") throw new EgressDeniedError("credentials in url", url);
  if (url.port !== "") throw new EgressDeniedError("non-default port", url);
  const rules = policy.get(url.hostname);
  if (rules === undefined) throw new EgressDeniedError("host not allowlisted", url);
  const m = method.toUpperCase();
  if (!rules.some((r) => r.method === m && pathMatches(r.path, url.pathname))) throw new EgressDeniedError(`${m} not allowlisted for this path`, url);
}

/** Called through the global object: the Workers runtime rejects a detached `fetch` reference. */
const runtimeFetch: FetchLike = (input, init) => fetch(input, init);

/**
 * Wraps a fetch so that every call is checked against `policy`, and refuses redirects.
 * The Workers runtime only supports `redirect: "follow" | "manual"` ("error" throws), so the wrapper asks for
 * "manual" and turns any 3xx response into an EgressDeniedError: a followed redirect could leave the allowlist.
 */
export function createEgressFetch(policy: EgressPolicy, underlying: FetchLike = runtimeFetch): FetchLike {
  return async (input, init) => {
    const url = toUrl(input);
    assertEgressAllowed(url, policy, init?.method ?? (input instanceof Request ? input.method : "GET"));
    const safeInit: RequestInit = { ...init, redirect: "manual" };
    const res = input instanceof Request ? await underlying(new Request(input, safeInit)) : await underlying(url.toString(), safeInit);
    if (res.status >= 300 && res.status < 400) throw new EgressDeniedError("redirect refused", url);
    return res;
  };
}
