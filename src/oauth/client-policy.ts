/**
 * Which OAuth clients may exist at all. Three gaps closed here (docs/threat-model.md T9, T14):
 *
 * 1. The OAuth library resolves a URL-shaped client_id (a Client ID Metadata Document) with the global fetch, outside
 *    src/net/egress.ts, from unauthenticated requests. Every client id the library could read (query string, form
 *    body, Basic credentials, client-assertion issuer) is screened at the Worker entry: a metadata URL must be on an
 *    allowed host, so nobody can make this Worker fetch an address of their choosing.
 * 2. Dynamic Client Registration is open by design (MCP clients register themselves). A registration may only name
 *    redirect URIs on an allowed https host or on loopback, so an attacker cannot register a look-alike client whose
 *    codes return to them (consent phishing), and may not name a key URL the server would later fetch.
 * 3. Registrations are counted per source address (in src/index.ts).
 */
import type { ClientRegistrationCallbackResult } from "@cloudflare/workers-oauth-provider";

/** Hosts serving the metadata documents of the supported clients (Claude, ChatGPT). Extend with CLIENT_METADATA_HOSTS. */
export const DEFAULT_METADATA_HOSTS: readonly string[] = ["claude.ai", "claude.com", "chatgpt.com"];
/** https redirect hosts of the supported web clients. Loopback (desktop and CLI clients) is always allowed. Extend with CLIENT_REDIRECT_HOSTS. */
export const DEFAULT_REDIRECT_HOSTS: readonly string[] = ["claude.ai", "claude.com", "chatgpt.com"];
export const DEFAULT_REGISTER_PER_HOUR = 10;

const LOOPBACK: ReadonlySet<string> = new Set(["localhost", "127.0.0.1", "[::1]"]);
const HOST = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
/** Larger form bodies on an OAuth endpoint are refused rather than screened partially. */
export const MAX_FORM_BYTES = 64 * 1024;

export interface ClientPolicy {
  readonly metadataHosts: ReadonlySet<string>;
  readonly redirectHosts: ReadonlySet<string>;
  readonly registerPerHour: number;
}

/** The defaults plus a comma-separated extension. Returns the issue (naming the variable, never the value) on a bad entry. */
export function parseHostList(defaults: readonly string[], extra: string | undefined, name: string): ReadonlySet<string> | string {
  const out = new Set(defaults);
  const entries = (extra ?? "").split(",").map((s) => s.trim().toLowerCase());
  for (const [i, h] of entries.entries()) {
    if (h === "") continue;
    if (!HOST.test(h)) return `${name}: entry ${i + 1} is not a plain host name`;
    out.add(h);
  }
  return out;
}

function parseUrl(value: string): URL | undefined {
  try {
    return new URL(value);
  } catch {
    return undefined;
  }
}

/** A client id that is not an https URL is looked up in the store, never fetched; an https one must be on an allowed host. */
export function clientIdAllowed(clientId: string, metadataHosts: ReadonlySet<string>): boolean {
  const u = parseUrl(clientId);
  if (u === undefined || u.protocol !== "https:") return true;
  return u.port === "" && u.username === "" && u.password === "" && metadataHosts.has(u.hostname.toLowerCase());
}

export function redirectUriAllowed(uri: string, redirectHosts: ReadonlySet<string>): boolean {
  const u = parseUrl(uri);
  if (u === undefined || u.username !== "" || u.password !== "" || u.hash !== "") return false;
  if (u.protocol === "https:") return u.port === "" && redirectHosts.has(u.hostname.toLowerCase());
  return u.protocol === "http:" && LOOPBACK.has(u.hostname.toLowerCase());
}

function assertionIssuer(assertion: string): string | undefined {
  const payload = assertion.split(".")[1];
  if (payload === undefined) return undefined;
  try {
    const json = JSON.parse(atob(payload.replace(/-/g, "+").replace(/_/g, "/"))) as { iss?: unknown };
    return typeof json.iss === "string" ? json.iss : undefined;
  } catch {
    return undefined;
  }
}

function basicClientIds(header: string | null): string[] {
  const m = /^basic[ \t]+(\S+)\s*$/i.exec(header ?? "");
  if (m?.[1] === undefined) return [];
  try {
    const creds = atob(m[1]);
    const user = creds.slice(0, Math.max(creds.indexOf(":"), 0));
    const ids = [user];
    try {
      ids.push(decodeURIComponent(user.replace(/\+/g, " ")));
    } catch {
      // the library refuses an undecodable id itself
    }
    return ids;
  } catch {
    return [];
  }
}

export type ScreenResult = "ok" | "client_host_not_allowed" | "body_too_large";

/**
 * Every client id the OAuth library could resolve from this request must pass `clientIdAllowed`. Reads a clone of a
 * form body (the token endpoint's), so the request itself is untouched for the library.
 */
export async function screenClientIds(request: Request, metadataHosts: ReadonlySet<string>): Promise<ScreenResult> {
  const ids = [...new URL(request.url).searchParams.getAll("client_id"), ...basicClientIds(request.headers.get("authorization"))];
  const type = (request.headers.get("content-type") ?? "").toLowerCase();
  if (request.method === "POST" && (type.startsWith("application/x-www-form-urlencoded") || type.startsWith("multipart/form-data"))) {
    const declared = Number(request.headers.get("content-length") ?? NaN);
    if (!Number.isFinite(declared) || declared > MAX_FORM_BYTES) return "body_too_large";
    const text = await request.clone().text();
    if (text.length > MAX_FORM_BYTES) return "body_too_large";
    const form = type.startsWith("multipart/") ? await new Request(request.url, { method: "POST", headers: { "content-type": type }, body: text }).formData() : new URLSearchParams(text);
    for (const v of form.getAll("client_id")) if (typeof v === "string") ids.push(v);
    for (const v of form.getAll("client_assertion")) if (typeof v === "string") ids.push(assertionIssuer(v) ?? "");
  }
  return ids.every((id) => clientIdAllowed(id, metadataHosts)) ? "ok" : "client_host_not_allowed";
}

/** The library's registration hook: allowed redirect URIs only, and no key URL for the server to fetch later. */
export function registrationPolicy(redirectHosts: ReadonlySet<string>): (o: { readonly clientMetadata: Record<string, unknown> }) => ClientRegistrationCallbackResult | undefined {
  return ({ clientMetadata }) => {
    const uris = clientMetadata["redirect_uris"];
    if (!Array.isArray(uris) || uris.length === 0 || !uris.every((u) => typeof u === "string" && redirectUriAllowed(u, redirectHosts))) {
      return { code: "invalid_redirect_uri", description: "Redirect URIs must be on a supported client's host or on loopback (http://localhost, 127.0.0.1 or [::1])." };
    }
    if (clientMetadata["jwks_uri"] !== undefined || clientMetadata["jwks"] !== undefined || clientMetadata["token_endpoint_auth_method"] === "private_key_jwt") {
      return { code: "invalid_client_metadata", description: "Key-based client authentication is not supported here." };
    }
    return undefined;
  };
}
