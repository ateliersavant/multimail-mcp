import { describe, expect, it } from "vitest";
import { env, exports } from "cloudflare:workers";
import { getOAuthApi } from "@cloudflare/workers-oauth-provider";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { randomToken, sha256b64url } from "../../src/auth/encoding.js";
import { loadConfig } from "../../src/config.js";
import { buildProviderOptions } from "../../src/oauth/options.js";
import { withConsistentStore } from "../../src/store/env.js";

const ORIGIN = "https://mcp.example.test";
type Fetcher = { fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> };
const worker = (exports as unknown as { default: Fetcher }).default;
const call = (path: string, init?: RequestInit) => worker.fetch(new Request(`${ORIGIN}${path}`, init));
const json = async <T,>(r: Response): Promise<T> => (await r.json()) as T;

const INITIALIZE = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } } });
const mcpHeaders = (token?: string) => ({ "content-type": "application/json", accept: "application/json, text/event-stream", ...(token ? { authorization: `Bearer ${token}` } : {}) });

describe("discovery", () => {
  it("publishes Protected Resource Metadata for /mcp with the exact resource and the mail scope", async () => {
    const r = await call("/.well-known/oauth-protected-resource/mcp");
    expect(r.status).toBe(200);
    const prm = await json<{ resource: string; authorization_servers: string[]; scopes_supported?: string[] }>(r);
    expect(prm.resource).toBe(`${ORIGIN}/mcp`);
    expect(prm.authorization_servers).toContain(ORIGIN);
    expect(prm.scopes_supported).toEqual(["mail"]);
  });

  it("publishes authorization-server metadata with CIMD, DCR, PKCE S256, public clients, iss and revocation", async () => {
    const r = await call("/.well-known/oauth-authorization-server");
    expect(r.status).toBe(200);
    const m = await json<Record<string, unknown>>(r);
    expect(m["issuer"]).toBe(ORIGIN);
    expect(m["authorization_endpoint"]).toBe(`${ORIGIN}/authorize`);
    expect(m["token_endpoint"]).toBe(`${ORIGIN}/oauth/token`);
    expect(m["registration_endpoint"]).toBe(`${ORIGIN}/oauth/register`);
    expect(m["revocation_endpoint"]).toBeDefined();
    expect(m["code_challenge_methods_supported"]).toEqual(["S256"]);
    expect(m["token_endpoint_auth_methods_supported"]).toContain("none");
    expect(m["client_id_metadata_document_supported"]).toBe(true);
    expect(m["authorization_response_iss_parameter_supported"]).toBe(true);
    expect(m["scopes_supported"]).toContain("mail");
  });
});

describe("/mcp without a valid token", () => {
  it("401 with a WWW-Authenticate challenge pointing at the PRM and asking for the mail scope", async () => {
    const r = await call("/mcp", { method: "POST", headers: mcpHeaders(), body: INITIALIZE });
    expect(r.status).toBe(401);
    const www = r.headers.get("www-authenticate") ?? "";
    expect(www).toContain(`resource_metadata="${ORIGIN}/.well-known/oauth-protected-resource/mcp"`);
    expect(www).toContain('scope="mail"');
  });

  it("401 for a garbage bearer token", async () => {
    const r = await call("/mcp", { method: "POST", headers: mcpHeaders("not-a-token"), body: INITIALIZE });
    expect(r.status).toBe(401);
  });
});

describe("consent page through the real provider", () => {
  it("registers a client via DCR, shows consent, and hands off to Google on approve", async () => {
    const reg = await call("/oauth/register", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "DCR Test Client", redirect_uris: ["https://client.example.test/cb"], token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] }) });
    expect(reg.status).toBe(201);
    const { client_id } = await json<{ client_id: string }>(reg);
    const challenge = await sha256b64url(randomToken());
    const q = new URLSearchParams({ response_type: "code", client_id, redirect_uri: "https://client.example.test/cb", scope: "mail", state: "s1", code_challenge: challenge, code_challenge_method: "S256", resource: `${ORIGIN}/mcp` });
    const consent = await call(`/authorize?${q}`);
    expect(consent.status).toBe(200);
    const html = await consent.text();
    expect(html).toContain("DCR Test Client");
    const handle = /name="handle" value="([^"]+)"/.exec(html)?.[1];
    expect(handle).toBeTruthy();
    const cookies = consent.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");
    // redirect: "manual" — otherwise the test fetcher follows the 302 to Google straight back into this Worker.
    const approve = await call("/authorize", { method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded", cookie: cookies }, body: new URLSearchParams({ handle: handle ?? "", decision: "approve" }) });
    expect(approve.status).toBe(302);
    const loc = new URL(approve.headers.get("location") ?? "");
    expect(loc.origin + loc.pathname).toBe("https://accounts.google.com/o/oauth2/v2/auth");
    expect(loc.searchParams.get("client_id")).toBe(env.GOOGLE_CLIENT_ID);
    expect(loc.searchParams.get("scope")).toBe("openid email");
    expect(loc.searchParams.get("state")).toBeTruthy();
    expect(loc.searchParams.get("code_challenge_method")).toBe("S256");
  });
});

/** Mints a grant the way /callback does after Google, then exchanges the code at the real token endpoint. */
async function tokenFor(email: string, resource = `${ORIGIN}/mcp`): Promise<{ status: number; token?: string }> {
  const storeEnv = withConsistentStore(env);
  const cfg = loadConfig(storeEnv);
  const noop = { fetch: async () => new Response(null, { status: 500 }) };
  const api = getOAuthApi(buildProviderOptions(cfg, { api: noop, pages: noop }), storeEnv);
  const client = await api.createClient({ redirectUris: ["https://client.example.test/cb"], clientName: "E2E", tokenEndpointAuthMethod: "none" });
  const verifier = randomToken();
  const request = { responseType: "code", clientId: client.clientId, redirectUri: "https://client.example.test/cb", scope: ["mail"], state: "st", codeChallenge: await sha256b64url(verifier), codeChallengeMethod: "S256", resource };
  let code: string | null = null;
  try {
    const { redirectTo } = await api.completeAuthorization({ request, userId: `sub-${email}`, metadata: {}, scope: ["mail"], props: { email, sub: `sub-${email}` } });
    code = new URL(redirectTo).searchParams.get("code");
  } catch (e) {
    if (resource !== `${ORIGIN}/mcp` && e instanceof Error && e.name === "AuthorizationError") return { status: 0 }; // unknown resource refused up front
    throw new Error(`completeAuthorization failed: ${e instanceof Error ? `${e.name}: ${e.message}` : String(e)}`);
  }
  const r = await call("/oauth/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", code: code ?? "", redirect_uri: "https://client.example.test/cb", client_id: client.clientId, code_verifier: verifier, resource }) });
  if (r.status !== 200) return { status: r.status };
  const body = await json<{ access_token: string }>(r);
  return { status: 200, token: body.access_token };
}

describe("MCP over HTTP with a real token", () => {
  it("lists tools and calls list_accounts for an allowed principal; output has no secret names", async () => {
    const { status, token } = await tokenFor("ada@example-studio.test");
    expect(status).toBe(200);
    const transport = new StreamableHTTPClientTransport(new URL(`${ORIGIN}/mcp`), {
      requestInit: { headers: { authorization: `Bearer ${token}` } },
      fetch: (input: RequestInfo | URL, init?: RequestInit) => worker.fetch(input, init),
    });
    const client = new Client({ name: "worker-test", version: "0.0.0" });
    await client.connect(transport);
    const tools = await client.listTools();
    const names = tools.tools.map((t) => t.name);
    expect(names).toEqual(["list_accounts", "search_threads", "get_thread", "get_message", "list_labels", "create_draft", "update_draft", "get_draft", "list_drafts", "delete_draft", "send_draft", "check_send_as", "modify_labels", "trash_thread", "untrash_thread"]);
    expect(names).not.toContain("send_message"); // rule 3: no direct send over the real transport either
    for (const t of tools.tools) expect(t.description, t.name).toContain("untrusted data");
    const result = await client.callTool({ name: "list_accounts", arguments: {} });
    const out = result.structuredContent as { principal: string; tenants: { id: string; mailboxes: { address: string }[] }[] };
    expect(out.principal).toBe("ada@example-studio.test");
    expect(out.tenants.map((t) => t.id)).toEqual(["example-studio", "example-labs"]);
    expect(JSON.stringify(result)).not.toContain("SA_EXAMPLE");
    await client.close();
  });

  it("read tools over HTTP in workerd: unknown account refused; missing or malformed service-account secret is a loud error, never an empty result", async () => {
    const { token } = await tokenFor("ada@example-studio.test");
    const transport = new StreamableHTTPClientTransport(new URL(`${ORIGIN}/mcp`), {
      requestInit: { headers: { authorization: `Bearer ${token}` } },
      fetch: (input: RequestInfo | URL, init?: RequestInit) => worker.fetch(input, init),
    });
    const client = new Client({ name: "worker-test", version: "0.0.0" });
    await client.connect(transport);
    const text = (r: Awaited<ReturnType<Client["callTool"]>>): string => (r.content as { type: string; text?: string }[]).map((c) => c.text ?? "").join("\n");

    const unknown = await client.callTool({ name: "list_labels", arguments: { account: "nobody@example-studio.test" } });
    expect(unknown.isError).toBe(true);
    expect(text(unknown)).toContain("Unknown account");

    // SA_EXAMPLE_STUDIO is not bound in the test runtime: the tenant exists, its key does not.
    const missing = await client.callTool({ name: "search_threads", arguments: { account: "ada@example-studio.test", query: "anything" } });
    expect(missing.isError).toBe(true);
    expect(text(missing)).toContain("example-studio");
    expect(text(missing)).toContain("operator configuration error");
    expect(text(missing)).not.toContain("SA_EXAMPLE_STUDIO");
    expect(missing.structuredContent).toBeUndefined();

    // SA_EXAMPLE_LABS is bound to a string that is not a key.
    const malformed = await client.callTool({ name: "get_thread", arguments: { account: "grace@example-labs.test", thread_id: "abc" } });
    expect(malformed.isError).toBe(true);
    expect(text(malformed)).toContain("malformed");
    expect(text(malformed)).toContain("example-labs");
    await client.close();
  });

  it("refuses a valid token whose principal has since left the allowlist (403, re-checked per call)", async () => {
    const { status, token } = await tokenFor("mallory@example-labs.test");
    expect(status).toBe(200); // the grant exists; only the per-call check stands in the way
    const r = await call("/mcp", { method: "POST", headers: mcpHeaders(token), body: INITIALIZE });
    expect(r.status).toBe(403);
    // ...and the refusal is in the durable audit log, metadata only.
    const audit = await env.AUDIT_DB.prepare("SELECT tool, outcome, error_code, principal FROM audit WHERE error_code = 'principal_not_allowed' ORDER BY id DESC LIMIT 1").first();
    expect(audit).toEqual({ tool: "mcp", outcome: "refused", error_code: "principal_not_allowed", principal: "mallory@example-labs.test" });
  });

  it("rate-limits one client token: past the per-minute limit → 429 with Retry-After, audited; another client is unaffected", async () => {
    const { token } = await tokenFor("ada@example-studio.test");
    let limited: Response | undefined;
    for (let i = 0; i < 85 && limited === undefined; i++) {
      const r = await call("/mcp", { method: "POST", headers: mcpHeaders(token), body: INITIALIZE });
      if (r.status === 429) limited = r;
      else await r.body?.cancel();
    }
    expect(limited?.status).toBe(429);
    expect(Number(limited?.headers.get("retry-after"))).toBeGreaterThan(0);
    const body = (await limited?.json()) as { error: { message: string } };
    expect(body.error.message).toMatch(/Rate limit: at most 40 requests per minute/);
    const audit = await env.AUDIT_DB.prepare("SELECT outcome, error_code FROM audit WHERE error_code = 'rate_limited' ORDER BY id DESC LIMIT 1").first();
    expect(audit).toEqual({ outcome: "refused", error_code: "rate_limited" });
    const other = await tokenFor("ada@example-studio.test"); // a different registered client
    const ok = await call("/mcp", { method: "POST", headers: mcpHeaders(other.token), body: INITIALIZE });
    expect(ok.status).toBe(200);
  });

  it("never yields a usable token for another resource (audience binding)", async () => {
    const { status, token } = await tokenFor("ada@example-studio.test", "https://other.example.test/mcp");
    if (status === 200 && token) {
      const r = await call("/mcp", { method: "POST", headers: mcpHeaders(token), body: INITIALIZE });
      expect(r.status).toBe(401);
    } else {
      expect(status).not.toBe(200);
    }
  });
});

describe("which clients may exist (src/oauth/client-policy.ts at the Worker entry)", () => {
  const register = (redirect: string, ip: string) =>
    call("/oauth/register", { method: "POST", headers: { "content-type": "application/json", "cf-connecting-ip": ip }, body: JSON.stringify({ client_name: "x", redirect_uris: [redirect], token_endpoint_auth_method: "none", grant_types: ["authorization_code"], response_types: ["code"] }) });

  it("refuses a registration whose redirect is not a supported client's host or loopback", async () => {
    const r = await register("https://attacker.example.net/cb", "198.51.100.1");
    expect(r.status).toBe(400);
    expect(await json<{ error: string }>(r)).toMatchObject({ error: "invalid_redirect_uri" });
    expect((await register("http://localhost:1455/cb", "198.51.100.1")).status).toBe(201);
  });

  it("refuses a metadata-document client id on another host at /authorize and at the token endpoint", async () => {
    const off = "https://attacker.example.net/client";
    const a = await call(`/authorize?${new URLSearchParams({ response_type: "code", client_id: off, redirect_uri: "https://attacker.example.net/cb", state: "s" })}`);
    expect(a.status).toBe(400);
    expect(await json<{ error: string }>(a)).toMatchObject({ error: "invalid_client" });
    const body = `grant_type=authorization_code&code=x&client_id=${encodeURIComponent(off)}`;
    const t = await call("/oauth/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "content-length": String(body.length) }, body });
    expect(t.status).toBe(400);
  });

  it("limits registrations per source address", async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 11; i++) statuses.push((await register("http://127.0.0.1:9/cb", "203.0.113.77")).status);
    expect(statuses.slice(0, 10).every((s) => s === 201)).toBe(true);
    expect(statuses[10]).toBe(429);
    expect((await register("http://127.0.0.1:9/cb", "203.0.113.78")).status).toBe(201); // another address is unaffected
  });
});
