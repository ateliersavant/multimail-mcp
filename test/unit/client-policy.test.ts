import { describe, expect, it } from "vitest";
import { DEFAULT_METADATA_HOSTS, DEFAULT_REDIRECT_HOSTS, MAX_FORM_BYTES, clientIdAllowed, parseHostList, redirectUriAllowed, registrationPolicy, screenClientIds } from "../../src/oauth/client-policy.js";

const meta = new Set(DEFAULT_METADATA_HOSTS);
const redirects = new Set(DEFAULT_REDIRECT_HOSTS);
const b64url = (s: string): string => btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

describe("client metadata documents", () => {
  it("allows registered ids and metadata URLs on supported hosts only", () => {
    expect(clientIdAllowed("Xy12-registered-client", meta)).toBe(true);
    expect(clientIdAllowed("https://claude.ai/oauth/mcp-oauth-client-metadata", meta)).toBe(true);
    for (const bad of ["https://attacker.example.net/x", "https://claude.ai.attacker.test/x", "https://claude.ai:8443/x", "https://u:p@claude.ai/x", "https://169.254.169.254/latest", "https://[::1]/x"]) {
      expect(clientIdAllowed(bad, meta), bad).toBe(false);
    }
  });

  it("screens the query, a form body, Basic credentials and a client assertion's issuer", async () => {
    const off = "https://attacker.example.net/c";
    const form = (body: string): Request => new Request("https://mcp.example.test/oauth/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "content-length": String(body.length) }, body });
    expect(await screenClientIds(new Request(`https://mcp.example.test/authorize?client_id=${encodeURIComponent(off)}`), meta)).toBe("client_host_not_allowed");
    expect(await screenClientIds(form(`grant_type=authorization_code&client_id=${encodeURIComponent(off)}`), meta)).toBe("client_host_not_allowed");
    const basic = new Request("https://mcp.example.test/oauth/token", { method: "POST", headers: { authorization: `Basic ${btoa(`${encodeURIComponent(off)}:secret`)}` } });
    expect(await screenClientIds(basic, meta)).toBe("client_host_not_allowed");
    const jwt = `${b64url('{"alg":"RS256"}')}.${b64url(JSON.stringify({ iss: off, sub: off }))}.sig`;
    expect(await screenClientIds(form(`client_assertion_type=x&client_assertion=${jwt}`), meta)).toBe("client_host_not_allowed");
    expect(await screenClientIds(form(`client_id=registered-1&grant_type=refresh_token`), meta)).toBe("ok");
    expect(await screenClientIds(form(`x=${"a".repeat(MAX_FORM_BYTES)}`), meta)).toBe("body_too_large");
  });

  it("leaves the screened request's body readable for the OAuth library", async () => {
    const r = new Request("https://mcp.example.test/oauth/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "content-length": "11" }, body: "client_id=a" });
    expect(await screenClientIds(r, meta)).toBe("ok");
    expect(await r.text()).toBe("client_id=a");
  });
});

describe("dynamic client registration", () => {
  const policy = registrationPolicy(redirects);
  it("accepts supported web clients and loopback", () => {
    for (const ok of ["https://claude.ai/api/mcp/auth_callback", "https://chatgpt.com/connector_platform_oauth_redirect", "http://localhost:33418/callback", "http://127.0.0.1:1455/auth/callback", "http://[::1]:8080/cb"]) {
      expect(redirectUriAllowed(ok, redirects), ok).toBe(true);
      expect(policy({ clientMetadata: { redirect_uris: [ok] } }), ok).toBeUndefined();
    }
  });
  it("refuses any other redirect, a missing list, and key URLs the server would fetch", () => {
    for (const bad of ["https://attacker.test/cb", "http://claude.ai/cb", "https://claude.ai:444/cb", "myapp://cb", "http://10.0.0.1/cb", "https://claude.ai/cb#frag"]) {
      expect(policy({ clientMetadata: { redirect_uris: ["https://claude.ai/ok", bad] } }), bad).toMatchObject({ code: "invalid_redirect_uri" });
    }
    expect(policy({ clientMetadata: {} })).toMatchObject({ code: "invalid_redirect_uri" });
    expect(policy({ clientMetadata: { redirect_uris: ["https://claude.ai/cb"], jwks_uri: "https://attacker.test/jwks" } })).toMatchObject({ code: "invalid_client_metadata" });
    expect(policy({ clientMetadata: { redirect_uris: ["https://claude.ai/cb"], token_endpoint_auth_method: "private_key_jwt" } })).toMatchObject({ code: "invalid_client_metadata" });
  });
  it("extends the host lists from configuration, naming the variable, never the value, on a bad entry", () => {
    const set = parseHostList(DEFAULT_REDIRECT_HOSTS, " Client.Example.Test ,", "CLIENT_REDIRECT_HOSTS");
    expect(typeof set !== "string" && set.has("client.example.test")).toBe(true);
    expect(parseHostList(DEFAULT_REDIRECT_HOSTS, "ok.test,https://evil.test/x", "CLIENT_REDIRECT_HOSTS")).toBe("CLIENT_REDIRECT_HOSTS: entry 2 is not a plain host name");
  });
});
