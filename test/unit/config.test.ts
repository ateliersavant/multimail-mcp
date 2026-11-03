import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { ConfigError, getConfig, loadConfig, type ConfigEnv as Env } from "../../src/config.js";

const tenants = readFileSync(new URL("../../fixtures/tenants.example.json", import.meta.url), "utf8");
const good: Env = {
  PUBLIC_URL: "https://mcp.example.test",
  TENANTS_JSON: tenants,
  ALLOWED_PRINCIPALS: "ada@example-studio.test",
  GOOGLE_CLIENT_ID: "cid",
  GOOGLE_CLIENT_SECRET: "csecret",
};

function issuesOf(env: Env): readonly string[] {
  try {
    loadConfig(env);
  } catch (e) {
    if (e instanceof ConfigError) return e.issues;
    throw e;
  }
  throw new Error("expected ConfigError");
}

describe("loadConfig", () => {
  it("builds the config and derives the MCP resource and redirect URI from PUBLIC_URL", () => {
    const cfg = loadConfig(good);
    expect(cfg.mcpResource).toBe("https://mcp.example.test/mcp");
    expect(cfg.google.redirectUri).toBe("https://mcp.example.test/callback");
    expect(cfg.registry.getMailbox("ada@example-studio.test")?.tenant.id).toBe("example-studio");
    expect(cfg.allowedPrincipals.has("ada@example-studio.test")).toBe(true);
  });

  it("names every missing variable at once and never echoes a value", () => {
    const issues = issuesOf({});
    for (const k of ["PUBLIC_URL", "TENANTS_JSON", "ALLOWED_PRINCIPALS", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"]) {
      expect(issues.some((i) => i.startsWith(`${k}:`)), k).toBe(true);
    }
    const partial = issuesOf({ ...good, GOOGLE_CLIENT_SECRET: "" });
    expect(partial).toEqual(["GOOGLE_CLIENT_SECRET: missing (set it with `wrangler secret put GOOGLE_CLIENT_SECRET`)"]);
    expect(JSON.stringify(issuesOf({ ...good, TENANTS_JSON: '{"tenants":[]}', GOOGLE_CLIENT_SECRET: "topsecret" }))).not.toContain("topsecret");
  });

  it("surfaces tenant file issues with their JSON paths", () => {
    const issues = issuesOf({ ...good, TENANTS_JSON: '{"tenants":[{"id":"x"}]}' });
    expect(issues.some((i) => i.startsWith("TENANTS_JSON $.tenants[0]."))).toBe(true);
    expect(issuesOf({ ...good, TENANTS_JSON: "nope" })[0]).toMatch(/^TENANTS_JSON \$: not valid JSON/);
  });

  it("rejects an insecure or non-bare PUBLIC_URL except http on localhost", () => {
    expect(issuesOf({ ...good, PUBLIC_URL: "http://mcp.example.test" })[0]).toMatch(/PUBLIC_URL: must be https/);
    expect(issuesOf({ ...good, PUBLIC_URL: "https://mcp.example.test/mcp" })[0]).toMatch(/bare origin/);
    expect(issuesOf({ ...good, PUBLIC_URL: "https://mcp.example.test/?x=1" })[0]).toMatch(/bare origin/);
    expect(issuesOf({ ...good, PUBLIC_URL: "not a url" })[0]).toMatch(/^PUBLIC_URL:/);
    expect(loadConfig({ ...good, PUBLIC_URL: "http://localhost:8787" }).mcpResource).toBe("http://localhost:8787/mcp");
    expect(loadConfig({ ...good, PUBLIC_URL: "https://mcp.example.test/" }).mcpResource).toBe("https://mcp.example.test/mcp");
  });

  it("rejects a bad principal allowlist", () => {
    expect(issuesOf({ ...good, ALLOWED_PRINCIPALS: "Ada@example-studio.test" })[0]).toMatch(/^ALLOWED_PRINCIPALS:/);
  });

  it("caches a good config per env object but never caches a failure", () => {
    const env: Env = { ...good };
    expect(getConfig(env)).toBe(getConfig(env));
    const broken: { -readonly [K in keyof Env]: Env[K] } = { ...good, GOOGLE_CLIENT_ID: "" };
    expect(() => getConfig(broken)).toThrow(ConfigError);
    broken.GOOGLE_CLIENT_ID = "cid";
    expect(getConfig(broken).google.clientId).toBe("cid");
  });
});
