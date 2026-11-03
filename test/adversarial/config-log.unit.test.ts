/**
 * src/config.ts: "Issues name variables, never values." src/index.ts logs ConfigError.issues verbatim
 * ("Issues name variables and JSON paths, never values"). loadTenantConfig (src/tenants/validate.ts) embeds the
 * JSON.parse message, and V8's message for an unexpected token quotes ~20 characters of the input, i.e. of the
 * tenant file (real mailbox addresses and company domains), into the Worker log.
 */
import { describe, expect, it } from "vitest";
import { ConfigError, loadConfig } from "../../src/config.js";

describe("configuration errors name variables, never values", () => {
  it("a typo in TENANTS_JSON does not copy tenant-file content into the logged issues", () => {
    const tenants = '{"tenants":[{"id":"acme-holdings","label":"Acme","domains":[ceo@acme-holdings.example]}]}'; // unquoted string
    let issues: readonly string[] = [];
    try {
      loadConfig({ PUBLIC_URL: "https://mcp.example.test", TENANTS_JSON: tenants, ALLOWED_PRINCIPALS: "ada@example-studio.test", GOOGLE_CLIENT_ID: "x", GOOGLE_CLIENT_SECRET: "y" });
    } catch (e) {
      if (e instanceof ConfigError) issues = e.issues;
    }
    expect(issues.length).toBeGreaterThan(0);
    expect(issues.join("\n")).not.toMatch(/acme/i);
  });
});
