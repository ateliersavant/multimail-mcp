import { describe, expect, it } from "vitest";
import { requireBindings } from "../../src/bindings.js";
import { ConfigError } from "../../src/config.js";

describe("requireBindings (rule 6 for platform bindings)", () => {
  it("refuses to serve without the store or the audit database, naming each", () => {
    const issuesOf = (env: { OAUTH_STORE?: unknown; AUDIT_DB?: unknown }): readonly string[] => {
      try {
        requireBindings(env);
      } catch (e) {
        if (e instanceof ConfigError) return e.issues;
        throw e;
      }
      return [];
    };
    expect(issuesOf({})).toEqual([expect.stringMatching(/^OAUTH_STORE:/), expect.stringMatching(/^AUDIT_DB:/)]);
    expect(issuesOf({ OAUTH_STORE: {} })).toEqual([expect.stringMatching(/^AUDIT_DB:/)]);
    expect(issuesOf({ AUDIT_DB: {} })).toEqual([expect.stringMatching(/^OAUTH_STORE:/)]);
    expect(issuesOf({ OAUTH_STORE: {}, AUDIT_DB: {} })).toEqual([]);
  });
});
