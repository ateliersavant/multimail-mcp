import { describe, expect, it } from "vitest";
import { PrincipalConfigError, isAllowedPrincipal, parseAllowedPrincipals } from "../../src/auth/principals.js";

describe("ALLOWED_PRINCIPALS", () => {
  it("refuses to start on a missing, empty or malformed allowlist (rule 6)", () => {
    for (const bad of [undefined, "", "   ", ",", "not-an-email", "Ada@example-studio.test", "ada@example-studio.test, nope"]) {
      expect(() => parseAllowedPrincipals(bad), String(bad)).toThrow(PrincipalConfigError);
    }
  });

  it("parses comma, space and newline separated lowercase addresses", () => {
    const set = parseAllowedPrincipals("ada@example-studio.test,\n grace@example-labs.test  ada@example-studio.test");
    expect([...set]).toEqual(["ada@example-studio.test", "grace@example-labs.test"]);
  });

  it("matches exactly: no case folding, no sub-addressing, no domain-only matches", () => {
    const set = parseAllowedPrincipals("ada@example-studio.test");
    expect(isAllowedPrincipal(set, "ada@example-studio.test")).toBe(true);
    for (const no of ["Ada@example-studio.test", "ada+x@example-studio.test", "ada@example-studio.test ", "grace@example-studio.test", "ada@example-studio.test.evil.test", ""]) {
      expect(isAllowedPrincipal(set, no), no).toBe(false);
    }
  });
});
