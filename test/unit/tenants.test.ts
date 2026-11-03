import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { TenantConfigError, TenantRegistry, UnknownAccountError, loadTenantConfig, parseTenantConfig } from "../../src/tenants/index.js";

const fixtureText = readFileSync(new URL("../../fixtures/tenants.example.json", import.meta.url), "utf8");
const fixture = (): Record<string, unknown> => JSON.parse(fixtureText) as Record<string, unknown>;

/** Deep-clone the fixture and apply a mutation, so each test starts from a valid file. */
function mutated(fn: (doc: Record<string, unknown>) => void): unknown {
  const doc = fixture();
  fn(doc);
  return doc;
}
type Loose = Record<string, unknown>;
const tenant = (doc: Loose, i: number): Loose => (doc["tenants"] as Loose[])[i] as Loose;
const mailbox = (doc: Loose, t: number, m: number): Loose => (tenant(doc, t)["mailboxes"] as Loose[])[m] as Loose;

function issuesOf(input: unknown): readonly string[] {
  try {
    parseTenantConfig(input);
  } catch (e) {
    if (e instanceof TenantConfigError) return e.issues;
    throw e;
  }
  throw new Error("expected TenantConfigError");
}

describe("tenant fixture", () => {
  it("parses and exposes two tenants with disjoint domains", () => {
    const cfg = loadTenantConfig(fixtureText);
    expect(cfg.tenants.map((t) => t.id)).toEqual(["example-studio", "example-labs"]);
    const all = cfg.tenants.flatMap((t) => t.domains);
    expect(new Set(all).size).toBe(all.length);
  });

  it("uses only reserved .test domains: no real company, no consumer mail provider", () => {
    // Structural guard for the fixture: every address and every configured domain must end in the reserved .test TLD.
    // (CI additionally greps the whole tree for the real names, which are deliberately not spelled out here.)
    const cfg = loadTenantConfig(fixtureText);
    for (const t of cfg.tenants) {
      for (const d of t.domains) expect(d).toMatch(/\.test$/);
      for (const m of t.mailboxes) {
        expect(m.address).toMatch(/@[a-z0-9.-]+\.test$/);
        for (const s of m.sendAs) expect(s).toMatch(/@[a-z0-9.-]+\.test$/);
      }
    }
    for (const m of fixtureText.matchAll(/@([a-z0-9.-]+)/g)) expect(m[1]).toMatch(/\.test$/);
  });
});

describe("TenantRegistry", () => {
  const reg = new TenantRegistry(loadTenantConfig(fixtureText));

  it("resolves a configured account to its tenant", () => {
    const r = reg.requireMailbox("ada@example-studio.test");
    expect(r.tenant.id).toBe("example-studio");
    expect(r.mailbox.sendAs).toContain("ada@example-studio-alias.test");
  });

  it("refuses unknown, differently-cased, padded and non-string accounts (rule 1)", () => {
    for (const bad of ["nobody@example-studio.test", "Ada@example-studio.test", " ada@example-studio.test", "", undefined, null, 42, "ada@example-labs.test"]) {
      expect(() => reg.requireMailbox(bad)).toThrow(UnknownAccountError);
    }
    expect(reg.getMailbox("nobody@example-studio.test")).toBeUndefined();
  });

  it("allows only allowlisted From addresses, never another tenant's or an unlisted same-domain one", () => {
    expect(reg.isAllowedSendAs("ada@example-studio.test", "ada@example-studio.test")).toBe(true);
    expect(reg.isAllowedSendAs("ada@example-studio.test", "hello@example-studio.test")).toBe(true);
    expect(reg.isAllowedSendAs("ada@example-studio.test", "press@example-labs.test")).toBe(false); // other tenant
    expect(reg.isAllowedSendAs("ada@example-studio.test", "nobody@example-studio.test")).toBe(false); // same domain, not listed
    expect(reg.isAllowedSendAs("hello@example-studio.test", "ada@example-studio.test")).toBe(false); // listed for a different mailbox
    expect(reg.isAllowedSendAs("ghost@example-studio.test", "ghost@example-studio.test")).toBe(false); // unknown account
  });

  it("public view never exposes secret names", () => {
    const json = JSON.stringify(reg.publicView());
    expect(json).not.toContain("serviceAccountSecret");
    expect(json).not.toContain("SA_EXAMPLE");
    expect(reg.publicView()[0]?.mailboxes[0]?.address).toBe("ada@example-studio.test");
  });
});

describe("parseTenantConfig fails closed (rule 6)", () => {
  it("rejects non-objects, missing and empty tenant lists", () => {
    expect(issuesOf(null)[0]).toMatch(/^\$: must be an object/);
    expect(issuesOf([])[0]).toMatch(/^\$: must be an object/);
    expect(issuesOf({})[0]).toMatch(/^\$\.tenants: must be an array/);
    expect(issuesOf({ tenants: [] })[0]).toMatch(/at least one tenant/);
  });

  it("rejects invalid JSON text", () => {
    expect(() => loadTenantConfig("{ not json")).toThrow(TenantConfigError);
  });

  it("rejects unknown keys at every level (typo protection)", () => {
    expect(issuesOf(mutated((d) => { d["tenant"] = []; }))).toContainEqual(expect.stringMatching(/^\$\.tenant: unknown key/));
    expect(issuesOf(mutated((d) => { tenant(d, 0)["sendas"] = []; }))).toContainEqual(expect.stringMatching(/tenants\[0\]\.sendas: unknown key/));
    expect(issuesOf(mutated((d) => { mailbox(d, 0, 0)["sendas"] = []; }))).toContainEqual(expect.stringMatching(/mailboxes\[0\]\.sendas: unknown key/));
  });

  it("rejects duplicate tenant ids, shared secrets and domains owned by two tenants", () => {
    expect(issuesOf(mutated((d) => { tenant(d, 1)["id"] = "example-studio"; }))).toContainEqual(expect.stringMatching(/tenants\[1\]\.id: duplicate/));
    expect(issuesOf(mutated((d) => { tenant(d, 1)["serviceAccountSecret"] = "SA_EXAMPLE_STUDIO"; }))).toContainEqual(expect.stringMatching(/serviceAccountSecret: shared with/));
    expect(issuesOf(mutated((d) => { (tenant(d, 1)["domains"] as string[]).push("example-studio.test"); }))).toContainEqual(expect.stringMatching(/domains\[1\]: already belongs to/));
  });

  it("rejects a secret VALUE-looking string where a secret NAME is expected", () => {
    const issues = issuesOf(mutated((d) => { tenant(d, 0)["serviceAccountSecret"] = '{"type":"service_account"}'; }));
    expect(issues).toContainEqual(expect.stringMatching(/serviceAccountSecret: must be a secret NAME/));
  });

  it("rejects mailboxes and send-as addresses outside the tenant's domains (structural cross-tenant guard)", () => {
    expect(issuesOf(mutated((d) => { mailbox(d, 0, 0)["address"] = "ada@example-labs.test"; }))).toContainEqual(expect.stringMatching(/mailboxes\[0\]\.address: domain is not one of this tenant's domains/));
    expect(issuesOf(mutated((d) => { (mailbox(d, 0, 0)["sendAs"] as string[]).push("press@example-labs.test"); }))).toContainEqual(expect.stringMatching(/sendAs\[3\]: domain is not one of this tenant's domains/));
    expect(issuesOf(mutated((d) => { (mailbox(d, 0, 0)["sendAs"] as string[]).push("ada@consumer-mail.example"); }))).toContainEqual(expect.stringMatching(/sendAs\[3\]: domain is not one of this tenant's domains/));
  });

  it("requires sendAs to include the mailbox's own address and to be unique", () => {
    expect(issuesOf(mutated((d) => { mailbox(d, 0, 1)["sendAs"] = ["ada@example-studio.test"]; }))).toContainEqual(expect.stringMatching(/mailboxes\[1\]\.sendAs: must include the mailbox's own address/));
    expect(issuesOf(mutated((d) => { mailbox(d, 0, 1)["sendAs"] = ["hello@example-studio.test", "hello@example-studio.test"]; }))).toContainEqual(expect.stringMatching(/sendAs\[1\]: duplicate within mailbox/));
  });

  it("rejects uppercase or padded addresses instead of normalising them", () => {
    expect(issuesOf(mutated((d) => { mailbox(d, 0, 1)["address"] = "Hello@example-studio.test"; }))).toContainEqual(expect.stringMatching(/mailboxes\[1\]\.address: must be a lowercase email/));
    expect(issuesOf(mutated((d) => { (tenant(d, 0)["domains"] as string[])[0] = "Example-Studio.test"; })).length).toBeGreaterThan(0);
  });

  it("rejects a mailbox address configured in two tenants", () => {
    const issues = issuesOf(mutated((d) => {
      (tenant(d, 1)["domains"] as string[]).push("shared.test");
      (tenant(d, 0)["domains"] as string[]).push("shared.test");
    }));
    expect(issues).toContainEqual(expect.stringMatching(/already belongs to/));
  });

  it("reports every issue at once with JSON paths, never a partial config", () => {
    const issues = issuesOf(mutated((d) => {
      tenant(d, 0)["label"] = "";
      mailbox(d, 1, 0)["address"] = "grace@example-studio.test";
      delete tenant(d, 1)["serviceAccountSecret"];
    }));
    expect(issues.length).toBeGreaterThanOrEqual(3);
    for (const i of issues) expect(i).toMatch(/^\$\.tenants\[\d\]/);
  });
});
