import { beforeAll, describe, expect, it, vi } from "vitest";
import { b64urlDecode } from "../../src/auth/encoding.js";
import { DelegationError, DelegationTokenSource, GMAIL_SCOPE, GOOGLE_TOKEN_ENDPOINT, importServiceAccountKey, parseServiceAccountKey, signAssertion } from "../../src/gmail/delegation.js";
import { EgressDeniedError, GOOGLE_EGRESS, createEgressFetch } from "../../src/net/egress.js";
import { TenantRegistry, loadTenantConfig } from "../../src/tenants/index.js";
import { readFileSync } from "node:fs";
import { FakeGoogle, LABS_GRACE, STUDIO_ADA, STUDIO_HELLO, makeServiceAccount, type TestServiceAccount } from "../helpers/fake-gmail.js";

const fixture = readFileSync(new URL("../../fixtures/tenants.example.json", import.meta.url), "utf8");
const registry = new TenantRegistry(loadTenantConfig(fixture));
const ada = registry.requireMailbox(STUDIO_ADA);
const hello = registry.requireMailbox(STUDIO_HELLO);
const grace = registry.requireMailbox(LABS_GRACE);
const NOW = Date.UTC(2026, 10, 3, 12, 0, 0);

let studioSa: TestServiceAccount;
let labsSa: TestServiceAccount;
beforeAll(async () => {
  studioSa = await makeServiceAccount("multimail-studio@fake-project.iam.gserviceaccount.test");
  labsSa = await makeServiceAccount("multimail-labs@fake-project.iam.gserviceaccount.test");
});

function google(): FakeGoogle {
  return new FakeGoogle(
    [
      { sa: studioSa, mailboxes: [STUDIO_ADA, STUDIO_HELLO] },
      { sa: labsSa, mailboxes: [LABS_GRACE] },
    ],
    {},
  );
}

function source(g: FakeGoogle, secrets: Record<string, unknown> = { SA_EXAMPLE_STUDIO: studioSa.json, SA_EXAMPLE_LABS: labsSa.json }, now: () => number = () => NOW): DelegationTokenSource {
  // Through the real egress wrapper, so a wrong host or a redirect would be refused exactly as in production.
  return new DelegationTokenSource({ secrets, fetch: createEgressFetch(GOOGLE_EGRESS, g.fetch), now });
}

describe("parseServiceAccountKey", () => {
  it("accepts Google's key file shape and keeps only the two fields needed", () => {
    const k = parseServiceAccountKey(studioSa.json);
    expect(k.clientEmail).toBe(studioSa.clientEmail);
    expect(k.privateKeyPem).toContain("BEGIN PRIVATE KEY");
    expect(Object.keys(k).sort()).toEqual(["clientEmail", "privateKeyPem"]);
  });

  it("refuses anything that is not a service-account key, without quoting it", () => {
    const base = JSON.parse(studioSa.json) as Record<string, unknown>;
    const cases: [string, unknown][] = [
      ["not json", "{"],
      ["array", "[]"],
      ["wrong type", JSON.stringify({ ...base, type: "authorized_user" })],
      ["no email", JSON.stringify({ ...base, client_email: undefined })],
      ["no key", JSON.stringify({ ...base, private_key: "nope" })],
      ["foreign token_uri", JSON.stringify({ ...base, token_uri: "https://evil.example.test/token" })],
    ];
    for (const [name, text] of cases) {
      expect(() => parseServiceAccountKey(text as string), name).toThrow();
      try {
        parseServiceAccountKey(text as string);
      } catch (e) {
        expect((e as Error).message, name).not.toContain("PRIVATE KEY");
        expect((e as Error).message, name).not.toContain("evil");
      }
    }
  });
});

describe("signAssertion", () => {
  it("produces an RS256 JWT that verifies with the public key and carries exactly the delegation claims", async () => {
    const key = await importServiceAccountKey(parseServiceAccountKey(studioSa.json));
    const iat = Math.floor(NOW / 1000);
    const jwt = await signAssertion(key, { iss: studioSa.clientEmail, sub: STUDIO_ADA, scope: GMAIL_SCOPE, aud: GOOGLE_TOKEN_ENDPOINT, iat, exp: iat + 3600 });
    const [h, p, s] = jwt.split(".") as [string, string, string];
    expect(JSON.parse(new TextDecoder().decode(b64urlDecode(h)))).toEqual({ alg: "RS256", typ: "JWT" });
    const claims = JSON.parse(new TextDecoder().decode(b64urlDecode(p))) as Record<string, unknown>;
    expect(claims).toEqual({ iss: studioSa.clientEmail, sub: STUDIO_ADA, scope: "https://www.googleapis.com/auth/gmail.modify", aud: "https://oauth2.googleapis.com/token", iat, exp: iat + 3600 });
    const ok = await crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, studioSa.publicKey, b64urlDecode(s), new TextEncoder().encode(`${h}.${p}`));
    expect(ok).toBe(true);
    expect(key.extractable).toBe(false);
  });
});

describe("DelegationTokenSource", () => {
  it("mints a token whose subject is the mailbox, via the egress-checked fetch, and caches it per mailbox", async () => {
    const g = google();
    const src = source(g);
    const t1 = await src.tokenFor(ada);
    const t2 = await src.tokenFor(ada);
    expect(t1).toBe(t2);
    expect(g.tokensIssued).toBe(1);
    const t3 = await src.tokenFor(hello);
    expect(t3).not.toBe(t1);
    expect(g.tokensIssued).toBe(2);
    expect(g.calls.every((c) => c.path === "/token" && c.method === "POST")).toBe(true);
  });

  it("shares one exchange between concurrent calls for the same mailbox", async () => {
    const g = google();
    const src = source(g);
    const tokens = await Promise.all([src.tokenFor(grace), src.tokenFor(grace), src.tokenFor(grace)]);
    expect(new Set(tokens).size).toBe(1);
    expect(g.tokensIssued).toBe(1);
  });

  it("refreshes a minute before Google's expiry, and after an explicit invalidate", async () => {
    const g = google();
    let now = NOW;
    const src = source(g, undefined, () => now);
    const first = await src.tokenFor(ada);
    now += 3600 * 1000 - 120 * 1000; // 58 min later: still fresh
    expect(await src.tokenFor(ada)).toBe(first);
    now += 61 * 1000; // inside the safety margin
    const second = await src.tokenFor(ada);
    expect(second).not.toBe(first);
    expect(g.tokensIssued).toBe(2);
    src.invalidate(ada);
    expect(await src.tokenFor(ada)).not.toBe(second);
    expect(g.tokensIssued).toBe(3);
  });

  it("uses each tenant's own service account: a studio mailbox is never signed by the labs key", async () => {
    const g = google();
    // Swap the secrets: the labs key under the studio's secret name. Google (the fake, like the real one) refuses.
    const src = source(g, { SA_EXAMPLE_STUDIO: labsSa.json, SA_EXAMPLE_LABS: studioSa.json });
    await expect(src.tokenFor(ada)).rejects.toMatchObject({ name: "DelegationError", code: "delegation_token_refused", detail: "unauthorized_client" });
    expect(g.tokensIssued).toBe(0);
  });

  it("missing secret: loud DelegationError naming the tenant and mailbox, not the secret; nothing is fetched", async () => {
    const g = google();
    const src = source(g, { SA_EXAMPLE_LABS: labsSa.json });
    const err = await src.tokenFor(ada).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(DelegationError);
    const e = err as DelegationError;
    expect(e.code).toBe("service_account_secret_missing");
    expect(e.tenantId).toBe("example-studio");
    expect(e.message).toContain("example-studio");
    expect(e.message).toContain(STUDIO_ADA);
    expect(e.message).not.toContain("SA_EXAMPLE_STUDIO");
    expect(e.message).toMatch(/not an empty mailbox/);
    expect(e.detail).toBe("SA_EXAMPLE_STUDIO"); // for the Worker log only
    expect(g.calls).toHaveLength(0);
    // An empty string is "missing" too.
    await expect(source(g, { SA_EXAMPLE_STUDIO: "  " }).tokenFor(ada)).rejects.toMatchObject({ code: "service_account_secret_missing" });
  });

  it("malformed secret: loud DelegationError, no key material in the message, nothing is fetched", async () => {
    const g = google();
    for (const bad of ["not json", "{}", JSON.stringify({ type: "service_account", client_email: "x@y.test", private_key: "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----" })]) {
      const err = (await source(g, { SA_EXAMPLE_STUDIO: bad }).tokenFor(ada).catch((e: unknown) => e)) as DelegationError;
      expect(err.code, bad).toBe("service_account_key_invalid");
      expect(err.message).not.toContain("AAAA");
      expect(err.message).not.toContain("SA_EXAMPLE_STUDIO");
    }
    expect(g.calls).toHaveLength(0);
  });

  it("Google refuses the assertion: loud error with the status, Google's code and an operator hint", async () => {
    const g = google();
    g.tokenFailure = { status: 401, error: "unauthorized_client" };
    const err = (await source(g).tokenFor(ada).catch((e: unknown) => e)) as DelegationError;
    expect(err.code).toBe("delegation_token_refused");
    expect(err.message).toContain("401");
    expect(err.message).toContain("unauthorized_client");
    expect(err.message).toContain("domain-wide delegation");
    expect(err.message).toContain("No mail was read");
    // A failure is not cached: the next call tries again.
    g.tokenFailure = undefined;
    await expect(source(g).tokenFor(ada)).resolves.toMatch(/^fake-token-/);
  });

  it("a token response without a usable token is a malformed-response error, never a silent empty token", async () => {
    for (const body of ["not json", "{}", JSON.stringify({ access_token: "", expires_in: 3600 }), JSON.stringify({ access_token: "t", expires_in: "soon" })]) {
      const f = vi.fn(async () => new Response(body, { status: 200 }));
      const src = new DelegationTokenSource({ secrets: { SA_EXAMPLE_STUDIO: studioSa.json }, fetch: f, now: () => NOW });
      await expect(src.tokenFor(ada), body).rejects.toMatchObject({ code: "delegation_token_malformed" });
    }
  });

  it("a redirecting token endpoint is refused by the egress wrapper before any token is accepted", async () => {
    const redirecting = async () => new Response(null, { status: 302, headers: { location: "https://evil.example.test/" } });
    const src = new DelegationTokenSource({ secrets: { SA_EXAMPLE_STUDIO: studioSa.json }, fetch: createEgressFetch(GOOGLE_EGRESS, redirecting), now: () => NOW });
    await expect(src.tokenFor(ada)).rejects.toBeInstanceOf(EgressDeniedError);
  });

  it("never writes the token or the key to the console", async () => {
    const g = google();
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const err = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    try {
      const token = await source(g).tokenFor(ada);
      g.tokenFailure = { status: 400, error: "invalid_grant" };
      await source(g).tokenFor(hello).catch(() => undefined);
      const everything = [...log.mock.calls, ...err.mock.calls, ...warn.mock.calls].flat().map(String).join("\n");
      expect(everything).not.toContain(token);
      expect(everything).not.toContain("PRIVATE KEY");
    } finally {
      log.mockRestore();
      err.mockRestore();
      warn.mockRestore();
    }
  });
});
