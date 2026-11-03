/**
 * Promise 8 / src/net/egress.ts: "The ONLY way this Worker talks to the outside world. Every outbound request must
 * pass an explicit host + path-prefix allowlist ... and may not follow redirects." SECURITY.md: "egress limited in
 * code to Google OAuth and Gmail hosts". The OAuth provider is configured with clientIdMetadataDocumentEnabled
 * (src/oauth/options.ts), and the library resolves a URL-shaped client_id with the GLOBAL fetch (default redirect
 * mode "follow"), from an unauthenticated GET /authorize. Runs in workerd; the global fetch is stubbed, so nothing
 * leaves the machine.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { exports } from "cloudflare:workers";
import { GOOGLE_EGRESS, assertEgressAllowed } from "../../src/net/egress.js";

const ORIGIN = "https://mcp.example.test";
type Fetcher = { fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> };
const worker = (exports as unknown as { default: Fetcher }).default;

afterEach(() => vi.restoreAllMocks());

function outsideAllowlist(u: string): boolean {
  try {
    assertEgressAllowed(new URL(u), GOOGLE_EGRESS);
    return false;
  } catch {
    return true;
  }
}

describe("egress allowlist vs. the OAuth layer", () => {
  it("an unauthenticated /authorize request cannot make the Worker fetch an arbitrary host", async () => {
    const seen: { url: string; redirect: string | undefined }[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = input instanceof Request ? input.url : String(input);
      seen.push({ url, redirect: init?.redirect ?? (input instanceof Request ? input.redirect : undefined) });
      return new Response("not found", { status: 404 });
    });
    const q = new URLSearchParams({
      response_type: "code",
      client_id: "https://attacker.example.net/anything/at/all",
      redirect_uri: "https://attacker.example.net/cb",
      scope: "mail",
      state: "s",
      code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      code_challenge_method: "S256",
      resource: `${ORIGIN}/mcp`,
    });
    try {
      const r = await worker.fetch(new Request(`${ORIGIN}/authorize?${q}`));
      await r.arrayBuffer();
    } catch {
      // The library's CimdFetchError is not an AuthorizationError, so authorizeGet rethrows it (a 500). Irrelevant here:
      // the question is whether the request left the allowlist before that.
    }
    const offList = seen.filter((s) => outsideAllowlist(s.url));
    expect(offList).toEqual([]);
  });
});
