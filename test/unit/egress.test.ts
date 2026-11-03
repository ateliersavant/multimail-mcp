import { describe, expect, it, vi } from "vitest";
import { EgressDeniedError, GOOGLE_EGRESS, assertEgressAllowed, createEgressFetch, type FetchLike } from "../../src/net/egress.js";

const ok: FetchLike = () => Promise.resolve(new Response("ok"));

describe("egress allowlist", () => {
  it("allows exactly the Google endpoints v1 needs", () => {
    for (const u of [
      "https://oauth2.googleapis.com/token",
      "https://oauth2.googleapis.com/revoke",
      "https://oauth2.googleapis.com/token/", // boundary: trailing slash on an exact entry is still that path
      "https://www.googleapis.com/oauth2/v3/certs",
      "https://gmail.googleapis.com/gmail/v1/users/me/messages?q=x",
      "https://gmail.googleapis.com/gmail/v1/users/ada%40example-studio.test/drafts/abc/send",
    ]) {
      expect(() => assertEgressAllowed(new URL(u), GOOGLE_EGRESS)).not.toThrow();
    }
  });

  it("denies other hosts, other Google APIs, http, ports, credentials and path tricks", () => {
    for (const u of [
      "https://example.com/",
      "https://accounts.google.com/.well-known/openid-configuration", // browser-only host, never fetched
      "https://openidconnect.googleapis.com/v1/userinfo", // not needed: email comes from the verified id_token
      "https://oauth2.googleapis.com/tokeninfo", // prefix "/token" must not leak onto "/tokeninfo"
      "https://www.googleapis.com/oauth2/v3/certs2",
      "https://gmail.googleapis.com/gmail/v1/usersx/me",
      "https://evil.googleapis.com/gmail/v1/users/me",
      "https://www.googleapis.com/gmail/v1/users/me", // Gmail is not served here in our policy
      "https://www.googleapis.com/drive/v3/files",
      "https://gmail.googleapis.com/upload/gmail/v1/users/me/messages/send", // attachment upload is not v1
      "https://gmail.googleapis.com/", // bare host
      "http://gmail.googleapis.com/gmail/v1/users/me/messages",
      "https://gmail.googleapis.com:8443/gmail/v1/users/me/messages",
      "https://user:pw@gmail.googleapis.com/gmail/v1/users/me/messages",
      "https://gmail.googleapis.com.evil.test/gmail/v1/users/me/messages",
    ]) {
      expect(() => assertEgressAllowed(new URL(u), GOOGLE_EGRESS), u).toThrow(EgressDeniedError);
    }
  });
});

describe("createEgressFetch", () => {
  it("passes allowed requests through, asking for redirects to be returned unfollowed", async () => {
    const underlying = vi.fn<FetchLike>(ok);
    const f = createEgressFetch(GOOGLE_EGRESS, underlying);
    await f("https://oauth2.googleapis.com/token", { method: "POST", redirect: "follow" });
    expect(underlying).toHaveBeenCalledTimes(1);
    const [url, init] = underlying.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://oauth2.googleapis.com/token");
    expect(init.method).toBe("POST");
    expect(init.redirect).toBe("manual"); // the Workers runtime rejects "error"
  });

  it("never calls the underlying fetch for a denied URL, whatever the input type", async () => {
    const underlying = vi.fn<FetchLike>(ok);
    const f = createEgressFetch(GOOGLE_EGRESS, underlying);
    await expect(f("https://example.com/x")).rejects.toThrow(EgressDeniedError);
    await expect(f(new URL("https://www.googleapis.com/drive/v3/files"))).rejects.toThrow(EgressDeniedError);
    await expect(f(new Request("https://hooks.slack.test/abc", { method: "POST" }))).rejects.toThrow(EgressDeniedError);
    expect(underlying).not.toHaveBeenCalled();
  });

  it("handles Request inputs and keeps their method and headers", async () => {
    const underlying = vi.fn<FetchLike>(ok);
    const f = createEgressFetch(GOOGLE_EGRESS, underlying);
    await f(new Request("https://gmail.googleapis.com/gmail/v1/users/me/labels", { headers: { authorization: "Bearer t" } }));
    const [req] = underlying.mock.calls[0] as unknown as [Request];
    expect(req).toBeInstanceOf(Request);
    expect(req.url).toBe("https://gmail.googleapis.com/gmail/v1/users/me/labels");
    expect(req.headers.get("authorization")).toBe("Bearer t");
    expect(req.redirect).toBe("manual");
  });

  it("refuses every 3xx response instead of following it", async () => {
    for (const status of [301, 302, 303, 307, 308]) {
      const redirecting: FetchLike = () => Promise.resolve(new Response(null, { status, headers: { location: "https://evil.example.test/" } }));
      const f = createEgressFetch(GOOGLE_EGRESS, redirecting);
      await expect(f("https://oauth2.googleapis.com/token", { method: "POST" }), String(status)).rejects.toThrow(EgressDeniedError);
    }
  });

  it("calls the runtime fetch through the global object by default (a detached fetch throws in Workers)", async () => {
    const original = globalThis.fetch;
    let sawThis: unknown = "unset";
    globalThis.fetch = function (this: unknown) {
      sawThis = this;
      if (this !== undefined && this !== globalThis) throw new TypeError("Illegal invocation");
      return Promise.resolve(new Response("ok"));
    } as typeof fetch;
    try {
      const f = createEgressFetch(GOOGLE_EGRESS);
      const res = await f("https://www.googleapis.com/oauth2/v3/certs");
      expect(res.status).toBe(200);
      expect(sawThis === undefined || sawThis === globalThis).toBe(true);
    } finally {
      globalThis.fetch = original;
    }
  });
});
