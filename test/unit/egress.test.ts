import { describe, expect, it, vi } from "vitest";
import { EgressDeniedError, GOOGLE_EGRESS, assertEgressAllowed, createEgressFetch, type FetchLike } from "../../src/net/egress.js";

const ok: FetchLike = () => Promise.resolve(new Response("ok"));

describe("egress allowlist", () => {
  it("allows exactly the Google requests v1 makes", () => {
    const allowed: [string, string][] = [
      ["POST", "https://oauth2.googleapis.com/token"],
      ["GET", "https://www.googleapis.com/oauth2/v3/certs"],
      ["GET", "https://gmail.googleapis.com/gmail/v1/users/me/threads?q=x"],
      ["GET", "https://gmail.googleapis.com/gmail/v1/users/ada%40example-studio.test/threads/18c2f"],
      ["GET", "https://gmail.googleapis.com/gmail/v1/users/ada%40example-studio.test/messages/18c2f?format=full"],
      ["GET", "https://gmail.googleapis.com/gmail/v1/users/me/labels"],
      ["GET", "https://gmail.googleapis.com/gmail/v1/users/me/settings/sendAs"],
      ["GET", "https://gmail.googleapis.com/gmail/v1/users/me/drafts"],
      ["POST", "https://gmail.googleapis.com/gmail/v1/users/me/drafts"],
      ["GET", "https://gmail.googleapis.com/gmail/v1/users/me/drafts/r-123"],
      ["PUT", "https://gmail.googleapis.com/gmail/v1/users/me/drafts/r-123"],
      ["DELETE", "https://gmail.googleapis.com/gmail/v1/users/me/drafts/r-123"],
      ["POST", "https://gmail.googleapis.com/gmail/v1/users/me/drafts/send"],
      ["POST", "https://gmail.googleapis.com/gmail/v1/users/me/threads/18c2f/modify"],
      ["POST", "https://gmail.googleapis.com/gmail/v1/users/me/messages/18c2f/modify"],
      ["POST", "https://gmail.googleapis.com/gmail/v1/users/me/threads/18c2f/trash"],
      ["POST", "https://gmail.googleapis.com/gmail/v1/users/me/threads/18c2f/untrash"],
    ];
    for (const [m, u] of allowed) expect(() => assertEgressAllowed(new URL(u), GOOGLE_EGRESS, m), `${m} ${u}`).not.toThrow();
  });

  it("denies everything else gmail.modify could do: direct send, per-message trash, bulk changes, deletes, other methods", () => {
    const denied: [string, string][] = [
      ["POST", "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"],
      ["POST", "https://gmail.googleapis.com/gmail/v1/users/me/messages/18c2f/trash"],
      ["POST", "https://gmail.googleapis.com/gmail/v1/users/me/messages/batchModify"],
      ["POST", "https://gmail.googleapis.com/gmail/v1/users/me/messages/batchDelete"],
      ["DELETE", "https://gmail.googleapis.com/gmail/v1/users/me/threads/18c2f"],
      ["GET", "https://gmail.googleapis.com/gmail/v1/users/me/threads/18c2f/trash"],
      ["DELETE", "https://gmail.googleapis.com/gmail/v1/users/me/messages/18c2f"],
      ["POST", "https://gmail.googleapis.com/gmail/v1/users/me/messages/import"],
      ["POST", "https://gmail.googleapis.com/gmail/v1/users/me/settings/sendAs"],
      ["POST", "https://gmail.googleapis.com/gmail/v1/users/me/labels"],
      ["GET", "https://gmail.googleapis.com/gmail/v1/users/me/messages/18c2f/attachments/a1"],
      ["GET", "https://gmail.googleapis.com/gmail/v1/users/me/drafts/a%2Fb"], // an escaped slash is not one segment
      ["GET", "https://gmail.googleapis.com/gmail/v1/users/me/threads/"],
      ["GET", "https://oauth2.googleapis.com/token"], // right path, wrong method
      ["POST", "https://oauth2.googleapis.com/revoke"],
      ["POST", "https://oauth2.googleapis.com/token/"],
    ];
    for (const [m, u] of denied) expect(() => assertEgressAllowed(new URL(u), GOOGLE_EGRESS, m), `${m} ${u}`).toThrow(EgressDeniedError);
  });

  it("denies other hosts, other Google APIs, http, ports, credentials and path tricks", () => {
    for (const u of [
      "https://example.com/",
      "https://accounts.google.com/.well-known/openid-configuration", // browser-only host, never fetched
      "https://openidconnect.googleapis.com/v1/userinfo", // not needed: email comes from the verified id_token
      "https://oauth2.googleapis.com/tokeninfo",
      "https://www.googleapis.com/oauth2/v3/certs2",
      "https://gmail.googleapis.com/gmail/v1/usersx/me/labels",
      "https://evil.googleapis.com/gmail/v1/users/me/labels",
      "https://www.googleapis.com/gmail/v1/users/me/labels", // Gmail is not served here in our policy
      "https://www.googleapis.com/drive/v3/files",
      "https://gmail.googleapis.com/upload/gmail/v1/users/me/messages/send",
      "https://gmail.googleapis.com/", // bare host
      "http://gmail.googleapis.com/gmail/v1/users/me/labels",
      "https://gmail.googleapis.com:8443/gmail/v1/users/me/labels",
      "https://user:pw@gmail.googleapis.com/gmail/v1/users/me/labels",
      "https://gmail.googleapis.com.evil.test/gmail/v1/users/me/labels",
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
    await expect(f(new Request("https://gmail.googleapis.com/gmail/v1/users/me/labels", { method: "POST" }))).rejects.toThrow(EgressDeniedError); // method from the Request
    await expect(f("https://gmail.googleapis.com/gmail/v1/users/me/messages/send", { method: "POST" })).rejects.toThrow(EgressDeniedError);
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
