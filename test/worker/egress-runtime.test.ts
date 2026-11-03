import { describe, expect, it } from "vitest";
import { GOOGLE_EGRESS, createEgressFetch, type FetchLike } from "../../src/net/egress.js";

// Runs in workerd, which (unlike Node) rejects redirect: "error". The underlying fetch builds a real Request from the
// wrapper's init, so any option the runtime rejects fails here, with no network access.
const validating: FetchLike = (input, init) => {
  const req = input instanceof Request ? input : new Request(input, init);
  return Promise.resolve(new Response(JSON.stringify({ redirect: req.redirect }), { headers: { "content-type": "application/json" } }));
};

describe("egress wrapper in the Workers runtime", () => {
  it("builds requests the runtime accepts, for string and Request inputs", async () => {
    const f = createEgressFetch(GOOGLE_EGRESS, validating);
    const a = await f("https://oauth2.googleapis.com/token", { method: "POST", body: "x=1" });
    expect(await a.json()).toEqual({ redirect: "manual" });
    const b = await f(new Request("https://gmail.googleapis.com/gmail/v1/users/me/labels"));
    expect(await b.json()).toEqual({ redirect: "manual" });
  });
});
