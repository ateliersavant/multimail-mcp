import { describe, expect, it } from "vitest";
import { env } from "cloudflare:workers";
import { DurableRateLimiter } from "../../src/guard/ratelimit.js";

const stub = () => env.OAUTH_STORE.get(env.OAUTH_STORE.idFromName("oauth-v1"));
const t0 = Date.UTC(2026, 10, 3, 12, 0, 0);

describe("rate limiting in the store Durable Object", () => {
  it("allows up to the limit per window, refuses after, resets with the next window", async () => {
    const s = stub();
    expect((await s.hit("rt:a", 2, 60, t0 + 1000)).allowed).toBe(true);
    expect((await s.hit("rt:a", 2, 60, t0 + 2000)).allowed).toBe(true);
    const over = await s.hit("rt:a", 2, 60, t0 + 3000);
    expect(over).toEqual({ allowed: false, count: 2, retryAfterSeconds: 57 });
    expect((await s.hit("rt:a", 2, 60, t0 + 61_000)).allowed).toBe(true);
  });

  it("is exact under concurrency: 20 parallel hits against a limit of 5 admit exactly 5", async () => {
    const s = stub();
    const results = await Promise.all(Array.from({ length: 20 }, () => s.hit("rt:parallel", 5, 60, t0)));
    expect(results.filter((r) => r.allowed)).toHaveLength(5);
  });

  it("the production limiter uses the same store", async () => {
    const rl = new DurableRateLimiter(env.OAUTH_STORE);
    expect((await rl.hit("rt:prod", 1, 3600)).allowed).toBe(true);
    expect((await rl.hit("rt:prod", 1, 3600)).allowed).toBe(false);
  });
});
