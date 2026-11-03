import { describe, expect, it } from "vitest";
import { DEFAULT_LIMITS, MemoryRateLimiter, decide, parseLimit } from "../../src/guard/ratelimit.js";

describe("fixed-window arithmetic", () => {
  const t0 = Date.UTC(2026, 10, 3, 12, 0, 0);
  it("allows up to the limit in a window, then refuses with the seconds left; a new window resets", () => {
    let prev: { windowStart: number; count: number } | undefined;
    for (let i = 1; i <= 3; i++) {
      const r = decide(prev, 3, 60, t0 + i * 1000);
      expect(r.decision).toEqual({ allowed: true, count: i, retryAfterSeconds: 0 });
      prev = r.next;
    }
    const over = decide(prev, 3, 60, t0 + 10_000);
    expect(over.decision.allowed).toBe(false);
    expect(over.decision.retryAfterSeconds).toBe(50);
    expect(over.next).toBeUndefined();
    expect(decide(prev, 3, 60, t0 + 61_000).decision).toEqual({ allowed: true, count: 1, retryAfterSeconds: 0 });
  });

  it("keeps different keys and window sizes apart", async () => {
    let now = t0;
    const rl = new MemoryRateLimiter(() => now);
    expect((await rl.hit("send:a", 1, 3600)).allowed).toBe(true);
    expect((await rl.hit("send:a", 1, 3600)).allowed).toBe(false);
    expect((await rl.hit("send:b", 1, 3600)).allowed).toBe(true);
    expect((await rl.hit("send:a", 5, 86_400)).allowed).toBe(true); // same key, other window
    now += 3600 * 1000;
    expect((await rl.hit("send:a", 1, 3600)).allowed).toBe(true);
  });

  it("parses overrides strictly, falling back on junk or out-of-range values", () => {
    expect(parseLimit("40", 120, 5, 10_000)).toBe(40);
    for (const bad of [undefined, "", "abc", "-5", "1e3", "4", "999999", " 12x"]) expect(parseLimit(bad, 120, 5, 10_000), String(bad)).toBe(120);
    expect(DEFAULT_LIMITS).toEqual({ mcpPerMinute: 120, draftsPerHour: 120, sendsPerHour: 20, sendsPerDay: 100 });
  });
});
