import { describe, expect, it } from "vitest";
import { MemorySendLedger, SENDING_TTL_SECONDS } from "../../src/gmail/ledger.js";

const ADA = "ada@example-studio.test";

describe("send ledger semantics (MemorySendLedger mirrors the Durable Object one)", () => {
  it("claims once, expires a stale claim, and never releases a sent record", async () => {
    let now = Date.UTC(2026, 10, 3, 12, 0, 0);
    const l = new MemorySendLedger(() => now);
    expect(await l.claim(ADA, "r-1", now)).toEqual({ claimed: true });
    expect(await l.claim(ADA, "r-1", now)).toEqual({ claimed: false, entry: { state: "sending", since: now } });
    now += (SENDING_TTL_SECONDS + 1) * 1000;
    expect(await l.claim(ADA, "r-1", now)).toEqual({ claimed: true }); // a crashed send never blocks forever
    await l.markSent(ADA, "r-1", { messageId: "m", threadId: "t", sentAt: now });
    await l.release(ADA, "r-1");
    expect(await l.lookup(ADA, "r-1")).toEqual({ state: "sent", record: { messageId: "m", threadId: "t", sentAt: now } });
    expect((await l.claim(ADA, "r-1", now)).claimed).toBe(false);
  });

  it("release drops an in-flight claim", async () => {
    const now = Date.UTC(2026, 10, 3, 12, 0, 0);
    const l = new MemorySendLedger(() => now);
    await l.claim(ADA, "r-2", now);
    await l.release(ADA, "r-2");
    expect(await l.lookup(ADA, "r-2")).toBeNull();
    expect(await l.claim(ADA, "r-2", now)).toEqual({ claimed: true });
  });
});
