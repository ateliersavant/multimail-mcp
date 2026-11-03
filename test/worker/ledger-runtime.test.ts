import { describe, expect, it } from "vitest";
import { env } from "cloudflare:workers";
import { DurableSendLedger } from "../../src/gmail/ledger.js";
import { withConsistentStore } from "../../src/store/env.js";

const ADA = "ada@example-studio.test";
const GRACE = "grace@example-labs.test";

// The production ledger over the production store (the OAuth Durable Object), in workerd.
describe("DurableSendLedger on the Durable Object store", () => {
  it("claims once, refuses a second claim, keeps mailboxes apart, and never releases a sent record", async () => {
    const now = Date.UTC(2026, 10, 3, 12, 0, 0);
    const ledger = new DurableSendLedger(env.OAUTH_STORE);
    expect(await ledger.lookup(ADA, "r-1")).toBeNull();
    expect(await ledger.claim(ADA, "r-1", now)).toEqual({ claimed: true });
    expect(await ledger.claim(ADA, "r-1", now + 5)).toEqual({ claimed: false, entry: { state: "sending", since: now } });
    expect(await ledger.claim(GRACE, "r-1", now)).toEqual({ claimed: true }); // same draft id, other mailbox
    await ledger.release(ADA, "r-1");
    expect(await ledger.lookup(ADA, "r-1")).toBeNull();
    expect(await ledger.claim(ADA, "r-1", now)).toEqual({ claimed: true });
    await ledger.markSent(ADA, "r-1", { messageId: "m-9", threadId: "t-9", sentAt: now });
    await ledger.release(ADA, "r-1"); // a late release after a send must not erase the record
    const sent = { state: "sent", record: { messageId: "m-9", threadId: "t-9", sentAt: now } };
    expect(await ledger.lookup(ADA, "r-1")).toEqual(sent);
    expect(await ledger.claim(ADA, "r-1", now)).toEqual({ claimed: false, entry: sent });
  });

  it("lets exactly one of many concurrent claims through", async () => {
    const ledger = new DurableSendLedger(env.OAUTH_STORE);
    const results = await Promise.all(Array.from({ length: 12 }, () => ledger.claim(ADA, "r-race", Date.now())));
    expect(results.filter((r) => r.claimed)).toHaveLength(1);
  });

  it("does not collide with the OAuth library's own keys", async () => {
    const kv = withConsistentStore(env).OAUTH_KV;
    await new DurableSendLedger(env.OAUTH_STORE).markSent(ADA, "r-2", { messageId: "m", threadId: "t", sentAt: 1 });
    for (const prefix of ["client:", "grant:", "token:", "transaction:"]) {
      const page = await kv.list({ prefix });
      expect(page.keys.some((k) => k.name.includes("r-2")), prefix).toBe(false);
    }
  });
});
