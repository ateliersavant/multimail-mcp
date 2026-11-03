import { describe, expect, it } from "vitest";
import { env } from "cloudflare:workers";
import { KvSendLedger, SENDING_TTL_SECONDS } from "../../src/gmail/ledger.js";
import { withConsistentStore } from "../../src/store/env.js";

// The production ledger over the production store (the OAuth Durable Object), in workerd.
describe("KvSendLedger on the Durable Object store", () => {
  it("remembers a sent draft, expires an in-flight marker, and keeps mailboxes apart", async () => {
    let now = Date.UTC(2026, 10, 3, 12, 0, 0);
    const ledger = new KvSendLedger(withConsistentStore(env).OAUTH_KV, () => now);
    expect(await ledger.lookup("ada@example-studio.test", "r-1")).toBeNull();
    await ledger.markSending("ada@example-studio.test", "r-1", now);
    expect(await ledger.lookup("ada@example-studio.test", "r-1")).toEqual({ state: "sending", since: now });
    expect(await ledger.lookup("grace@example-labs.test", "r-1")).toBeNull(); // same draft id, other mailbox
    now += (SENDING_TTL_SECONDS + 1) * 1000;
    expect(await ledger.lookup("ada@example-studio.test", "r-1")).toBeNull(); // a stale marker never blocks forever
    await ledger.markSent("ada@example-studio.test", "r-1", { messageId: "m-9", threadId: "t-9", sentAt: now });
    expect(await ledger.lookup("ada@example-studio.test", "r-1")).toEqual({ state: "sent", record: { messageId: "m-9", threadId: "t-9", sentAt: now } });
    await ledger.clear("ada@example-studio.test", "r-1");
    expect(await ledger.lookup("ada@example-studio.test", "r-1")).toBeNull();
  });

  it("does not collide with the OAuth library's own keys", async () => {
    const kv = withConsistentStore(env).OAUTH_KV;
    await new KvSendLedger(kv).markSent("ada@example-studio.test", "r-2", { messageId: "m", threadId: "t", sentAt: 1 });
    for (const prefix of ["client:", "grant:", "token:", "transaction:"]) {
      const page = await kv.list({ prefix });
      expect(page.keys.some((k) => k.name.includes("r-2")), prefix).toBe(false);
    }
  });
});
