/**
 * Rule 5: send_draft never reports success on inference, never sends a draft twice, and says `failed` / "nothing was
 * sent" only when nothing was sent. Originally the ledger was read with lookup() and written with markSending() several
 * awaits later, so the in-flight marker was not a lock; now a send starts with one atomic claim().
 */
import { afterEach, describe, expect, it } from "vitest";
import { MemorySendLedger, type SendLedger } from "../../src/gmail/ledger.js";
import { STUDIO_ADA } from "../helpers/fake-gmail.js";
import { NOW, harness, text, type Harness } from "../helpers/mcp-harness.js";

let h: Harness | undefined;
afterEach(async () => {
  await h?.close();
  h = undefined;
});

async function draftId(x: Harness): Promise<string> {
  const r = await x.call("create_draft", { account: STUDIO_ADA, from: STUDIO_ADA, to: ["bill@vendor.test"], subject: "Invoice 1042 paid", body_text: "Paid today." });
  expect(r.isError, text(r)).toBeFalsy();
  return (r.structuredContent as { draftId: string }).draftId;
}
const sendCalls = (x: Harness): number => x.google.calls.filter((c) => c.method === "POST" && c.path.endsWith("/drafts/send")).length;

describe("send_draft and the sent-draft ledger", () => {
  it("two concurrent send_draft calls for one draft (a client retry while the first is in flight): one reaches Gmail, neither claims 'nothing was sent', the ledger still says already_sent", async () => {
    h = await harness();
    const id = await draftId(h);
    const [a, b] = await Promise.all([h.call("send_draft", { account: STUDIO_ADA, draft_id: id }), h.call("send_draft", { account: STUDIO_ADA, draft_id: id })]);
    const outcomes = [a, b].map((r) => ({ isError: r.isError === true, status: (r.structuredContent as { status?: string } | undefined)?.status ?? null, saysNothingSent: /Nothing was sent/.test(text(r)) }));
    const retry = await h.call("send_draft", { account: STUDIO_ADA, draft_id: id });
    const retryCode = h.written.at(-1)?.errorCode;
    expect({ gmailSent: h.google.sentLog.length, draftsSendCalls: sendCalls(h), anyClaimsNothingSent: outcomes.some((o) => o.saysNothingSent), outcomes, retryCode, retryIsError: retry.isError === true }).toEqual({
      gmailSent: 1,
      draftsSendCalls: 1,
      anyClaimsNothingSent: false,
      outcomes: expect.any(Array),
      retryCode: "already_sent",
      retryIsError: true,
    });
  });

  it("a ledger write that fails AFTER Gmail sent the message is not reported as 'Nothing was sent'", async () => {
    const inner = new MemorySendLedger(() => NOW);
    const flaky: SendLedger = {
      lookup: (a, d) => inner.lookup(a, d),
      claim: (a, d, n) => inner.claim(a, d, n),
      markSent: async () => {
        throw new Error("Durable Object storage operation exceeded timeout"); // a transient DO failure
      },
      release: (a, d) => inner.release(a, d),
    };
    h = await harness({ ledger: flaky });
    const id = await draftId(h);
    const r = await h.call("send_draft", { account: STUDIO_ADA, draft_id: id });
    expect(h.google.sentLog).toHaveLength(1); // Gmail did send it
    expect(text(r)).not.toMatch(/Nothing was sent/);
  });
});
