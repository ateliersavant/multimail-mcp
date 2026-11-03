/**
 * Email content is untrusted, but the server must still present it faithfully. renderHeaders() (src/gmail/render.ts)
 * cuts every header value to 2000 characters WITHOUT any truncation flag (bodies are flagged, headers are not). Any
 * outside sender can therefore choose a From whose first 2000 characters end in someone else's address: the model
 * (and the human reading its summary) is told the mail came from that address, while Gmail shows the real sender.
 * Zero-width spaces (not collapsed by normaliseWhitespace) make the padding invisible.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { STUDIO_ADA, sampleMailboxes } from "../helpers/fake-gmail.js";
import { harness, text, type Harness } from "../helpers/mcp-harness.js";

const ATTACKER = "attacker@evil.test";
const SPOOFED = "ceo@example-studio.test";
const ZWSP = "​";
const FROM = `"${ZWSP.repeat(2000 - 27)} <${SPOOFED}>" <${ATTACKER}>`; // one valid mailbox: display name + real address

let h: Harness;
beforeEach(async () => {
  const boxes = sampleMailboxes();
  const ada = boxes[STUDIO_ADA];
  if (ada === undefined) throw new Error("fixture");
  boxes[STUDIO_ADA] = {
    ...ada,
    messages: [...ada.messages, { id: "m-spoof", threadId: "t-spoof", from: FROM, to: STUDIO_ADA, subject: "Urgent: approve the wire today", date: "Tue, 3 Nov 2026 09:00:00 +0000", internalDate: Date.UTC(2026, 10, 3, 9), text: "Please approve the transfer before noon." }],
  };
  h = await harness({ mailboxes: boxes });
});
afterEach(async () => h.close());

describe("sender shown to the model", () => {
  it("get_message shows the real sender address of a message with a 2000+ character From", async () => {
    const r = await h.call("get_message", { account: STUDIO_ADA, message_id: "m-spoof" });
    expect(r.isError, text(r)).toBeFalsy();
    const from = (r.structuredContent as { message: { headers: { from?: string } } }).message.headers.from ?? "";
    expect({ endsWith: from.replaceAll(ZWSP, "").slice(-40), containsRealSender: from.includes(ATTACKER) }).toEqual({ endsWith: expect.any(String), containsRealSender: true });
  });

  it("search_threads participants show the real sender", async () => {
    const r = await h.call("search_threads", { account: STUDIO_ADA, query: "wire" });
    expect(r.isError, text(r)).toBeFalsy();
    const participants = (r.structuredContent as { threads: { participants: string[] }[] }).threads.flatMap((t) => t.participants);
    expect(participants.some((p) => p.includes(ATTACKER))).toBe(true);
  });
});
