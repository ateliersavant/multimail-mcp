/**
 * T10 (DoS) and T4 (email content is untrusted): any outside sender controls the HTML of a message. stripHtml()
 * (src/gmail/render.ts) runs several regexes over the WHOLE decoded body before the 20k-character bound is applied,
 * and some of them are quadratic on unterminated constructs ("<!--" without "-->", "<li"/"<p"/"<a" without ">").
 * A modest attacker email therefore pins the Worker's CPU when the user reads it with get_message or get_thread.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { STUDIO_ADA, sampleMailboxes } from "../helpers/fake-gmail.js";
import { harness, text, type Harness } from "./harness.js";

const PAYLOAD = "<!--".repeat(40_000); // 160 kB of HTML, well under Gmail's message size limits

let h: Harness;
beforeEach(async () => {
  const boxes = sampleMailboxes();
  const ada = boxes[STUDIO_ADA];
  if (ada === undefined) throw new Error("fixture");
  boxes[STUDIO_ADA] = {
    ...ada,
    messages: [...ada.messages, { id: "m-dos", threadId: "t-dos", from: "Attacker <a@attacker.test>", to: STUDIO_ADA, subject: "Newsletter", date: "Tue, 3 Nov 2026 09:00:00 +0000", internalDate: Date.UTC(2026, 10, 3, 9), html: PAYLOAD }],
  };
  h = await harness({ mailboxes: boxes });
});
afterEach(async () => h.close());

describe("rendering an attacker-controlled HTML body", () => {
  it("get_message on a 160 kB HTML email finishes in well under a second", async () => {
    const t0 = performance.now();
    const r = await h.call("get_message", { account: STUDIO_ADA, message_id: "m-dos" });
    const ms = Math.round(performance.now() - t0);
    expect(r.isError, text(r)).toBeFalsy();
    expect(ms).toBeLessThan(1000);
  });
});
