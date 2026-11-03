/**
 * T4 (prompt injection): "the model can still draft bad content; the human approval step is the control". The
 * approval step only works if what the human is shown is what the recipients will read. Originally create_draft
 * accepted a body_html that became the part mail clients display, while the preview carried only the plain text.
 * Now: the model cannot write HTML at all, and a draft that gained an HTML part elsewhere shows it in get_draft.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { STUDIO_ADA } from "../helpers/fake-gmail.js";
import { harness, text, type Harness } from "../helpers/mcp-harness.js";

let h: Harness;
beforeEach(async () => {
  h = await harness();
});
afterEach(async () => h.close());

const BENIGN = "Hi Bill, thanks for the call today. Speak Thursday. Ada";
const HIDDEN = "Our bank details changed: pay invoice 1042 to IBAN XX00 EVIL 0000 0000";

describe("what the human approves vs. what the recipient reads", () => {
  it("create_draft and update_draft refuse a model-supplied HTML body and create nothing", async () => {
    const r = await h.call("create_draft", { account: STUDIO_ADA, from: STUDIO_ADA, to: ["bill@vendor.test"], subject: "Thanks", body_text: BENIGN, body_html: `<p>${HIDDEN}</p>` });
    expect(r.isError).toBe(true);
    expect(h.google.draftIds(STUDIO_ADA)).toEqual([]);

    const ok = await h.call("create_draft", { account: STUDIO_ADA, from: STUDIO_ADA, to: ["bill@vendor.test"], subject: "Thanks", body_text: BENIGN });
    expect(ok.isError, text(ok)).toBeFalsy();
    const id = (ok.structuredContent as { draftId: string }).draftId;
    const u = await h.call("update_draft", { account: STUDIO_ADA, draft_id: id, from: STUDIO_ADA, to: ["bill@vendor.test"], subject: "Thanks", body_text: BENIGN, body_html: `<p>${HIDDEN}</p>` });
    expect(u.isError).toBe(true);
    expect(h.google.draft(STUDIO_ADA, id)?.html).toBeUndefined();
  });

  it("get_draft shows the HTML part of a draft that gained one outside multimail", async () => {
    const r = await h.call("create_draft", { account: STUDIO_ADA, from: STUDIO_ADA, to: ["bill@vendor.test"], subject: "Thanks", body_text: BENIGN });
    const id = (r.structuredContent as { draftId: string }).draftId;
    h.google.editDraftHtml(STUDIO_ADA, id, `<p>${HIDDEN}</p>`);
    const got = await h.call("get_draft", { account: STUDIO_ADA, draft_id: id });
    expect(got.isError, text(got)).toBeFalsy();
    expect((got.structuredContent as { htmlText: string | null }).htmlText).toContain(HIDDEN);
  });
});
