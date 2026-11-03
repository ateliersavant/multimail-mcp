/**
 * Rule 4 at send time: send_draft re-reads the draft's From (it "may have been edited in Gmail since it was
 * created") and checks it against the operator list and Gmail's Send-as list. These tests feed it From headers a
 * standards-conforming parser reads differently from extractAddress() (src/gmail/mime.ts) after renderHeaders()
 * (src/gmail/render.ts) has cut every header value to 2000 characters.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { STUDIO_ADA } from "../helpers/fake-gmail.js";
import { harness, text, type Harness } from "../helpers/mcp-harness.js";

/** On Gmail's own "Send mail as" list for ada (accepted), but NOT on the operator's send-as list for ada. */
const NOT_ALLOWLISTED = "extra@example-studio.test";

let h: Harness;
beforeEach(async () => {
  h = await harness();
  h.google.setSendAs(STUDIO_ADA, [
    { sendAsEmail: STUDIO_ADA, displayName: "Ada Lovelace", isPrimary: true, isDefault: true },
    { sendAsEmail: NOT_ALLOWLISTED, displayName: "Extra", isPrimary: false, isDefault: false, treatAsAlias: true, verificationStatus: "accepted" },
  ]);
});
afterEach(async () => h.close());

async function draftFromAda(): Promise<string> {
  const r = await h.call("create_draft", { account: STUDIO_ADA, from: STUDIO_ADA, to: ["bill@vendor.test"], subject: "Invoice", body_text: "Hello" });
  expect(r.isError, text(r)).toBeFalsy();
  return (r.structuredContent as { draftId: string }).draftId;
}

describe("send_draft From re-check (rule 4) vs. crafted From headers", () => {
  it("refuses a single, valid RFC 5322 mailbox whose real address is not allowlisted, even with a >2000-char display name", async () => {
    const id = await draftFromAda();
    // One mailbox: a quoted display name that happens to END (at character 2000) with "<ada@...>", then the real
    // angle-addr. renderHeaders() keeps the first 2000 characters, so extractAddress() sees "...<ada@...>" at the end.
    const quoted = `"${"A".repeat(2000 - 27)} <${STUDIO_ADA}>"`;
    expect(quoted.slice(0, 2000).endsWith(`<${STUDIO_ADA}>`)).toBe(true); // the cut falls right after <ada@...>
    h.google.editDraftFrom(STUDIO_ADA, id, `${quoted} <${NOT_ALLOWLISTED}>`);

    const r = await send(id);
    const sentFrom = h.google.sentLog[0]?.headers["from"]?.slice(-30);
    // Safe behaviour: refused, nothing sent (the actual From is not on the operator list for this mailbox).
    expect({ isError: r.isError === true, sent: h.google.sentLog.length, sentFrom, reported: (r.structuredContent as { status?: string; from?: string } | undefined) }).toEqual({ isError: true, sent: 0, sentFrom: undefined, reported: undefined });
  });

  // The next two depend on what Gmail does with an ambiguous From (not verifiable without a real mailbox); the point
  // is that the server's own check passes them instead of refusing an ambiguous sender.
  it("refuses a From that names more than one mailbox (the check reads only the last angle-addr)", async () => {
    const id = await draftFromAda();
    h.google.editDraftFrom(STUDIO_ADA, id, `${NOT_ALLOWLISTED}, Ada <${STUDIO_ADA}>`);
    expect(froms(id)).toEqual([`${NOT_ALLOWLISTED}, Ada <${STUDIO_ADA}>`]); // precondition: the crafted header is stored
    const r = await send(id);
    expect({ isError: r.isError === true, sent: h.google.sentLog.length }).toEqual({ isError: true, sent: 0 });
    // Same with the allowed address first: a multi-mailbox From is refused as such, not reduced to its first entry.
    const id2 = await draftFromAda();
    h.google.editDraftFrom(STUDIO_ADA, id2, `Ada <${STUDIO_ADA}>, ${NOT_ALLOWLISTED}`);
    const r2 = await send(id2);
    expect({ isError: r2.isError === true, sent: h.google.sentLog.length }).toEqual({ isError: true, sent: 0 });
  });

  it("refuses a draft carrying two From headers (renderHeaders keeps only the first)", async () => {
    const id = await draftFromAda();
    h.google.editDraftFrom(STUDIO_ADA, id, `Ada <${STUDIO_ADA}>\r\nFrom: ${NOT_ALLOWLISTED}`);
    expect(froms(id)).toEqual([`Ada <${STUDIO_ADA}>`, NOT_ALLOWLISTED]); // precondition: two From headers are stored
    const r = await send(id);
    expect({ isError: r.isError === true, sent: h.google.sentLog.length }).toEqual({ isError: true, sent: 0 });
  });
});

function froms(id: string): string[] {
  return (h.google.draft(STUDIO_ADA, id)?.headers ?? []).filter((x) => x.name.toLowerCase() === "from").map((x) => x.value);
}

function send(id: string) {
  return h.call("send_draft", { account: STUDIO_ADA, draft_id: id });
}
