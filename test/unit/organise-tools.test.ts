import { afterEach, describe, expect, it } from "vitest";
import { LABS_GRACE, STUDIO_ADA } from "../helpers/fake-gmail.js";
import { harness, text, type Harness } from "../helpers/mcp-harness.js";

interface Changed {
  tenant: string;
  account: string;
  threadId: string | null;
  messageId: string | null;
  added: { id: string; name: string }[];
  removed: { id: string; name: string }[];
  messageCount: number;
  labelIds: string[];
  confirmed: boolean;
  instruction: string;
}

let h: Harness | undefined;
afterEach(async () => {
  await h?.close();
  h = undefined;
});
async function open(opts: Parameters<typeof harness>[0] = {}): Promise<Harness> {
  h = await harness(opts);
  return h;
}
const changes = (x: Harness): number => x.google.calls.filter((c) => c.method === "POST" && /\/(modify|trash|untrash)$/.test(c.path)).length;
const out = (r: { structuredContent?: unknown }): Changed => r.structuredContent as Changed;

describe("modify_labels", () => {
  it("archives a whole thread (remove INBOX), confirms it by reading back, and audits ids only", async () => {
    const x = await open();
    const r = await x.call("modify_labels", { account: STUDIO_ADA, thread_id: "t-invoice", remove: ["INBOX"] });
    expect(r.isError, text(r)).toBeFalsy();
    expect(out(r)).toMatchObject({ tenant: "example-studio", account: STUDIO_ADA, threadId: "t-invoice", messageId: null, removed: [{ id: "INBOX", name: "INBOX" }], messageCount: 2, confirmed: true });
    expect(out(r).labelIds).not.toContain("INBOX");
    expect(x.google.messageLabels(STUDIO_ADA, "m-inv-1")).toEqual(["Label_7"]);
    const rec = x.written.at(-1);
    expect(rec).toMatchObject({ tool: "modify_labels", outcome: "ok", threadId: "t-invoice", tenant: "example-studio" });
    expect(JSON.stringify(rec)).not.toMatch(/INBOX|Clients/);
  });

  it("marks one message read by label name, case-insensitively, and leaves the rest of the thread alone", async () => {
    const x = await open();
    const r = await x.call("modify_labels", { account: STUDIO_ADA, message_id: "m-news-1", remove: ["unread"], add: ["Clients", "STARRED"] });
    expect(out(r)).toMatchObject({ messageId: "m-news-1", threadId: null, confirmed: true, added: [{ id: "Label_7", name: "Clients" }, { id: "STARRED", name: "STARRED" }] });
    expect(x.google.messageLabels(STUDIO_ADA, "m-news-1")?.sort()).toEqual(["INBOX", "Label_7", "STARRED"]);
    expect(x.google.messageLabels(STUDIO_ADA, "m-inv-1")).toEqual(["INBOX", "Label_7"]);
  });

  it("refuses unknown labels, Gmail-managed ones and Trash or Spam, before changing anything", async () => {
    const x = await open();
    const cases: [Record<string, unknown>, string][] = [
      [{ thread_id: "t-invoice", add: ["Lawsuit"] }, "unknown_label"],
      [{ thread_id: "t-invoice", add: ["TRASH"] }, "label_not_allowed"],
      [{ thread_id: "t-invoice", add: ["spam"] }, "label_not_allowed"],
      [{ thread_id: "t-invoice", remove: ["SENT"] }, "label_not_allowed"],
      [{ thread_id: "t-invoice", message_id: "m-inv-1", add: ["STARRED"] }, "target_required"],
      [{ add: ["STARRED"] }, "target_required"],
      [{ thread_id: "t-invoice" }, "no_change"],
      [{ thread_id: "t-invoice", add: ["STARRED"], remove: ["starred"] }, "no_change"],
    ];
    for (const [args, code] of cases) {
      const r = await x.call("modify_labels", { account: STUDIO_ADA, ...args });
      expect(r.isError, JSON.stringify(args)).toBe(true);
      expect(x.written.at(-1), JSON.stringify(args)).toMatchObject({ outcome: "refused", errorCode: code });
    }
    expect(changes(x)).toBe(0);
  });

  it("refuses an unknown account before any Google call, and a thread from another company's mailbox is not found", async () => {
    const x = await open();
    const r = await x.call("modify_labels", { account: "nobody@example-studio.test", thread_id: "t-invoice", add: ["STARRED"] });
    expect(r.isError).toBe(true);
    expect(x.google.calls).toHaveLength(0);
    const cross = await x.call("modify_labels", { account: LABS_GRACE, thread_id: "t-invoice", add: ["INBOX"] });
    expect(cross.isError).toBe(true);
    expect(x.google.messageLabels(STUDIO_ADA, "m-inv-1")).toEqual(["INBOX", "Label_7"]);
  });

  it("reports a change Gmail did not apply as not confirmed, never as done", async () => {
    const x = await open();
    x.google.ignoreLabelChanges = true;
    const r = await x.call("modify_labels", { account: STUDIO_ADA, thread_id: "t-newsletter", remove: ["UNREAD"] });
    expect(r.isError).toBeFalsy();
    expect(out(r)).toMatchObject({ confirmed: false });
    expect(out(r).instruction).toMatch(/do not match/);
    expect(x.written.at(-1)).toMatchObject({ outcome: "error", errorCode: "not_confirmed" });
  });

  it("reports a failed read-back as not confirmed", async () => {
    const x = await open();
    x.google.failReadBack = true;
    const r = await x.call("modify_labels", { account: STUDIO_ADA, thread_id: "t-newsletter", remove: ["UNREAD"] });
    expect(out(r)).toMatchObject({ confirmed: false });
    expect(out(r).instruction).toMatch(/reading it back failed/);
  });

  it("is limited per principal per hour; refusals do not count", async () => {
    const x = await open({ limits: { organisePerHour: 2 } });
    await x.call("modify_labels", { account: STUDIO_ADA, thread_id: "t-invoice", add: ["Nope"] }); // refused, not counted
    expect(out(await x.call("modify_labels", { account: STUDIO_ADA, thread_id: "t-invoice", add: ["STARRED"] })).confirmed).toBe(true);
    expect(out(await x.call("trash_thread", { account: STUDIO_ADA, thread_id: "t-newsletter" })).confirmed).toBe(true);
    const third = await x.call("untrash_thread", { account: STUDIO_ADA, thread_id: "t-newsletter" });
    expect(third.isError).toBe(true);
    expect(x.written.at(-1)).toMatchObject({ tool: "untrash_thread", outcome: "refused", errorCode: "rate_limited" });
    expect(changes(x)).toBe(2);
  });
});

describe("trash_thread and untrash_thread", () => {
  it("moves a thread to Trash and back, confirming each by reading the labels", async () => {
    const x = await open();
    const t = await x.call("trash_thread", { account: STUDIO_ADA, thread_id: "t-invoice" });
    expect(out(t)).toMatchObject({ threadId: "t-invoice", messageCount: 2, confirmed: true });
    expect(out(t).instruction).toMatch(/30 days/);
    expect(x.google.messageLabels(STUDIO_ADA, "m-inv-2")).toContain("TRASH");
    const u = await x.call("untrash_thread", { account: STUDIO_ADA, thread_id: "t-invoice" });
    expect(out(u)).toMatchObject({ confirmed: true });
    expect(x.google.messageLabels(STUDIO_ADA, "m-inv-1")).not.toContain("TRASH");
    expect(x.written.map((w) => w.tool).slice(-2)).toEqual(["trash_thread", "untrash_thread"]);
  });

  it("never deletes: the only Gmail calls are threads.trash / threads.untrash and reads", async () => {
    const x = await open();
    await x.call("trash_thread", { account: STUDIO_ADA, thread_id: "t-invoice" });
    expect(x.google.calls.filter((c) => c.method === "DELETE")).toHaveLength(0);
    expect(x.google.calls.filter((c) => c.method === "POST" && !c.path.endsWith("/token")).map((c) => c.path.replace(/\?.*$/, ""))).toEqual([`/gmail/v1/users/${encodeURIComponent(STUDIO_ADA)}/threads/t-invoice/trash`]);
  });

  it("reports a Trash move Gmail did not apply as not confirmed", async () => {
    const x = await open();
    x.google.ignoreLabelChanges = true;
    const r = await x.call("trash_thread", { account: STUDIO_ADA, thread_id: "t-invoice" });
    expect(out(r)).toMatchObject({ confirmed: false });
  });

  it("is marked destructive for clients that ask before such tools; modify_labels and untrash are not", async () => {
    const x = await open();
    const { tools } = await x.client.listTools();
    const by = new Map(tools.map((t) => [t.name, t]));
    expect(by.get("trash_thread")?.annotations?.destructiveHint).toBe(true);
    expect(by.get("modify_labels")?.annotations?.destructiveHint).toBe(false);
    expect(by.get("untrash_thread")?.annotations?.destructiveHint).toBe(false);
    for (const n of ["modify_labels", "trash_thread", "untrash_thread"]) expect(by.get(n)?.description, n).toMatch(/untrusted data/);
  });
});
