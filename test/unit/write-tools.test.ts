import { readFileSync } from "node:fs";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import type { CallToolResult } from "@modelcontextprotocol/server";
import { Audit, type AuditRecord, type AuditSink } from "../../src/audit.js";
import { loadConfig, type AppConfig } from "../../src/config.js";
import { GmailClient } from "../../src/gmail/client.js";
import { DelegationTokenSource } from "../../src/gmail/delegation.js";
import { MemorySendLedger, SENDING_TTL_SECONDS, type SendLedger } from "../../src/gmail/ledger.js";
import { DEFAULT_LIMITS, MemoryRateLimiter, type Limits } from "../../src/guard/ratelimit.js";
import { assessSendAs } from "../../src/gmail/sendas.js";
import { buildMcpServer } from "../../src/mcp/server.js";
import { GOOGLE_EGRESS, createEgressFetch } from "../../src/net/egress.js";
import type { ResolvedMailbox } from "../../src/tenants/registry.js";
import { FakeGoogle, LABS_GRACE, LABS_PRESS, STUDIO_ADA, STUDIO_ADA_ALIAS, STUDIO_HELLO, makeServiceAccount, sampleMailboxes, type FakeMailboxData, type TestServiceAccount } from "../helpers/fake-gmail.js";

const fixture = readFileSync(new URL("../../fixtures/tenants.example.json", import.meta.url), "utf8");
const NOW = Date.UTC(2026, 10, 3, 12, 0, 0);
const identity = { principal: STUDIO_ADA, clientId: "client-1" };
const WRITE_TOOLS = ["create_draft", "update_draft", "get_draft", "list_drafts", "delete_draft", "send_draft", "check_send_as"] as const;

let cfg: AppConfig;
let studioSa: TestServiceAccount;
let labsSa: TestServiceAccount;
let consoleError: ReturnType<typeof vi.spyOn>;
let clock = NOW;

beforeAll(async () => {
  cfg = loadConfig({ PUBLIC_URL: "https://mcp.example.test", TENANTS_JSON: fixture, ALLOWED_PRINCIPALS: STUDIO_ADA, GOOGLE_CLIENT_ID: "cid", GOOGLE_CLIENT_SECRET: "cs" });
  studioSa = await makeServiceAccount("multimail-studio@fake-project.iam.gserviceaccount.test");
  labsSa = await makeServiceAccount("multimail-labs@fake-project.iam.gserviceaccount.test");
  consoleError = vi.spyOn(console, "error").mockImplementation(() => undefined);
});
afterAll(() => consoleError.mockRestore());

interface Harness {
  readonly google: FakeGoogle;
  readonly written: AuditRecord[];
  readonly client: Client;
  call(name: string, args: Record<string, unknown>): Promise<CallToolResult>;
  close(): Promise<void>;
}

async function harness(opts: { readonly ledger?: boolean | SendLedger; readonly rateLimiter?: boolean; readonly limits?: Partial<Limits>; readonly mailboxes?: Record<string, FakeMailboxData> } = {}): Promise<Harness> {
  const google = new FakeGoogle(
    [
      { sa: studioSa, mailboxes: [STUDIO_ADA, STUDIO_HELLO] },
      { sa: labsSa, mailboxes: [LABS_GRACE] },
    ],
    opts.mailboxes ?? sampleMailboxes(),
  );
  const fetch = createEgressFetch(GOOGLE_EGRESS, google.fetch);
  const tokens = new DelegationTokenSource({ secrets: { SA_EXAMPLE_STUDIO: studioSa.json, SA_EXAMPLE_LABS: labsSa.json }, fetch, now: () => clock });
  const written: AuditRecord[] = [];
  const sink: AuditSink = { write: async (r) => { written.push(r); } };
  const server = buildMcpServer(cfg, identity, {
    gmail: new GmailClient({ fetch, tokens }),
    audit: new Audit(sink, () => new Date(clock)),
    now: () => clock,
    ...(opts.ledger === false ? {} : { ledger: typeof opts.ledger === "object" ? opts.ledger : new MemorySendLedger(() => clock) }),
    ...(opts.rateLimiter === false ? {} : { rateLimiter: new MemoryRateLimiter(() => clock) }),
    limits: { ...DEFAULT_LIMITS, ...opts.limits },
  });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await server.connect(st);
  const client = new Client({ name: "unit", version: "0" });
  await client.connect(ct);
  return {
    google,
    written,
    client,
    call: (name, args) => client.callTool({ name, arguments: args }) as Promise<CallToolResult>,
    close: async () => {
      await client.close();
      await server.close();
    },
  };
}

const text = (r: CallToolResult): string => r.content.map((c) => (c.type === "text" ? c.text : "")).join("\n");
const headersOf = (p: { headers: { name: string; value: string }[] } | undefined): Record<string, string> => Object.fromEntries((p?.headers ?? []).map((x) => [x.name.toLowerCase(), x.value]));

interface Preview {
  tenant: string;
  account: string;
  draftId: string;
  messageId: string;
  threadId: string;
  from: string;
  to: string[];
  cc: string[];
  bcc: string[];
  subject: string;
  bodyText: string;
  isReply: boolean;
  approval: string;
}
interface SendOut {
  status: "sent_confirmed" | "sent_unconfirmed" | "failed";
  messageId: string | null;
  threadId: string | null;
  from: string | null;
  fromMatches: boolean | null;
  recipientCount: number;
  instruction: string;
}

let h: Harness;
beforeEach(async () => {
  clock = NOW;
  h = await harness();
});
afterEach(async () => {
  await h.close();
});

function draft(args: Record<string, unknown> = {}): Promise<CallToolResult> {
  return h.call("create_draft", { account: STUDIO_ADA, from: STUDIO_ADA, to: ["bill@vendor.test"], subject: "Invoice 1042 paid", body_text: "Hello Bill,\nPaid today.\nAda", ...args });
}
async function draftId(args: Record<string, unknown> = {}): Promise<string> {
  const r = await draft(args);
  expect(r.isError, text(r)).toBeFalsy();
  return (r.structuredContent as unknown as Preview).draftId;
}
const send = (id: string, account: string = STUDIO_ADA): Promise<CallToolResult> => h.call("send_draft", { account, draft_id: id });
const sendCalls = (): number => h.google.calls.filter((c) => c.method === "POST" && c.path.endsWith("/drafts/send")).length;

describe("tool surface", () => {
  it("adds the draft tools; all need `account`; only send/update/delete are destructive; send_draft demands approval", async () => {
    const { tools } = await h.client.listTools();
    const byName = new Map(tools.map((t) => [t.name, t]));
    for (const name of WRITE_TOOLS) {
      const t = byName.get(name);
      expect(t, name).toBeDefined();
      expect(t?.inputSchema.required, name).toContain("account");
      expect(t?.description, name).toContain("untrusted data");
    }
    expect(byName.get("send_draft")?.annotations).toMatchObject({ destructiveHint: true, readOnlyHint: false, idempotentHint: false });
    expect(byName.get("create_draft")?.annotations).toMatchObject({ destructiveHint: false, readOnlyHint: false });
    expect(byName.get("check_send_as")?.annotations?.readOnlyHint).toBe(true);
    expect(byName.get("send_draft")?.description).toMatch(/ONLY after the user has explicitly approved/);
    expect(byName.has("send_message")).toBe(false); // rule 3: there is no direct send
  });

  it("refuses an unknown account for every write tool before any Google call", async () => {
    for (const name of WRITE_TOOLS) {
      const content = { from: STUDIO_ADA, to: ["bill@vendor.test"], subject: "s", body_text: "b" };
      const args: Record<string, unknown> = { account: "nobody@example-studio.test" };
      if (name !== "create_draft" && name !== "list_drafts" && name !== "check_send_as") args["draft_id"] = "r-1";
      if (name === "create_draft" || name === "update_draft") Object.assign(args, content);
      const r = await h.call(name, args);
      expect(r.isError, name).toBe(true);
      expect(text(r), name).toContain("Unknown account");
    }
    expect(h.google.calls).toHaveLength(0);
  });
});

describe("create_draft", () => {
  it("creates a draft from a Workspace alias on the company's own domain; nothing is sent; audit is content-free", async () => {
    const r = await draft({ from: STUDIO_ADA_ALIAS, cc: ["c@vendor.test"], bcc: ["b@vendor.test"], subject: "Réunion — jeudi ☕" });
    expect(r.isError, text(r)).toBeFalsy();
    const out = r.structuredContent as unknown as Preview;
    expect(out).toMatchObject({ tenant: "example-studio", account: STUDIO_ADA, from: STUDIO_ADA_ALIAS, to: ["bill@vendor.test"], cc: ["c@vendor.test"], bcc: ["b@vendor.test"], subject: "Réunion — jeudi ☕", isReply: false });
    expect(out.approval).toMatch(/nothing has been sent/i);
    expect(out.approval).toMatch(/explicitly approves/);
    const stored = h.google.draft(STUDIO_ADA, out.draftId);
    const sh = headersOf(stored);
    expect(sh["from"]).toBe('"Ada Lovelace" <ada@example-studio-alias.test>');
    expect(sh["subject"]).toBe("Réunion — jeudi ☕");
    expect(sh["bcc"]).toBe("b@vendor.test");
    expect(stored?.text).toBe("Hello Bill,\nPaid today.\nAda");
    expect(h.google.sentLog).toHaveLength(0);
    expect(h.written.at(-1)).toMatchObject({ tool: "create_draft", outcome: "ok", tenant: "example-studio", account: STUDIO_ADA, from: STUDIO_ADA_ALIAS, draftId: out.draftId, recipientCount: 3 });
    const audit = JSON.stringify(h.written);
    for (const banned of ["vendor.test", "Réunion", "Bill", "Paid", "Ada Lovelace"]) expect(audit).not.toContain(banned);
  });

  it("refuses a From that is not on this mailbox's list (another company's, another mailbox's, or a lookalike) before any Google call", async () => {
    for (const from of [LABS_GRACE, LABS_PRESS, "nobody@example-studio.test", "ADA@example-studio.test", "ada@example-studio.test.attacker.test"]) {
      const r = await draft({ from });
      expect(r.isError, from).toBe(true);
      expect(text(r), from).toContain("not on the send-as list");
    }
    expect(h.google.calls).toHaveLength(0);
    for (const w of h.written) {
      expect(w).toMatchObject({ outcome: "refused", errorCode: "send_as_not_allowed" });
      expect(w.from).toBeUndefined(); // a refused From is model input and is not logged
    }
  });

  it("refuses an allowed From that Gmail does not list, or lists as pending, and creates nothing", async () => {
    h.google.setSendAs(STUDIO_ADA, [{ sendAsEmail: STUDIO_ADA, isPrimary: true, isDefault: true }]);
    const missing = await draft({ from: STUDIO_HELLO });
    expect(missing.isError).toBe(true);
    expect(text(missing)).toContain('"Send mail as"');
    expect(text(missing)).toContain("Add another email address");
    expect(h.written.at(-1)).toMatchObject({ outcome: "refused", errorCode: "send_as_not_in_gmail", from: STUDIO_HELLO });
    h.google.setSendAs(STUDIO_ADA, [{ sendAsEmail: STUDIO_ADA, isPrimary: true, isDefault: true }, { sendAsEmail: STUDIO_HELLO, isPrimary: false, isDefault: false, verificationStatus: "pending" }]);
    const pending = await draft({ from: STUDIO_HELLO });
    expect(pending.isError).toBe(true);
    expect(text(pending)).toMatch(/pending/);
    expect(h.written.at(-1)).toMatchObject({ errorCode: "send_as_pending" });
    expect(h.google.draftIds(STUDIO_ADA)).toHaveLength(0);
  });

  it("an unverified alias outside the company's domains is never usable (defence in depth)", () => {
    const real = cfg.registry.requireMailbox(STUDIO_ADA);
    const target: ResolvedMailbox = { tenant: real.tenant, mailbox: { address: STUDIO_ADA, sendAs: [...real.mailbox.sendAs, "ada@elsewhere.test"] } };
    const d = assessSendAs(target, "ada@elsewhere.test", [{ sendAsEmail: "ada@elsewhere.test", isPrimary: false, isDefault: false }]);
    expect(d).toMatchObject({ usable: false, gmailStatus: "unverified", refusal: "send_as_unverified" });
    expect(assessSendAs(target, "ada@elsewhere.test", [{ sendAsEmail: "ada@elsewhere.test", isPrimary: false, isDefault: false, verificationStatus: "accepted" }]).usable).toBe(true);
  });

  it("refuses header injection, invalid addresses and a missing subject, and creates nothing", async () => {
    const injected = await draft({ subject: "Hi\r\nBcc: evil@attacker.test" });
    expect(injected.isError).toBe(true);
    expect(text(injected)).toMatch(/line break/);
    expect(h.written.at(-1)).toMatchObject({ errorCode: "header_injection" });
    const bad = await draft({ to: ["not-an-address"] });
    expect(bad.isError).toBe(true);
    expect(h.written.at(-1)).toMatchObject({ errorCode: "invalid_address" });
    const noSubject = await draft({ subject: undefined });
    expect(noSubject.isError).toBe(true);
    expect(h.written.at(-1)).toMatchObject({ errorCode: "subject_required" });
    expect(h.google.draftIds(STUDIO_ADA)).toHaveLength(0);
  });

  it("drafts a reply in the original thread with Re: subject and reply headers", async () => {
    const r = await h.call("create_draft", { account: STUDIO_ADA, from: STUDIO_ADA, to: ["bill@vendor.test"], body_text: "Thanks Bill.", reply_to_message_id: "m-inv-1" });
    expect(r.isError, text(r)).toBeFalsy();
    const out = r.structuredContent as unknown as Preview;
    expect(out).toMatchObject({ subject: "Re: Invoice 1042", threadId: "t-invoice", isReply: true });
    const sh = headersOf(h.google.draft(STUDIO_ADA, out.draftId));
    expect(sh["in-reply-to"]).toBe("<m-inv-1@fake.test>");
    expect(sh["references"]).toBe("<m-inv-1@fake.test>");
  });

  it("refuses to reply from a mailbox that did not receive the message (another company's thread)", async () => {
    const r = await h.call("create_draft", { account: LABS_GRACE, from: LABS_GRACE, to: ["bill@vendor.test"], body_text: "x", reply_to_message_id: "m-inv-1" });
    expect(r.isError).toBe(true);
    expect(text(r)).toContain(`is not a message in ${LABS_GRACE}`);
    expect(h.written.at(-1)).toMatchObject({ outcome: "refused", errorCode: "reply_not_found", tenant: "example-labs" });
  });

  it("drops malformed threading headers copied from an untrusted original", async () => {
    await h.close();
    const boxes = sampleMailboxes();
    const ada = boxes[STUDIO_ADA];
    if (ada === undefined) throw new Error("fixture");
    boxes[STUDIO_ADA] = { ...ada, messages: [...ada.messages, { id: "m-dirty", threadId: "t-dirty", from: "x@vendor.test", to: STUDIO_ADA, subject: "Hello", date: "Mon, 2 Nov 2026 10:00:00 +0000", internalDate: NOW - 1000, text: "hi", extraHeaders: { References: "not-an-id; DROP TABLE" } }] };
    h = await harness({ mailboxes: boxes });
    const r = await h.call("create_draft", { account: STUDIO_ADA, from: STUDIO_ADA, to: ["x@vendor.test"], body_text: "ok", reply_to_message_id: "m-dirty" });
    const sh = headersOf(h.google.draft(STUDIO_ADA, (r.structuredContent as unknown as Preview).draftId));
    expect(sh["in-reply-to"]).toBe("<m-dirty@fake.test>");
    expect(sh["references"]).toBe("<m-dirty@fake.test>");
  });
});

describe("update_draft, get_draft, list_drafts, delete_draft", () => {
  it("update replaces the content, keeps the reply thread and subject, and re-checks the From", async () => {
    const r = await h.call("create_draft", { account: STUDIO_ADA, from: STUDIO_ADA, to: ["bill@vendor.test"], body_text: "v1", reply_to_message_id: "m-inv-1" });
    const id = (r.structuredContent as unknown as Preview).draftId;
    const u = await h.call("update_draft", { account: STUDIO_ADA, draft_id: id, from: STUDIO_HELLO, to: ["bill@vendor.test", "accounts@vendor.test"], body_text: "v2" });
    expect(u.isError, text(u)).toBeFalsy();
    expect(u.structuredContent).toMatchObject({ draftId: id, from: STUDIO_HELLO, subject: "Re: Invoice 1042", threadId: "t-invoice", isReply: true, bodyText: "v2" });
    const stored = h.google.draft(STUDIO_ADA, id);
    expect(headersOf(stored)["from"]).toBe('"Example Studio" <hello@example-studio.test>');
    expect(headersOf(stored)["in-reply-to"]).toBe("<m-inv-1@fake.test>");
    expect(stored?.text).toBe("v2");
    const foreign = await h.call("update_draft", { account: STUDIO_ADA, draft_id: id, from: LABS_GRACE, to: ["bill@vendor.test"], body_text: "v3" });
    expect(foreign.isError).toBe(true);
    expect(h.google.draft(STUDIO_ADA, id)?.text).toBe("v2");
    const missing = await h.call("update_draft", { account: STUDIO_ADA, draft_id: "r-999", from: STUDIO_ADA, to: ["bill@vendor.test"], subject: "s", body_text: "x" });
    expect(missing.isError).toBe(true);
    expect(h.written.at(-1)).toMatchObject({ errorCode: "draft_not_found" });
  });

  it("get, list and delete drafts, with the tenant echoed", async () => {
    const a = await draftId({ subject: "First" });
    const b = await draftId({ subject: "Second" });
    const list = (await h.call("list_drafts", { account: STUDIO_ADA })).structuredContent as { tenant: string; drafts: { draftId: string; subject: string | null }[]; nextPageToken: string | null };
    expect(list.tenant).toBe("example-studio");
    expect(list.drafts.map((d) => [d.draftId, d.subject])).toEqual([[b, "Second"], [a, "First"]]);
    const got = (await h.call("get_draft", { account: STUDIO_ADA, draft_id: a })).structuredContent as { draftId: string; message: { headers: { subject?: string; from?: string }; body: { text: string } } };
    expect(got).toMatchObject({ draftId: a, message: { headers: { subject: "First", from: "Ada Lovelace <ada@example-studio.test>" }, body: { text: "Hello Bill,\nPaid today.\nAda" } } });
    const del = await h.call("delete_draft", { account: STUDIO_ADA, draft_id: a });
    expect(del.structuredContent).toMatchObject({ draftId: a, deleted: true });
    expect(h.google.draftIds(STUDIO_ADA)).toEqual([b]);
    const gone = await h.call("get_draft", { account: STUDIO_ADA, draft_id: a });
    expect(gone.isError).toBe(true);
    expect(text(gone)).toContain("404");
  });
});

describe("send_draft (rules 3, 4 and 5)", () => {
  it("sends, confirms the message is in Sent from the right address, and audits ids only", async () => {
    const id = await draftId({ from: STUDIO_ADA_ALIAS });
    const r = await send(id);
    expect(r.isError, text(r)).toBeFalsy();
    const out = r.structuredContent as unknown as SendOut;
    expect(out).toMatchObject({ status: "sent_confirmed", from: STUDIO_ADA_ALIAS, fromMatches: true, recipientCount: 1 });
    expect(out.messageId).toMatch(/^sent-/);
    expect(out.instruction).toBe("Sent and confirmed in Sent.");
    expect(h.google.sentLog).toHaveLength(1);
    expect(h.google.sentLog[0]?.headers["from"]).toContain(STUDIO_ADA_ALIAS);
    expect(h.google.draftIds(STUDIO_ADA)).toHaveLength(0);
    expect(h.written.at(-1)).toMatchObject({ tool: "send_draft", outcome: "ok", draftId: id, messageId: out.messageId, from: STUDIO_ADA_ALIAS, recipientCount: 1 });
    expect(h.written.at(-1)?.errorCode).toBeUndefined();
  });

  it("never sends the same draft twice, and refuses to edit a sent draft", async () => {
    const id = await draftId();
    const first = (await send(id)).structuredContent as unknown as SendOut;
    const again = await send(id);
    expect(again.isError).toBe(true);
    expect(text(again)).toContain(`already sent as message ${first.messageId ?? ""}`);
    expect(text(again)).toContain("Do not send it again");
    expect(sendCalls()).toBe(1);
    expect(h.written.at(-1)).toMatchObject({ outcome: "refused", errorCode: "already_sent" });
    const edit = await h.call("update_draft", { account: STUDIO_ADA, draft_id: id, from: STUDIO_ADA, to: ["bill@vendor.test"], subject: "s", body_text: "x" });
    expect(edit.isError).toBe(true);
    expect(h.written.at(-1)).toMatchObject({ errorCode: "already_sent" });
  });

  it("re-checks the From at send time: a draft edited in Gmail to a foreign address, or whose alias went pending, is not sent", async () => {
    const a = await draftId();
    h.google.editDraftFrom(STUDIO_ADA, a, "Mallory <mallory@attacker.test>");
    const r1 = await send(a);
    expect(r1.isError).toBe(true);
    expect(text(r1)).toContain("not on the send-as list");
    const b = await draftId();
    h.google.editDraftFrom(STUDIO_ADA, b, `Grace <${LABS_GRACE}>`); // another company
    expect((await send(b)).isError).toBe(true);
    const c = await draftId({ from: STUDIO_HELLO });
    h.google.setSendAs(STUDIO_ADA, [{ sendAsEmail: STUDIO_ADA, isPrimary: true, isDefault: true }, { sendAsEmail: STUDIO_HELLO, isPrimary: false, isDefault: false, verificationStatus: "pending" }]);
    const r3 = await send(c);
    expect(r3.isError).toBe(true);
    expect(h.written.at(-1)).toMatchObject({ errorCode: "send_as_pending" });
    expect(sendCalls()).toBe(0);
    expect(h.google.sentLog).toHaveLength(0);
    expect(h.google.draftIds(STUDIO_ADA)).toHaveLength(3);
  });

  it("failed: Gmail refuses (4xx) → nothing sent, draft kept, safe to retry", async () => {
    const id = await draftId();
    h.google.sendFailure = { status: 400, googleStatus: "FAILED_PRECONDITION" };
    const r = await send(id);
    expect(r.isError).toBe(true);
    const out = r.structuredContent as unknown as SendOut;
    expect(out.status).toBe("failed");
    expect(out.instruction).toMatch(/Nothing was sent/);
    expect(out.instruction).toMatch(/safe to fix the draft and call send_draft again/);
    expect(h.google.sentLog).toHaveLength(0);
    expect(h.google.draftIds(STUDIO_ADA)).toEqual([id]);
    expect(h.written.at(-1)).toMatchObject({ outcome: "error", errorCode: "send_failed", draftId: id });
    h.google.sendFailure = undefined;
    expect(((await send(id)).structuredContent as unknown as SendOut).status).toBe("sent_confirmed");
  });

  it("ambiguous error with the draft still in Drafts → failed, safe to retry", async () => {
    const id = await draftId();
    h.google.sendFailure = { status: 503, googleStatus: "UNAVAILABLE", afterSend: false };
    const r = await send(id);
    expect((r.structuredContent as unknown as SendOut).status).toBe("failed");
    expect((r.structuredContent as unknown as SendOut).instruction).toMatch(/still in Drafts/);
    h.google.sendFailure = undefined;
    expect(((await send(id)).structuredContent as unknown as SendOut).status).toBe("sent_confirmed");
    expect(h.google.sentLog).toHaveLength(1);
  });

  it("ambiguous error after Gmail actually sent → sent_unconfirmed; retries are refused, never a second send", async () => {
    const id = await draftId();
    h.google.sendFailure = { status: 503, googleStatus: "UNAVAILABLE", afterSend: true };
    const r = await send(id);
    expect(r.isError).toBeFalsy();
    const out = r.structuredContent as unknown as SendOut;
    expect(out.status).toBe("sent_unconfirmed");
    expect(out.instruction).toMatch(/Do NOT send it again/);
    expect(h.written.at(-1)).toMatchObject({ outcome: "ok", errorCode: "sent_unconfirmed" });
    h.google.sendFailure = undefined;
    const soon = await send(id);
    expect(soon.isError).toBe(true);
    expect(h.written.at(-1)).toMatchObject({ errorCode: "send_in_progress" });
    clock += (SENDING_TTL_SECONDS + 1) * 1000;
    const later = await send(id);
    expect(later.isError).toBe(true);
    expect(text(later)).toMatch(/check Sent/);
    expect(h.written.at(-1)).toMatchObject({ errorCode: "draft_not_found" });
    expect(h.google.sentLog).toHaveLength(1);
  });

  it("confirmation read fails → sent_unconfirmed with the message id; a retry is refused as already sent", async () => {
    const id = await draftId();
    h.google.confirmFailure = { status: 503 };
    const out = (await send(id)).structuredContent as unknown as SendOut;
    expect(out.status).toBe("sent_unconfirmed");
    expect(out.messageId).toMatch(/^sent-/);
    expect(out.instruction).toMatch(/Do NOT send it again/);
    expect(out.instruction).toMatch(/get_message/);
    h.google.confirmFailure = undefined;
    const again = await send(id);
    expect(again.isError).toBe(true);
    expect(text(again)).toContain("already sent");
    expect(h.google.sentLog).toHaveLength(1);
  });

  it("no SENT label yet → sent_unconfirmed, not confirmed by inference", async () => {
    const id = await draftId();
    h.google.omitSentLabel = true;
    const out = (await send(id)).structuredContent as unknown as SendOut;
    expect(out.status).toBe("sent_unconfirmed");
    expect(out.instruction).toMatch(/SENT label/);
  });

  it("Gmail rewrote the From → confirmed but flagged loudly, and audited", async () => {
    const id = await draftId({ from: STUDIO_HELLO });
    h.google.rewriteFromToPrimary = true;
    const out = (await send(id)).structuredContent as unknown as SendOut;
    expect(out).toMatchObject({ status: "sent_confirmed", fromMatches: false, from: STUDIO_ADA });
    expect(out.instruction).toMatch(/WARNING/);
    expect(h.written.at(-1)).toMatchObject({ outcome: "ok", errorCode: "from_rewritten" });
  });

  it("an unknown draft is refused with a pointer to Sent, not recreated", async () => {
    const r = await send("r-999");
    expect(r.isError).toBe(true);
    expect(text(r)).toMatch(/check Sent/);
    expect(sendCalls()).toBe(0);
  });

  it("without a ledger, sending is refused (fail closed) and nothing is sent", async () => {
    await h.close();
    h = await harness({ ledger: false });
    const id = await draftId();
    const r = await send(id);
    expect(r.isError).toBe(true);
    expect(text(r)).toMatch(/cannot record sent drafts/);
    expect(sendCalls()).toBe(0);
    expect(h.written.at(-1)).toMatchObject({ outcome: "error", errorCode: "ledger_unavailable" });
  });

  it("each company sends only through its own mailbox and aliases", async () => {
    const r = await h.call("create_draft", { account: LABS_GRACE, from: LABS_PRESS, to: ["r@paper.test"], subject: "Statement", body_text: "Our statement." });
    expect(r.isError, text(r)).toBeFalsy();
    const out = (await send((r.structuredContent as unknown as Preview).draftId, LABS_GRACE)).structuredContent as unknown as SendOut;
    expect(out).toMatchObject({ status: "sent_confirmed", from: LABS_PRESS });
    expect(h.google.sentLog[0]?.account).toBe(LABS_GRACE);
    expect(h.written.at(-1)).toMatchObject({ tenant: "example-labs", account: LABS_GRACE });
  });

  it("the audit trail of a full draft → edit → send cycle holds no content", async () => {
    const id = await draftId({ subject: "Confidential terms", body_text: "secret body text", to: ["counterparty@vendor.test"] });
    await h.call("update_draft", { account: STUDIO_ADA, draft_id: id, from: STUDIO_ADA, to: ["counterparty@vendor.test"], subject: "Confidential terms v2", body_text: "secret body text v2" });
    await send(id);
    const audit = JSON.stringify(h.written);
    for (const banned of ["Confidential", "secret body", "counterparty", "vendor.test", "Ada Lovelace"]) expect(audit).not.toContain(banned);
  });
});

describe("check_send_as", () => {
  it("shows which allowed addresses Gmail accepts and which Gmail addresses are not allowed", async () => {
    const r = await h.call("check_send_as", { account: STUDIO_ADA });
    expect(r.isError, text(r)).toBeFalsy();
    expect(r.structuredContent).toMatchObject({
      tenant: "example-studio",
      addresses: [
        { address: STUDIO_ADA, usable: true, gmailStatus: "primary" },
        { address: STUDIO_ADA_ALIAS, usable: true, gmailStatus: "workspace_alias" },
        { address: STUDIO_HELLO, usable: true, gmailStatus: "accepted" },
      ],
      inGmailButNotAllowed: [],
    });
    h.google.setSendAs(STUDIO_ADA, [{ sendAsEmail: STUDIO_ADA, isPrimary: true, isDefault: true }, { sendAsEmail: "extra@example-studio.test", isPrimary: false, isDefault: false, verificationStatus: "accepted" }]);
    const after = (await h.call("check_send_as", { account: STUDIO_ADA })).structuredContent as { addresses: { address: string; usable: boolean; gmailStatus: string }[]; inGmailButNotAllowed: string[] };
    expect(after.addresses.find((a) => a.address === STUDIO_HELLO)).toMatchObject({ usable: false, gmailStatus: "missing" });
    expect(after.inGmailButNotAllowed).toEqual(["extra@example-studio.test"]);
  });
});

describe("rate limits on drafting and sending", () => {
  it("refuses sends past the hourly limit before Gmail is called; refusals do not use up the quota", async () => {
    await h.close();
    h = await harness({ limits: { sendsPerHour: 2 } });
    const refused = await send("r-999"); // unknown draft: refused before the limit is counted
    expect(refused.isError).toBe(true);
    const a = await draftId();
    const b = await draftId();
    const c = await draftId();
    expect(((await send(a)).structuredContent as unknown as SendOut).status).toBe("sent_confirmed");
    expect(((await send(b)).structuredContent as unknown as SendOut).status).toBe("sent_confirmed");
    const third = await send(c);
    expect(third.isError).toBe(true);
    expect(text(third)).toMatch(/at most 2 emails per hour/);
    expect(text(third)).toMatch(/Nothing was sent/);
    expect(h.written.at(-1)).toMatchObject({ tool: "send_draft", outcome: "refused", errorCode: "rate_limited" });
    expect(sendCalls()).toBe(2);
    expect(h.google.draftIds(STUDIO_ADA)).toEqual([c]);
    clock += 3600 * 1000;
    expect(((await send(c)).structuredContent as unknown as SendOut).status).toBe("sent_confirmed");
  });

  it("the daily send limit applies across every mailbox and company of the principal", async () => {
    await h.close();
    h = await harness({ limits: { sendsPerDay: 1 } });
    expect(((await send(await draftId())).structuredContent as unknown as SendOut).status).toBe("sent_confirmed");
    const labs = await h.call("create_draft", { account: LABS_GRACE, from: LABS_GRACE, to: ["r@paper.test"], subject: "s", body_text: "b" });
    const r = await send((labs.structuredContent as unknown as Preview).draftId, LABS_GRACE);
    expect(r.isError).toBe(true);
    expect(text(r)).toMatch(/at most 1 emails per day/);
    expect(h.google.sentLog).toHaveLength(1);
  });

  it("limits drafts per hour", async () => {
    await h.close();
    h = await harness({ limits: { draftsPerHour: 1 } });
    await draftId();
    const second = await draft();
    expect(second.isError).toBe(true);
    expect(text(second)).toMatch(/at most 1 drafts/);
    expect(h.written.at(-1)).toMatchObject({ tool: "create_draft", errorCode: "rate_limited" });
  });

  it("without a rate limiter, sending is refused (fail closed); drafting still works", async () => {
    await h.close();
    h = await harness({ rateLimiter: false });
    const id = await draftId();
    const r = await send(id);
    expect(r.isError).toBe(true);
    expect(text(r)).toMatch(/cannot enforce its sending limits/);
    expect(sendCalls()).toBe(0);
    expect(h.written.at(-1)).toMatchObject({ outcome: "error", errorCode: "rate_limiter_unavailable" });
  });
});

describe("send_draft after the adversarial review", () => {
  it("a 404 from the send after Gmail actually sent is reported as possibly sent, never as 'nothing was sent'", async () => {
    const id = await draftId();
    h.google.sendFailure = { status: 404, googleStatus: "NOT_FOUND", afterSend: true };
    const r = await send(id);
    const out = r.structuredContent as unknown as SendOut;
    expect(h.google.sentLog).toHaveLength(1);
    expect(out.status).toBe("sent_unconfirmed");
    expect(out.instruction).toMatch(/Do NOT send it again/);
    expect(text(r)).not.toMatch(/Nothing was sent/);
  });

  it("refuses a draft whose Sender header names someone other than its From", async () => {
    const id = await draftId();
    h.google.addDraftHeader(STUDIO_ADA, id, "Sender", "Grace <grace@example-labs.test>");
    const r = await send(id);
    expect(r.isError).toBe(true);
    expect(h.written.at(-1)).toMatchObject({ errorCode: "draft_from_ambiguous" });
    expect(sendCalls()).toBe(0);
    // The refusal released the claim: once the header is gone the draft can be sent.
    expect(h.google.draftIds(STUDIO_ADA)).toContain(id);
  });

  it("a ledger write that fails after a real send still reports the send, and says not to send again", async () => {
    await h.close();
    const inner = new MemorySendLedger(() => clock);
    const flaky: SendLedger = {
      lookup: (a, d) => inner.lookup(a, d),
      claim: (a, d, n) => inner.claim(a, d, n),
      markSent: async () => {
        throw new Error("storage timeout");
      },
      release: (a, d) => inner.release(a, d),
    };
    h = await harness({ ledger: flaky });
    const id = await draftId();
    const out = (await send(id)).structuredContent as unknown as SendOut;
    expect(h.google.sentLog).toHaveLength(1);
    expect(out.status).toBe("sent_confirmed");
    expect(out.instruction).toMatch(/do not send it again/);
  });

  it("two concurrent sends of one draft reach Gmail once", async () => {
    const id = await draftId();
    const [a, b] = await Promise.all([send(id), send(id)]);
    expect(sendCalls()).toBe(1);
    expect([a, b].filter((r) => r.isError === true)).toHaveLength(1);
  });
});
