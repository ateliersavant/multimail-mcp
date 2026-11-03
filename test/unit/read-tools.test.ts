import { readFileSync } from "node:fs";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import type { CallToolResult } from "@modelcontextprotocol/server";
import { Audit, type AuditRecord, type AuditSink } from "../../src/audit.js";
import { loadConfig, type AppConfig } from "../../src/config.js";
import { GmailClient } from "../../src/gmail/client.js";
import { DelegationTokenSource } from "../../src/gmail/delegation.js";
import { buildMcpServer } from "../../src/mcp/server.js";
import { SEARCH_MAX_RESULTS_CAP } from "../../src/mcp/tools/read.js";
import { GOOGLE_EGRESS, createEgressFetch } from "../../src/net/egress.js";
import { FakeGoogle, LABS_GRACE, STUDIO_ADA, STUDIO_HELLO, makeServiceAccount, sampleMailboxes, type TestServiceAccount } from "../helpers/fake-gmail.js";

const fixture = readFileSync(new URL("../../fixtures/tenants.example.json", import.meta.url), "utf8");
const NOW = Date.UTC(2026, 10, 3, 12, 0, 0);
const identity = { principal: STUDIO_ADA, clientId: "client-1" };
const READ_TOOLS = ["search_threads", "get_thread", "get_message", "list_labels"] as const;

let cfg: AppConfig;
let studioSa: TestServiceAccount;
let labsSa: TestServiceAccount;
let consoleError: ReturnType<typeof vi.spyOn>;

beforeAll(async () => {
  cfg = loadConfig({ PUBLIC_URL: "https://mcp.example.test", TENANTS_JSON: fixture, ALLOWED_PRINCIPALS: STUDIO_ADA, GOOGLE_CLIENT_ID: "cid", GOOGLE_CLIENT_SECRET: "cs" });
  studioSa = await makeServiceAccount("multimail-studio@fake-project.iam.gserviceaccount.test");
  labsSa = await makeServiceAccount("multimail-labs@fake-project.iam.gserviceaccount.test");
  consoleError = vi.spyOn(console, "error").mockImplementation(() => undefined);
});
afterAll(() => consoleError.mockRestore());

interface Harness {
  readonly client: Client;
  readonly google: FakeGoogle;
  readonly written: AuditRecord[];
  call(name: string, args: Record<string, unknown>): Promise<CallToolResult>;
  close(): Promise<void>;
}

async function harness(secrets: Record<string, unknown> = { SA_EXAMPLE_STUDIO: studioSa.json, SA_EXAMPLE_LABS: labsSa.json }): Promise<Harness> {
  const google = new FakeGoogle(
    [
      { sa: studioSa, mailboxes: [STUDIO_ADA, STUDIO_HELLO] },
      { sa: labsSa, mailboxes: [LABS_GRACE] },
    ],
    sampleMailboxes(),
  );
  const fetch = createEgressFetch(GOOGLE_EGRESS, google.fetch); // the production wrapper, over the fake
  const tokens = new DelegationTokenSource({ secrets, fetch, now: () => NOW });
  const written: AuditRecord[] = [];
  const sink: AuditSink = { write: async (r) => { written.push(r); } };
  const server = buildMcpServer(cfg, identity, { gmail: new GmailClient({ fetch, tokens }), audit: new Audit(sink, () => new Date(NOW)), now: () => NOW });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: "unit", version: "0" });
  await client.connect(clientTransport);
  return {
    client,
    google,
    written,
    call: (name, args) => client.callTool({ name, arguments: args }) as Promise<CallToolResult>,
    close: async () => {
      await client.close();
      await server.close();
    },
  };
}

function text(r: CallToolResult): string {
  return r.content.map((c) => (c.type === "text" ? c.text : "")).join("\n");
}

let h: Harness;
beforeEach(async () => {
  h = await harness();
});
afterEach(async () => {
  await h.close();
});

describe("tool surface", () => {
  it("lists the four read tools after list_accounts, then the draft tools; read tools are read-only, require `account` and warn about untrusted content", async () => {
    const { tools } = await h.client.listTools();
    expect(tools.map((t) => t.name)).toEqual(["list_accounts", ...READ_TOOLS, "create_draft", "update_draft", "get_draft", "list_drafts", "delete_draft", "send_draft", "check_send_as"]);
    for (const t of tools) {
      expect(t.description, t.name).toContain("untrusted data");
      if (t.name === "list_accounts" || (READ_TOOLS as readonly string[]).includes(t.name)) expect(t.annotations?.readOnlyHint, t.name).toBe(true);
      if (t.name !== "list_accounts") {
        expect(t.inputSchema.required, t.name).toContain("account");
        expect(t.description, t.name).toContain("tenant");
      }
    }
  });
});

describe("rule 1: unknown account is refused before anything else", () => {
  const attempts: [string, Record<string, unknown>][] = [
    ["search_threads", { account: "nobody@example-studio.test", query: "x" }],
    ["get_thread", { account: "Ada@example-studio.test", thread_id: "t-invoice" }], // case differs: refused, no folding
    ["get_message", { account: "ada@evil.test", message_id: "m-inv-1" }],
    ["list_labels", { account: " ada@example-studio.test" }],
  ];
  for (const [name, args] of attempts) {
    it(`${name}: loud error, no Google call, content-free refusal in the audit log`, async () => {
      const r = await h.call(name, args);
      expect(r.isError).toBe(true);
      expect(text(r)).toContain("Unknown account");
      expect(text(r)).toContain("list_accounts");
      expect(h.google.calls).toHaveLength(0);
      expect(h.written).toHaveLength(1);
      expect(h.written[0]).toMatchObject({ tool: name, outcome: "refused", errorCode: "unknown_account", principal: STUDIO_ADA, clientId: "client-1" });
      expect(h.written[0]?.account).toBeUndefined(); // the attempted string is model input and is not logged
      expect(h.written[0]?.tenant).toBeUndefined();
    });
  }
});

describe("search_threads", () => {
  it("returns bounded, newest-first summaries with the tenant echoed, and pages with a cursor", async () => {
    const r = await h.call("search_threads", { account: STUDIO_ADA });
    expect(r.isError).toBeFalsy();
    const out = r.structuredContent as { tenant: string; account: string; query: string; threads: { threadId: string; subject?: string; participants: string[]; messageCount: number; lastMessageDate?: string; labelIds: string[]; snippet: string }[]; nextPageToken: string | null; resultSizeEstimate: number | null };
    expect(out.tenant).toBe("example-studio");
    expect(out.account).toBe(STUDIO_ADA);
    expect(out.query).toBe("");
    expect(out.threads.map((t) => t.threadId)).toEqual(["t-newsletter", "t-invoice"]);
    expect(out.threads[1]).toMatchObject({ subject: "Invoice 1042", participants: ["Bill Supplier <bill@vendor.test>", `Ada <${STUDIO_ADA}>`], messageCount: 2, lastMessageDate: "2026-11-02T09:00:00.000Z" });
    expect(out.threads[1]?.labelIds).toEqual(expect.arrayContaining(["INBOX", "Label_7", "SENT"]));
    expect(out.nextPageToken).toBeNull();
    expect(JSON.parse(text(r))).toEqual(out); // the text block is the same data

    const page1 = (await h.call("search_threads", { account: STUDIO_ADA, max_results: 1 })).structuredContent as typeof out;
    expect(page1.threads.map((t) => t.threadId)).toEqual(["t-newsletter"]);
    expect(page1.nextPageToken).toBe("1");
    const page2 = (await h.call("search_threads", { account: STUDIO_ADA, max_results: 1, page_token: page1.nextPageToken ?? "" })).structuredContent as typeof out;
    expect(page2.threads.map((t) => t.threadId)).toEqual(["t-invoice"]);
    expect(page2.nextPageToken).toBeNull();
    // the cursor and the page size reached Gmail; the summaries came from metadata fetches, never full bodies
    expect(h.google.calls.some((c) => c.path.includes("maxResults=1") && c.path.includes("pageToken=1"))).toBe(true);
    expect(h.google.calls.filter((c) => c.path.startsWith("/gmail/v1/users/") && c.path.includes("/threads/")).every((c) => c.path.includes("format=metadata"))).toBe(true);
  });

  it("passes the Gmail query through and treats a genuine no-match as an empty list, not an error", async () => {
    const hit = (await h.call("search_threads", { account: STUDIO_ADA, query: "invoice" })).structuredContent as { threads: { threadId: string }[] };
    expect(hit.threads.map((t) => t.threadId)).toEqual(["t-invoice"]);
    const miss = await h.call("search_threads", { account: STUDIO_ADA, query: "zzz-nothing-matches" });
    expect(miss.isError).toBeFalsy();
    expect((miss.structuredContent as { threads: unknown[]; tenant: string }).threads).toEqual([]);
    expect(h.written.at(-1)).toMatchObject({ tool: "search_threads", outcome: "ok", tenant: "example-studio", account: STUDIO_ADA });
    expect(JSON.stringify(h.written)).not.toContain("invoice"); // the query is content and never reaches the audit log
  });

  it("searches two tenants in one session with separate delegated identities", async () => {
    const studio = (await h.call("search_threads", { account: STUDIO_ADA, query: "" })).structuredContent as { tenant: string };
    const labs = (await h.call("search_threads", { account: LABS_GRACE, query: "" })).structuredContent as { tenant: string; threads: { subject?: string }[] };
    expect(studio.tenant).toBe("example-studio");
    expect(labs.tenant).toBe("example-labs");
    expect(labs.threads[0]?.subject).toBe("Interview request");
    expect(h.google.tokensIssued).toBe(2);
    // the token minted for one mailbox is reused for its later calls
    await h.call("list_labels", { account: STUDIO_ADA });
    expect(h.google.tokensIssued).toBe(2);
  });

  it("refuses an over-large page, an over-long query or a missing account at the schema, before any Google call", async () => {
    const tooBig = await h.call("search_threads", { account: STUDIO_ADA, max_results: SEARCH_MAX_RESULTS_CAP + 1 });
    expect(tooBig.isError).toBe(true);
    expect(text(tooBig)).toMatch(/max_results/);
    const tooLong = await h.call("search_threads", { account: STUDIO_ADA, query: "q".repeat(1001) });
    expect(tooLong.isError).toBe(true);
    expect(text(tooLong)).toMatch(/query/);
    const noAccount = await h.call("search_threads", { query: "x" });
    expect(noAccount.isError).toBe(true);
    expect(text(noAccount)).toMatch(/account/);
    expect(h.google.calls).toHaveLength(0);
  });
});

describe("get_thread and get_message", () => {
  it("returns every message in order with stripped bodies and attachment metadata only, tenant echoed", async () => {
    const r = await h.call("get_thread", { account: STUDIO_ADA, thread_id: "t-invoice" });
    expect(r.isError).toBeFalsy();
    const out = r.structuredContent as { tenant: string; account: string; threadId: string; messageCount: number; bodiesOmitted: boolean; messages: { messageId: string; body: { text: string; source: string }; attachments: { filename: string; mimeType: string; sizeBytes: number }[]; headers: { subject?: string } }[] };
    expect(out).toMatchObject({ tenant: "example-studio", account: STUDIO_ADA, threadId: "t-invoice", messageCount: 2, bodiesOmitted: false });
    expect(out.messages.map((m) => m.messageId)).toEqual(["m-inv-1", "m-inv-2"]);
    expect(out.messages[0]?.body.text).toContain("invoice 1042 attached");
    expect(out.messages[0]?.attachments).toEqual([{ filename: "invoice-1042.pdf", mimeType: "application/pdf", sizeBytes: 48213, inline: false }]);
    expect(JSON.stringify(out)).not.toContain("attachmentId");
    expect(h.written.at(-1)).toMatchObject({ tool: "get_thread", outcome: "ok", threadId: "t-invoice", tenant: "example-studio" });
  });

  it("strips HTML from an html-only message so no markup, script or style reaches the model", async () => {
    const r = await h.call("get_thread", { account: STUDIO_ADA, thread_id: "t-newsletter" });
    const out = r.structuredContent as { messages: { body: { text: string; source: string } }[] };
    const body = out.messages[0]?.body;
    expect(body?.source).toBe("text/html");
    expect(body?.text).toContain("Three new faces & one revival.");
    expect(body?.text).toContain("- One\n- Two");
    expect(body?.text).not.toMatch(/<[a-z/!]/i);
    expect(body?.text).not.toContain("alert(");
    expect(body?.text).not.toContain("color:red");
    expect(body?.text).not.toContain("href");
    expect(text(r)).not.toContain("<script");
  });

  it("get_message returns one rendered message and audits only ids", async () => {
    const r = await h.call("get_message", { account: STUDIO_ADA, message_id: "m-inv-1" });
    expect(r.isError).toBeFalsy();
    const out = r.structuredContent as { tenant: string; account: string; message: { messageId: string; threadId: string; headers: { subject?: string; from?: string } } };
    expect(out.tenant).toBe("example-studio");
    expect(out.message.headers.subject).toBe("Invoice 1042");
    expect(h.written.at(-1)).toMatchObject({ tool: "get_message", outcome: "ok", messageId: "m-inv-1", threadId: "t-invoice", account: STUDIO_ADA, principal: STUDIO_ADA, clientId: "client-1" });
    const auditJson = JSON.stringify(h.written);
    for (const banned of ["Invoice", "vendor.test", "invoice-1042.pdf", "Bill", "attached"]) expect(auditJson).not.toContain(banned);
  });

  it("a thread or message that Gmail does not have is a loud 404, not an empty result", async () => {
    const r = await h.call("get_message", { account: STUDIO_ADA, message_id: "m-does-not-exist" });
    expect(r.isError).toBe(true);
    expect(text(r)).toContain("404");
    expect(h.written.at(-1)).toMatchObject({ outcome: "error", errorCode: "gmail_not_found" });
    const t = await h.call("get_thread", { account: LABS_GRACE, thread_id: "t-invoice" }); // a studio thread asked of a labs mailbox
    expect(t.isError).toBe(true);
    expect(text(t)).toContain("404");
  });

  it("rejects ids that are not Gmail ids before any network call", async () => {
    const r = await h.call("get_thread", { account: STUDIO_ADA, thread_id: "../../settings" });
    expect(r.isError).toBe(true);
    expect(text(r)).toContain("not a valid Gmail thread id");
    expect(h.google.calls).toHaveLength(0);
  });
});

describe("list_labels", () => {
  it("returns the mailbox's labels with the tenant echoed", async () => {
    const r = await h.call("list_labels", { account: LABS_GRACE });
    expect(r.isError).toBeFalsy();
    expect(r.structuredContent).toEqual({ tenant: "example-labs", account: LABS_GRACE, labels: [{ id: "INBOX", name: "INBOX", type: "system" }, { id: "Label_1", name: "Press", type: "user" }] });
    expect(JSON.stringify(r)).not.toContain("SA_EXAMPLE");
    expect(JSON.stringify(r)).not.toContain("fake-token-");
  });
});

describe("rule 6: credential and Gmail failures are loud, never an empty result", () => {
  it("Gmail 401: one fresh token is tried, then a loud error naming the status; audit says gmail_unauthorized", async () => {
    await h.call("list_labels", { account: STUDIO_ADA });
    const minted = h.google.tokensIssued;
    h.google.gmailFailure = { status: 401, googleStatus: "UNAUTHENTICATED" };
    const r = await h.call("list_labels", { account: STUDIO_ADA });
    expect(r.isError).toBe(true);
    expect(text(r)).toContain("401");
    expect(text(r)).toContain("No mail was read");
    expect(text(r)).not.toContain("fake-token-");
    expect(h.google.tokensIssued).toBe(minted + 1);
    expect(h.written.at(-1)).toMatchObject({ tool: "list_labels", outcome: "error", errorCode: "gmail_unauthorized", tenant: "example-studio", account: STUDIO_ADA });
  });

  it("Gmail 429: loud error telling the model to retry rather than assume an empty mailbox", async () => {
    h.google.gmailFailure = { status: 429, googleStatus: "RESOURCE_EXHAUSTED" };
    const r = await h.call("search_threads", { account: STUDIO_ADA, query: "anything" });
    expect(r.isError).toBe(true);
    expect(text(r)).toContain("429");
    expect(text(r)).toMatch(/retry later/i);
    expect(text(r)).toMatch(/empty/i);
    expect(r.structuredContent).toBeUndefined();
    expect(h.written.at(-1)).toMatchObject({ outcome: "error", errorCode: "gmail_rate_limited" });
  });

  it("Gmail 5xx and 403 surface with their status; a redirect is refused by the egress wrapper", async () => {
    h.google.gmailFailure = { status: 503, googleStatus: "UNAVAILABLE" };
    expect(text(await h.call("list_labels", { account: STUDIO_ADA }))).toContain("503");
    h.google.gmailFailure = { status: 403, googleStatus: "PERMISSION_DENIED" };
    expect(text(await h.call("list_labels", { account: STUDIO_ADA }))).toContain("403");
    expect(h.written.at(-1)).toMatchObject({ errorCode: "gmail_forbidden" });
    h.google.gmailFailure = { redirect: "https://evil.example.test/" };
    const r = await h.call("list_labels", { account: STUDIO_ADA });
    expect(r.isError).toBe(true);
    expect(text(r)).toContain("egress allowlist");
    expect(h.written.at(-1)).toMatchObject({ errorCode: "egress_denied" });
  });

  it("missing service-account secret: loud error naming the tenant, not the secret; nothing fetched; audit code set", async () => {
    await h.close();
    h = await harness({ SA_EXAMPLE_STUDIO: studioSa.json }); // labs key absent
    const r = await h.call("list_labels", { account: LABS_GRACE });
    expect(r.isError).toBe(true);
    expect(text(r)).toContain("example-labs");
    expect(text(r)).toContain(LABS_GRACE);
    expect(text(r)).toContain("operator configuration error");
    expect(text(r)).not.toContain("SA_EXAMPLE_LABS");
    expect(h.google.calls).toHaveLength(0);
    expect(h.written.at(-1)).toMatchObject({ tool: "list_labels", outcome: "error", errorCode: "service_account_secret_missing", tenant: "example-labs", account: LABS_GRACE });
    // the studio tenant still works: one tenant's misconfiguration never touches another
    expect((await h.call("list_labels", { account: STUDIO_ADA })).isError).toBeFalsy();
  });

  it("malformed service-account secret: loud error, no key material in the answer or the audit log", async () => {
    await h.close();
    h = await harness({ SA_EXAMPLE_STUDIO: '{"type":"service_account","client_email":"x@y.test","private_key":"-----BEGIN PRIVATE KEY-----\\nZZZZ\\n-----END PRIVATE KEY-----"}', SA_EXAMPLE_LABS: labsSa.json });
    const r = await h.call("get_message", { account: STUDIO_ADA, message_id: "m-inv-1" });
    expect(r.isError).toBe(true);
    expect(text(r)).toContain("malformed");
    expect(text(r)).not.toContain("ZZZZ");
    expect(JSON.stringify(h.written)).not.toContain("ZZZZ");
    expect(h.written.at(-1)).toMatchObject({ outcome: "error", errorCode: "service_account_key_invalid" });
  });

  it("Google refuses the delegation: loud error with the hint about Admin Console authorisation", async () => {
    h.google.tokenFailure = { status: 401, error: "unauthorized_client" };
    const r = await h.call("search_threads", { account: STUDIO_ADA, query: "" });
    expect(r.isError).toBe(true);
    expect(text(r)).toContain("unauthorized_client");
    expect(text(r)).toContain("Admin Console");
    expect(h.written.at(-1)).toMatchObject({ outcome: "error", errorCode: "delegation_token_refused" });
  });

  it("writes exactly one audit record per call, ok or not, and the console never sees a token", async () => {
    consoleError.mockClear();
    const before = h.written.length;
    await h.call("list_labels", { account: STUDIO_ADA });
    await h.call("list_labels", { account: "nobody@example-labs.test" });
    h.google.gmailFailure = { status: 429 };
    await h.call("list_labels", { account: STUDIO_ADA });
    expect(h.written.length - before).toBe(3);
    expect(h.written.slice(before).map((r) => r.outcome)).toEqual(["ok", "refused", "error"]);
    expect(consoleError.mock.calls.flat().map(String).join("\n")).not.toContain("fake-token-");
  });
});
