/**
 * Phase 1 read tools: search_threads, get_thread, get_message, list_labels.
 *
 * Every tool takes an explicit `account`, resolves it through the registry (rule 1; an unknown account is refused
 * before anything else happens), echoes `tenant` and `account` in its result (rule 2), writes one content-free
 * audit record per call (rule 7), and fails loudly on any Gmail or credential problem (rule 6). Every description
 * carries the untrusted-content sentence (rule 9).
 */
import type { CallToolResult, McpServer } from "@modelcontextprotocol/server";
import * as z from "zod";
import type { Audit } from "../../audit.js";
import { DelegationError } from "../../gmail/delegation.js";
import { GmailApiError, type GmailClient, type GmailMessage } from "../../gmail/client.js";
import { renderMessage, renderThread, summariseThread } from "../../gmail/render.js";
import { EgressDeniedError } from "../../net/egress.js";
import { type ResolvedMailbox, type TenantRegistry, UnknownAccountError } from "../../tenants/registry.js";
import { UNTRUSTED_NOTE, type McpIdentity } from "../identity.js";

/** Bounded page size (handoff §6). Each summary costs one metadata fetch, so the cap is deliberately small. */
export const SEARCH_MAX_RESULTS_CAP = 25;
export const SEARCH_MAX_RESULTS_DEFAULT = 10;
const MAX_QUERY_CHARS = 1000;
const MAX_PAGE_TOKEN_CHARS = 2000;
const SUMMARY_HEADERS = ["Subject", "From", "Date"] as const;

export interface ReadToolDeps {
  readonly registry: TenantRegistry;
  readonly gmail: GmailClient;
  readonly audit: Audit;
  readonly identity: McpIdentity;
  readonly now?: () => number;
}

const Account = z.string().min(3).max(254).describe("Mailbox address exactly as returned by list_accounts. Required; there is no default mailbox.");
const GmailId = z.string().min(1).max(128);

const Attachment = z.object({ filename: z.string(), mimeType: z.string(), sizeBytes: z.number(), inline: z.boolean() });
const Body = z.object({ text: z.string(), source: z.enum(["text/plain", "text/html", "none", "omitted"]), truncated: z.boolean(), originalChars: z.number() });
const Headers = z.object({
  from: z.string().optional(),
  to: z.string().optional(),
  cc: z.string().optional(),
  bcc: z.string().optional(),
  replyTo: z.string().optional(),
  subject: z.string().optional(),
  date: z.string().optional(),
  rfc822MessageId: z.string().optional(),
  inReplyTo: z.string().optional(),
  references: z.string().optional(),
});
const Message = z.object({
  messageId: z.string(),
  threadId: z.string(),
  labelIds: z.array(z.string()),
  internalDate: z.string().optional(),
  sizeEstimate: z.number().optional(),
  headers: Headers,
  snippet: z.string(),
  body: Body,
  attachments: z.array(Attachment),
});
const ThreadSummary = z.object({
  threadId: z.string(),
  subject: z.string().optional(),
  participants: z.array(z.string()),
  messageCount: z.number(),
  lastMessageDate: z.string().optional(),
  labelIds: z.array(z.string()),
  snippet: z.string(),
});

const Echo = { tenant: z.string(), account: z.string() };
export const SearchThreadsOutput = z.object({ ...Echo, query: z.string(), threads: z.array(ThreadSummary), nextPageToken: z.string().nullable(), resultSizeEstimate: z.number().nullable() });
export const GetThreadOutput = z.object({ ...Echo, threadId: z.string(), messageCount: z.number(), messages: z.array(Message), bodiesOmitted: z.boolean() });
export const GetMessageOutput = z.object({ ...Echo, message: Message });
export const ListLabelsOutput = z.object({ ...Echo, labels: z.array(z.object({ id: z.string(), name: z.string(), type: z.string().optional() })) });

type ErrorCode = string;

function classify(e: unknown): { readonly outcome: "refused" | "error"; readonly code: ErrorCode } {
  if (e instanceof UnknownAccountError) return { outcome: "refused", code: "unknown_account" };
  if (e instanceof DelegationError) return { outcome: "error", code: e.code };
  if (e instanceof GmailApiError) return { outcome: "error", code: e.code };
  if (e instanceof EgressDeniedError) return { outcome: "error", code: "egress_denied" };
  return { outcome: "error", code: "internal_error" };
}

/** What the model is told. Typed errors carry operator-safe messages; anything else is hidden behind a generic line. */
function loud(e: unknown): Error {
  if (e instanceof UnknownAccountError || e instanceof DelegationError || e instanceof GmailApiError) return e;
  if (e instanceof EgressDeniedError) return new Error(`Refused to contact a host outside the egress allowlist. ${e.message}`);
  return new Error("The mailbox call failed before any result was produced (internal error; see the server log). Do not treat this as an empty mailbox.");
}

export function registerReadTools(server: McpServer, deps: ReadToolDeps): void {
  const now = deps.now ?? (() => Date.now());
  const { identity } = deps;

  /**
   * The one path every read tool goes through: resolve the account (refusing unknown ones), run, audit, answer.
   * `ids` lets a tool contribute the thread/message id to the audit record; nothing else from the result is logged.
   */
  async function run<T extends { tenant: string; account: string }>(
    tool: string,
    account: string,
    fn: (target: ResolvedMailbox) => Promise<T>,
    ids: (out: T) => { threadId?: string; messageId?: string } = () => ({}),
  ): Promise<CallToolResult> {
    const started = now();
    let target: ResolvedMailbox;
    try {
      target = deps.registry.requireMailbox(account);
    } catch (e) {
      // The attempted account string is model-controlled input and is deliberately not recorded.
      await deps.audit.record({ tool, outcome: "refused", errorCode: "unknown_account", principal: identity.principal, clientId: identity.clientId, durationMs: now() - started });
      throw loud(e);
    }
    try {
      const out = await fn(target);
      await deps.audit.record({ tool, outcome: "ok", tenant: target.tenant.id, account: target.mailbox.address, ...ids(out), principal: identity.principal, clientId: identity.clientId, durationMs: now() - started });
      return { content: [{ type: "text", text: JSON.stringify(out, null, 2) }], structuredContent: out };
    } catch (e) {
      const { outcome, code } = classify(e);
      await deps.audit.record({ tool, outcome, errorCode: code, tenant: target.tenant.id, account: target.mailbox.address, principal: identity.principal, clientId: identity.clientId, durationMs: now() - started });
      if (e instanceof DelegationError) console.error(JSON.stringify({ delegation_error: e.code, tenant: e.tenantId, detail: e.detail }));
      else if (code === "internal_error") console.error(JSON.stringify({ tool_exception: e instanceof Error ? e.name : typeof e, tool, detail: e instanceof Error ? e.message.slice(0, 200) : undefined }));
      throw loud(e);
    }
  }

  const readOnly = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true } as const;

  server.registerTool(
    "search_threads",
    {
      title: "Search threads",
      description: `Search one mailbox with Gmail query syntax (for example \`from:someone newer_than:7d\`, \`is:unread\`, \`subject:invoice has:attachment\`, \`label:INBOX\`). Returns up to \`max_results\` (max ${SEARCH_MAX_RESULTS_CAP}) thread summaries, newest first: subject, participants, message count, last date, labels and a snippet. Pass \`page_token\` from a previous result to continue. Use get_thread to read bodies. Every result echoes the \`tenant\` (company) it belongs to: state it when reporting. ${UNTRUSTED_NOTE}`,
      inputSchema: z.object({
        account: Account,
        query: z.string().max(MAX_QUERY_CHARS).default("").describe("Gmail search query. Empty lists the most recent threads."),
        max_results: z.number().int().min(1).max(SEARCH_MAX_RESULTS_CAP).default(SEARCH_MAX_RESULTS_DEFAULT),
        page_token: z.string().min(1).max(MAX_PAGE_TOKEN_CHARS).optional().describe("Cursor from a previous search_threads result."),
        label_ids: z.array(z.string().min(1).max(100)).max(10).optional().describe("Restrict to threads carrying all of these label ids (see list_labels)."),
      }),
      outputSchema: SearchThreadsOutput,
      annotations: readOnly,
    },
    async (input) =>
      run("search_threads", input.account, async (target) => {
        const page = await deps.gmail.listThreads(target, { q: input.query, maxResults: input.max_results, ...(input.page_token !== undefined ? { pageToken: input.page_token } : {}), ...(input.label_ids !== undefined ? { labelIds: input.label_ids } : {}) });
        const summaries = await Promise.all(
          page.threads.map(async (t) => {
            const thread = await deps.gmail.getThread(target, t.id, "metadata", SUMMARY_HEADERS);
            return summariseThread(t.id, thread.messages ?? [], t.snippet);
          }),
        );
        return {
          tenant: target.tenant.id,
          account: target.mailbox.address,
          query: input.query,
          threads: summaries,
          nextPageToken: page.nextPageToken ?? null,
          resultSizeEstimate: page.resultSizeEstimate ?? null,
        };
      }),
  );

  server.registerTool(
    "get_thread",
    {
      title: "Get thread",
      description: `Read one thread in full from one mailbox: every message in order with its headers, its body as plain text (HTML is stripped; a body cut at the size bound is marked \`truncated\`; past the per-thread budget bodies are marked \`omitted\` and only headers remain) and its attachments listed by name, type and size only (attachments cannot be downloaded). Every result echoes the \`tenant\` it belongs to: state it when reporting. ${UNTRUSTED_NOTE}`,
      inputSchema: z.object({ account: Account, thread_id: GmailId.describe("Thread id from search_threads.") }),
      outputSchema: GetThreadOutput,
      annotations: readOnly,
    },
    async (input) =>
      run(
        "get_thread",
        input.account,
        async (target) => {
          const thread = await deps.gmail.getThread(target, input.thread_id, "full");
          const rendered = renderThread(thread.id, thread.messages ?? []);
          return { tenant: target.tenant.id, account: target.mailbox.address, ...rendered };
        },
        (out) => ({ threadId: out.threadId }),
      ),
  );

  server.registerTool(
    "get_message",
    {
      title: "Get message",
      description: `Read one message from one mailbox: headers, body as plain text (HTML stripped, bounded and marked \`truncated\` if cut) and attachments by name, type and size only. Every result echoes the \`tenant\` it belongs to: state it when reporting. ${UNTRUSTED_NOTE}`,
      inputSchema: z.object({ account: Account, message_id: GmailId.describe("Message id from get_thread.") }),
      outputSchema: GetMessageOutput,
      annotations: readOnly,
    },
    async (input) =>
      run(
        "get_message",
        input.account,
        async (target) => {
          const msg: GmailMessage = await deps.gmail.getMessage(target, input.message_id);
          return { tenant: target.tenant.id, account: target.mailbox.address, message: renderMessage(msg) };
        },
        (out) => ({ messageId: out.message.messageId, threadId: out.message.threadId }),
      ),
  );

  server.registerTool(
    "list_labels",
    {
      title: "List labels",
      description: `List the labels of one mailbox (system labels such as INBOX, SENT, UNREAD and the user's own). Label ids are what search_threads accepts in \`label_ids\`. Every result echoes the \`tenant\` it belongs to. ${UNTRUSTED_NOTE}`,
      inputSchema: z.object({ account: Account }),
      outputSchema: ListLabelsOutput,
      annotations: readOnly,
    },
    async (input) =>
      run("list_labels", input.account, async (target) => {
        const labels = await deps.gmail.listLabels(target);
        return { tenant: target.tenant.id, account: target.mailbox.address, labels: labels.map((l) => ({ id: l.id, name: l.name, ...(l.type !== undefined ? { type: l.type } : {}) })) };
      }),
  );
}
