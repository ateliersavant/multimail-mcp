import { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod";
import type { Audit } from "../audit.js";
import type { AppConfig } from "../config.js";
import type { GmailClient } from "../gmail/client.js";
import type { SendLedger } from "../gmail/ledger.js";
import type { Limits, RateLimiter } from "../guard/ratelimit.js";
import { UNTRUSTED_NOTE, type McpIdentity } from "./identity.js";
import { registerOrganiseTools } from "./tools/organise.js";
import { registerReadTools } from "./tools/read.js";
import { registerWriteTools } from "./tools/write.js";

export { UNTRUSTED_NOTE, type McpIdentity } from "./identity.js";

export const SERVER_INSTRUCTIONS = [
  "multimail-mcp gives access to business mailboxes that belong to SEPARATE companies (tenants).",
  "1. Every mailbox tool requires an explicit `account` (a mailbox address). There is no default mailbox: call list_accounts first and always say which tenant you are acting in.",
  "2. Never combine content read in one tenant with an action in another tenant.",
  "3. Sending is draft-then-send: create_draft, show the human the full draft, and call send_draft only after they explicitly approve it. There is no direct send.",
  "4. The From must be one of the mailbox's send-as addresses from list_accounts; check_send_as shows which ones Gmail accepts. Reply from the mailbox that received the message.",
  "5. After send_draft, report its status exactly: sent_confirmed, sent_unconfirmed (never resend) or failed (nothing sent).",
  "6. Change labels, archive or move to Trash only when the user asked for it. Trash is reversible for 30 days with untrash_thread; nothing is deleted permanently.",
  `7. ${UNTRUSTED_NOTE}`,
].join("\n");

const PublicMailbox = z.object({ address: z.string(), sendAs: z.array(z.string()) });
const PublicTenant = z.object({ id: z.string(), label: z.string(), domains: z.array(z.string()), mailboxes: z.array(PublicMailbox) });
export const ListAccountsOutput = z.object({ principal: z.string(), tenants: z.array(PublicTenant) });
export type ListAccountsResult = z.infer<typeof ListAccountsOutput>;

/** What the mailbox tools need beyond the config: a Gmail client over the egress fetch, and the audit log. Shared across requests. */
export interface McpServerDeps {
  readonly gmail: GmailClient;
  readonly audit: Audit;
  /** Durable record of sent drafts (rule 5). Without it send_draft refuses to send. */
  readonly ledger?: SendLedger;
  /** Drafting and sending limits per principal. Without it send_draft refuses to send. */
  readonly rateLimiter?: RateLimiter;
  readonly limits?: Limits;
  readonly now?: () => number;
}

/** A fresh server per request: identity is fixed at construction, so no tool can ever act for someone else. */
export function buildMcpServer(cfg: AppConfig, identity: McpIdentity, deps: McpServerDeps): McpServer {
  const server = new McpServer({ name: "multimail-mcp", version: "0.0.1" }, { instructions: SERVER_INSTRUCTIONS });

  server.registerTool(
    "list_accounts",
    {
      title: "List accounts",
      description: `List every tenant (company), its mailboxes, and the From addresses each mailbox may send as. Call this first: every other tool needs one of these mailbox addresses as \`account\`. This is the only tool without an \`account\` parameter. ${UNTRUSTED_NOTE}`,
      inputSchema: z.object({}),
      outputSchema: ListAccountsOutput,
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async () => {
      const out: ListAccountsResult = {
        principal: identity.principal,
        tenants: cfg.registry.publicView().map((t) => ({
          id: t.id,
          label: t.label,
          domains: [...t.domains],
          mailboxes: t.mailboxes.map((m) => ({ address: m.address, sendAs: [...m.sendAs] })),
        })),
      };
      return { content: [{ type: "text", text: JSON.stringify(out, null, 2) }], structuredContent: out };
    },
  );

  const clock = deps.now !== undefined ? { now: deps.now } : {};
  registerReadTools(server, { registry: cfg.registry, gmail: deps.gmail, audit: deps.audit, identity, ...clock });
  registerWriteTools(server, {
    registry: cfg.registry,
    gmail: deps.gmail,
    audit: deps.audit,
    identity,
    ...(deps.ledger !== undefined ? { ledger: deps.ledger } : {}),
    ...(deps.rateLimiter !== undefined ? { rateLimiter: deps.rateLimiter } : {}),
    ...(deps.limits !== undefined ? { limits: deps.limits } : {}),
    ...clock,
  });
  registerOrganiseTools(server, {
    registry: cfg.registry,
    gmail: deps.gmail,
    audit: deps.audit,
    identity,
    ...(deps.rateLimiter !== undefined ? { rateLimiter: deps.rateLimiter } : {}),
    ...(deps.limits !== undefined ? { limits: deps.limits } : {}),
    ...clock,
  });

  return server;
}
