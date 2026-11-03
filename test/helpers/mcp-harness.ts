/**
 * The same wiring as test/unit/write-tools.test.ts (real MCP server, real Gmail client, real delegation and egress,
 * fake Google), with hooks for an injectable ledger, mailbox data and limits. Used by the adversarial tests and
 * the organising-tool tests.
 */
import { readFileSync } from "node:fs";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import type { CallToolResult } from "@modelcontextprotocol/server";
import { Audit, type AuditRecord, type AuditSink } from "../../src/audit.js";
import { loadConfig, type AppConfig } from "../../src/config.js";
import { GmailClient } from "../../src/gmail/client.js";
import { DelegationTokenSource } from "../../src/gmail/delegation.js";
import { MemorySendLedger, type SendLedger } from "../../src/gmail/ledger.js";
import { DEFAULT_LIMITS, MemoryRateLimiter, type Limits } from "../../src/guard/ratelimit.js";
import { buildMcpServer } from "../../src/mcp/server.js";
import { GOOGLE_EGRESS, createEgressFetch } from "../../src/net/egress.js";
import { FakeGoogle, LABS_GRACE, STUDIO_ADA, STUDIO_HELLO, makeServiceAccount, sampleMailboxes, type FakeMailboxData, type TestServiceAccount } from "./fake-gmail.js";

const fixture = readFileSync(new URL("../../fixtures/tenants.example.json", import.meta.url), "utf8");
export const NOW = Date.UTC(2026, 10, 3, 12, 0, 0);

let shared: { cfg: AppConfig; studioSa: TestServiceAccount; labsSa: TestServiceAccount } | undefined;
async function setup(): Promise<NonNullable<typeof shared>> {
  if (shared === undefined) {
    shared = {
      cfg: loadConfig({ PUBLIC_URL: "https://mcp.example.test", TENANTS_JSON: fixture, ALLOWED_PRINCIPALS: STUDIO_ADA, GOOGLE_CLIENT_ID: "cid", GOOGLE_CLIENT_SECRET: "cs" }),
      studioSa: await makeServiceAccount("multimail-studio@fake-project.iam.gserviceaccount.test"),
      labsSa: await makeServiceAccount("multimail-labs@fake-project.iam.gserviceaccount.test"),
    };
  }
  return shared;
}

export interface Harness {
  readonly google: FakeGoogle;
  readonly written: AuditRecord[];
  readonly client: Client;
  call(name: string, args: Record<string, unknown>): Promise<CallToolResult>;
  close(): Promise<void>;
}

export async function harness(opts: { readonly ledger?: SendLedger; readonly mailboxes?: Record<string, FakeMailboxData>; readonly limits?: Partial<Limits> } = {}): Promise<Harness> {
  const { cfg, studioSa, labsSa } = await setup();
  const clock = () => NOW;
  const google = new FakeGoogle(
    [
      { sa: studioSa, mailboxes: [STUDIO_ADA, STUDIO_HELLO] },
      { sa: labsSa, mailboxes: [LABS_GRACE] },
    ],
    opts.mailboxes ?? sampleMailboxes(),
  );
  const fetch = createEgressFetch(GOOGLE_EGRESS, google.fetch);
  const tokens = new DelegationTokenSource({ secrets: { SA_EXAMPLE_STUDIO: studioSa.json, SA_EXAMPLE_LABS: labsSa.json }, fetch, now: clock });
  const written: AuditRecord[] = [];
  const sink: AuditSink = { write: async (r) => { written.push(r); } };
  const server = buildMcpServer(cfg, { principal: STUDIO_ADA, clientId: "client-1" }, {
    gmail: new GmailClient({ fetch, tokens }),
    audit: new Audit(sink, () => new Date(NOW)),
    now: clock,
    ledger: opts.ledger ?? new MemorySendLedger(clock),
    rateLimiter: new MemoryRateLimiter(clock),
    limits: { ...DEFAULT_LIMITS, ...opts.limits },
  });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await server.connect(st);
  const client = new Client({ name: "adversarial", version: "0" });
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

export const text = (r: CallToolResult): string => r.content.map((c) => (c.type === "text" ? c.text : "")).join("\n");
