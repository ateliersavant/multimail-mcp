/**
 * Rule 7: telemetry is content-free. This module is the only path to the audit log and the
 * only logger the tools may use. It accepts a closed set of metadata fields and silently drops
 * everything else, so a future tool cannot leak a subject or a recipient by accident.
 */
export type Outcome = "ok" | "refused" | "error";

export interface AuditRecord {
  readonly ts: string;
  readonly tool: string;
  readonly outcome: Outcome;
  readonly tenant?: string;
  readonly account?: string;
  readonly from?: string;
  readonly messageId?: string;
  readonly threadId?: string;
  readonly draftId?: string;
  readonly recipientCount?: number;
  /** A short machine code such as "unknown_account" or "send_as_refused". Never an error message. */
  readonly errorCode?: string;
  readonly clientId?: string;
  readonly principal?: string;
  readonly durationMs?: number;
}

const STRING_KEYS = ["tool", "tenant", "account", "from", "messageId", "threadId", "draftId", "errorCode", "clientId", "principal"] as const;
const NUMBER_KEYS = ["recipientCount", "durationMs"] as const;
const OUTCOMES: ReadonlySet<string> = new Set<Outcome>(["ok", "refused", "error"]);
const MAX_STRING = 200;
const ERROR_CODE = /^[a-z][a-z0-9_]{0,63}$/;

/**
 * Builds a record from loose input, keeping only allowlisted keys. Content-bearing keys
 * (subject, body, to, cc, bcc, snippet, attachment names, headers, query) can never get through
 * because nothing outside the allowlist is copied.
 */
export function toAuditRecord(input: Readonly<Record<string, unknown>>, now: () => Date = () => new Date()): AuditRecord {
  const tool = typeof input["tool"] === "string" ? input["tool"].slice(0, MAX_STRING) : "unknown";
  const rawOutcome = input["outcome"];
  const outcome: Outcome = typeof rawOutcome === "string" && OUTCOMES.has(rawOutcome) ? (rawOutcome as Outcome) : "error";
  const out: { -readonly [K in keyof AuditRecord]: AuditRecord[K] } = { ts: now().toISOString(), tool, outcome };
  for (const k of STRING_KEYS) {
    if (k === "tool") continue;
    const v = input[k];
    if (typeof v !== "string" || v.length === 0) continue;
    if (k === "errorCode" && !ERROR_CODE.test(v)) {
      out.errorCode = "invalid_error_code";
      continue;
    }
    out[k] = v.slice(0, MAX_STRING);
  }
  for (const k of NUMBER_KEYS) {
    const v = input[k];
    if (typeof v === "number" && Number.isFinite(v) && v >= 0) out[k] = Math.floor(v);
  }
  return out;
}

export interface AuditSink {
  write(record: AuditRecord): Promise<void>;
}

/** Structured one-line JSON to the Worker log stream. The KV/D1 sink with retention arrives in Phase 3. */
export class ConsoleAuditSink implements AuditSink {
  async write(record: AuditRecord): Promise<void> {
    console.log(JSON.stringify({ audit: record }));
  }
}

export class Audit {
  constructor(private readonly sink: AuditSink, private readonly now: () => Date = () => new Date()) {}
  async record(input: Readonly<Record<string, unknown>>): Promise<AuditRecord> {
    const rec = toAuditRecord(input, this.now);
    await this.sink.write(rec);
    return rec;
  }
}
