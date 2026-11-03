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

/** Q3: audit rows older than this are deleted by the daily scheduled job. */
export const AUDIT_RETENTION_DAYS = 90;

/** The durable copy: one row per record in the D1 `audit` table (migrations/0001_audit.sql). Only allowlisted fields exist. */
export class D1AuditSink implements AuditSink {
  constructor(private readonly db: D1Database) {}

  async write(r: AuditRecord): Promise<void> {
    await this.db
      .prepare(
        "INSERT INTO audit (ts, tool, outcome, tenant, account, from_address, message_id, thread_id, draft_id, recipient_count, error_code, client_id, principal, duration_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
      )
      .bind(r.ts, r.tool, r.outcome, r.tenant ?? null, r.account ?? null, r.from ?? null, r.messageId ?? null, r.threadId ?? null, r.draftId ?? null, r.recipientCount ?? null, r.errorCode ?? null, r.clientId ?? null, r.principal ?? null, r.durationMs ?? null)
      .run();
  }
}

/**
 * Writes every record to the log stream first, then to the durable store. A durable-store failure is reported (by
 * error name only) and never turns a completed action into an error: the log-stream copy is the fallback.
 */
export class CompositeAuditSink implements AuditSink {
  constructor(
    private readonly stream: AuditSink,
    private readonly durable: AuditSink,
  ) {}

  async write(record: AuditRecord): Promise<void> {
    await this.stream.write(record);
    try {
      await this.durable.write(record);
    } catch (e) {
      console.error(JSON.stringify({ audit_sink_error: e instanceof Error ? e.name : typeof e, tool: record.tool }));
    }
  }
}

const audits = new WeakMap<object, Audit>();

/** One Audit per env object: the log stream plus the D1 table when the binding exists (the Worker entry requires it). */
export function auditFor(env: { readonly AUDIT_DB?: D1Database }): Audit {
  const hit = audits.get(env);
  if (hit !== undefined) return hit;
  const sink = env.AUDIT_DB !== undefined ? new CompositeAuditSink(new ConsoleAuditSink(), new D1AuditSink(env.AUDIT_DB)) : new ConsoleAuditSink();
  const audit = new Audit(sink);
  audits.set(env, audit);
  return audit;
}

/** Deletes audit rows older than the retention period; returns how many went. Run daily by the scheduled handler. */
export async function purgeAudit(db: D1Database, nowMs: number, keepDays: number = AUDIT_RETENTION_DAYS): Promise<number> {
  const cutoff = new Date(nowMs - keepDays * 24 * 3600 * 1000).toISOString();
  const res = await db.prepare("DELETE FROM audit WHERE ts < ?1").bind(cutoff).run();
  return res.meta.changes ?? 0;
}
