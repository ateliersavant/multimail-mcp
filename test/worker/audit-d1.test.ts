import { describe, expect, it, vi } from "vitest";
import { env } from "cloudflare:workers";
import { AUDIT_RETENTION_DAYS, Audit, CompositeAuditSink, ConsoleAuditSink, D1AuditSink, auditFor, purgeAudit, type AuditSink } from "../../src/audit.js";
import { runRetention } from "../../src/index.js";

const rows = async (where = "1"): Promise<Record<string, unknown>[]> => (await env.AUDIT_DB.prepare(`SELECT * FROM audit WHERE ${where} ORDER BY id`).all()).results;

describe("durable audit log (D1)", () => {
  it("stores one row per record with only the allowlisted metadata columns", async () => {
    const audit = new Audit(new D1AuditSink(env.AUDIT_DB), () => new Date("2026-11-03T10:00:00.000Z"));
    await audit.record({ tool: "send_draft", outcome: "ok", tenant: "example-studio", account: "ada@example-studio.test", from: "hello@example-studio.test", messageId: "m1", threadId: "t1", draftId: "r-1", recipientCount: 3, clientId: "c1", principal: "ada@example-studio.test", durationMs: 42, subject: "Secret", body: "secret body", to: "x@vendor.test" });
    const [row] = await rows("draft_id = 'r-1'");
    expect(row).toMatchObject({ ts: "2026-11-03T10:00:00.000Z", tool: "send_draft", outcome: "ok", tenant: "example-studio", account: "ada@example-studio.test", from_address: "hello@example-studio.test", message_id: "m1", thread_id: "t1", draft_id: "r-1", recipient_count: 3, error_code: null, client_id: "c1", principal: "ada@example-studio.test", duration_ms: 42 });
    const columns = Object.keys(row ?? {}).sort();
    expect(columns).toEqual(["account", "client_id", "draft_id", "duration_ms", "error_code", "from_address", "id", "message_id", "outcome", "principal", "recipient_count", "tenant", "thread_id", "tool", "ts"]);
    expect(JSON.stringify(await rows())).not.toMatch(/Secret|secret body|vendor\.test/);
  });

  it("a failing durable store never fails the action; the log stream keeps the record and the error is reported by name", async () => {
    const stream: { written: unknown[] } & AuditSink = { written: [], write: async (r) => { stream.written.push(r); } };
    const broken: AuditSink = { write: async () => { throw new TypeError("D1 down"); } };
    const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    await expect(new Audit(new CompositeAuditSink(stream, broken)).record({ tool: "get_thread", outcome: "ok" })).resolves.toBeDefined();
    expect(stream.written).toHaveLength(1);
    expect(spy.mock.calls.flat().join(" ")).toContain('"audit_sink_error":"TypeError"');
    expect(spy.mock.calls.flat().join(" ")).not.toContain("D1 down");
    spy.mockRestore();
  });

  it("auditFor(env) writes to both the log stream and D1, once per env", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const a = auditFor(env);
    expect(auditFor(env)).toBe(a);
    await a.record({ tool: "list_labels", outcome: "ok", account: "grace@example-labs.test", clientId: "auditfor-test" });
    expect((await rows("client_id = 'auditfor-test'")).length).toBe(1);
    expect(log.mock.calls.flat().join(" ")).toContain("auditfor-test");
    log.mockRestore();
    expect(new ConsoleAuditSink()).toBeInstanceOf(ConsoleAuditSink);
  });

  it(`retention deletes rows older than ${AUDIT_RETENTION_DAYS} days and keeps the rest; the scheduled job runs it`, async () => {
    const now = Date.UTC(2026, 10, 3, 12, 0, 0);
    const day = 86_400_000;
    const at = (ms: number) => new Audit(new D1AuditSink(env.AUDIT_DB), () => new Date(ms));
    await at(now - 91 * day).record({ tool: "retention", outcome: "ok", clientId: "old-1" });
    await at(now - 120 * day).record({ tool: "retention", outcome: "ok", clientId: "old-2" });
    await at(now - 89 * day).record({ tool: "retention", outcome: "ok", clientId: "keep-1" });
    await at(now).record({ tool: "retention", outcome: "ok", clientId: "keep-2" });
    expect(await purgeAudit(env.AUDIT_DB, now)).toBe(2);
    expect((await rows("tool = 'retention'")).map((r) => r["client_id"])).toEqual(["keep-1", "keep-2"]);
    await at(now - 200 * day).record({ tool: "retention", outcome: "ok", clientId: "old-3" });
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    expect(await runRetention(env, now)).toBe(1);
    expect(log.mock.calls.flat().join(" ")).toContain('"audit_retention"');
    log.mockRestore();
  });
});
