import { describe, expect, it } from "vitest";
import { Audit, toAuditRecord, type AuditRecord, type AuditSink } from "../../src/audit.js";

const fixedNow = () => new Date("2026-11-03T10:00:00.000Z");

describe("audit records are content-free (rule 7)", () => {
  it("keeps only allowlisted metadata and drops every content field", () => {
    const rec = toAuditRecord(
      {
        tool: "send_draft",
        outcome: "ok",
        tenant: "example-studio",
        account: "ada@example-studio.test",
        from: "ada@example-studio.test",
        messageId: "m1",
        threadId: "t1",
        draftId: "d1",
        recipientCount: 3,
        clientId: "c1",
        principal: "ada@example-studio.test",
        // everything below must vanish
        subject: "Confidential offer",
        body: "please wire the funds",
        snippet: "please wire",
        to: ["x@example.test"],
        cc: "y@example.test",
        bcc: "z@example.test",
        attachments: ["contract.pdf"],
        headers: { "x-foo": "bar" },
        query: "from:bank",
        error: new Error("Mailbox foo@bar said no"),
      },
      fixedNow,
    );
    const json = JSON.stringify(rec);
    for (const banned of ["Confidential", "wire", "x@example.test", "y@example", "z@example", "contract.pdf", "x-foo", "from:bank", "said no", "subject", "body", "snippet", "attachments", "headers", "query"]) {
      expect(json).not.toContain(banned);
    }
    expect(rec).toEqual<AuditRecord>({
      ts: "2026-11-03T10:00:00.000Z",
      tool: "send_draft",
      outcome: "ok",
      tenant: "example-studio",
      account: "ada@example-studio.test",
      from: "ada@example-studio.test",
      messageId: "m1",
      threadId: "t1",
      draftId: "d1",
      recipientCount: 3,
      clientId: "c1",
      principal: "ada@example-studio.test",
    });
  });

  it("refuses free-text error codes (an error message could carry content)", () => {
    expect(toAuditRecord({ tool: "x", outcome: "error", errorCode: "Mailbox ada@example-studio.test refused: subject Hello" }, fixedNow).errorCode).toBe("invalid_error_code");
    expect(toAuditRecord({ tool: "x", outcome: "refused", errorCode: "unknown_account" }, fixedNow).errorCode).toBe("unknown_account");
  });

  it("defaults unknown tools and outcomes to safe values and bounds string length", () => {
    const rec = toAuditRecord({ outcome: "success", account: "a".repeat(1000) }, fixedNow);
    expect(rec.tool).toBe("unknown");
    expect(rec.outcome).toBe("error");
    expect(rec.account?.length).toBe(200);
  });

  it("ignores negative, NaN and non-numeric counts", () => {
    const rec = toAuditRecord({ tool: "x", outcome: "ok", recipientCount: -1, durationMs: Number.NaN }, fixedNow);
    expect(rec.recipientCount).toBeUndefined();
    expect(rec.durationMs).toBeUndefined();
  });

  it("writes the sanitised record to the sink", async () => {
    const written: AuditRecord[] = [];
    const sink: AuditSink = { write: async (r) => { written.push(r); } };
    const audit = new Audit(sink, fixedNow);
    await audit.record({ tool: "list_accounts", outcome: "ok", subject: "nope" });
    expect(written).toHaveLength(1);
    expect(JSON.stringify(written[0])).not.toContain("nope");
  });
});
