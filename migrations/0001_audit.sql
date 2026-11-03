-- Content-free audit log (handoff rule 7, Q3: 90-day retention). One row per tool call, authorisation or refusal.
-- Columns mirror src/audit.ts AuditRecord exactly; there is deliberately no column that could hold content.
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  tool TEXT NOT NULL,
  outcome TEXT NOT NULL,
  tenant TEXT,
  account TEXT,
  from_address TEXT,
  message_id TEXT,
  thread_id TEXT,
  draft_id TEXT,
  recipient_count INTEGER,
  error_code TEXT,
  client_id TEXT,
  principal TEXT,
  duration_ms INTEGER
);
CREATE INDEX IF NOT EXISTS audit_ts ON audit (ts);
