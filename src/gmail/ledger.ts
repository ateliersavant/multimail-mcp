/**
 * Rule 5's memory: which drafts this server has already sent, and which sends are in flight. A successfully sent
 * draft no longer exists in Gmail, so without this a retried send_draft would see "not found" and invite the model
 * to recreate and resend the message. Kept in the strongly consistent OAuth Durable Object (via its KV interface),
 * under its own key prefix. Holds ids and timestamps only, never content.
 */
export interface SentRecord {
  readonly messageId: string;
  readonly threadId: string;
  readonly sentAt: number;
}

export type LedgerEntry = { readonly state: "sent"; readonly record: SentRecord } | { readonly state: "sending"; readonly since: number };

export interface SendLedger {
  lookup(account: string, draftId: string): Promise<LedgerEntry | null>;
  markSending(account: string, draftId: string, now: number): Promise<void>;
  markSent(account: string, draftId: string, record: SentRecord): Promise<void>;
  clear(account: string, draftId: string): Promise<void>;
}

/** An in-flight marker expires after this, so a crashed send never blocks a draft forever. */
export const SENDING_TTL_SECONDS = 120;
/** How long a sent draft id is remembered. */
export const SENT_TTL_SECONDS = 90 * 24 * 3600;

const key = (account: string, draftId: string): string => `multimail-send:${account}:${draftId}`;

function parse(text: string | null, now: number): LedgerEntry | null {
  if (text === null) return null;
  try {
    const v = JSON.parse(text) as { state?: unknown; messageId?: unknown; threadId?: unknown; sentAt?: unknown; since?: unknown };
    if (v.state === "sent" && typeof v.messageId === "string" && typeof v.threadId === "string" && typeof v.sentAt === "number") {
      return { state: "sent", record: { messageId: v.messageId, threadId: v.threadId, sentAt: v.sentAt } };
    }
    if (v.state === "sending" && typeof v.since === "number" && now - v.since < SENDING_TTL_SECONDS * 1000) return { state: "sending", since: v.since };
  } catch {
    return null;
  }
  return null;
}

export class KvSendLedger implements SendLedger {
  constructor(
    private readonly kv: KVNamespace,
    private readonly now: () => number = () => Date.now(),
  ) {}

  async lookup(account: string, draftId: string): Promise<LedgerEntry | null> {
    return parse(await this.kv.get(key(account, draftId)), this.now());
  }

  async markSending(account: string, draftId: string, now: number): Promise<void> {
    await this.kv.put(key(account, draftId), JSON.stringify({ state: "sending", since: now }), { expirationTtl: SENDING_TTL_SECONDS });
  }

  async markSent(account: string, draftId: string, record: SentRecord): Promise<void> {
    await this.kv.put(key(account, draftId), JSON.stringify({ state: "sent", ...record }), { expirationTtl: SENT_TTL_SECONDS });
  }

  async clear(account: string, draftId: string): Promise<void> {
    await this.kv.delete(key(account, draftId));
  }
}

/** For tests: the same semantics in memory, with an injectable clock. */
export class MemorySendLedger implements SendLedger {
  private readonly entries = new Map<string, string>();
  constructor(private readonly now: () => number = () => Date.now()) {}

  async lookup(account: string, draftId: string): Promise<LedgerEntry | null> {
    return parse(this.entries.get(key(account, draftId)) ?? null, this.now());
  }
  async markSending(account: string, draftId: string, now: number): Promise<void> {
    this.entries.set(key(account, draftId), JSON.stringify({ state: "sending", since: now }));
  }
  async markSent(account: string, draftId: string, record: SentRecord): Promise<void> {
    this.entries.set(key(account, draftId), JSON.stringify({ state: "sent", ...record }));
  }
  async clear(account: string, draftId: string): Promise<void> {
    this.entries.delete(key(account, draftId));
  }
}
