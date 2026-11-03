/**
 * Rule 5's memory: which drafts this server has already sent, and which sends are in flight. A successfully sent
 * draft no longer exists in Gmail, so without this a retried send_draft would see "not found" and invite the model
 * to recreate and resend the message. Kept in the strongly consistent OAuth Durable Object, under its own key
 * prefix. Holds ids and timestamps only, never content.
 *
 * A send starts with an atomic `claim`: exactly one of several concurrent send_draft calls for one draft gets it, the
 * others are refused before Gmail is called. `release` gives up a claim when nothing was sent; it never removes a
 * sent record.
 */
import { STORE_NAME } from "../store/consistent-kv.js";
import type { OAuthStore } from "../store/oauth-store.js";

export interface SentRecord {
  readonly messageId: string;
  readonly threadId: string;
  readonly sentAt: number;
}

export type LedgerEntry = { readonly state: "sent"; readonly record: SentRecord } | { readonly state: "sending"; readonly since: number };

export type ClaimResult = { readonly claimed: true } | { readonly claimed: false; readonly entry: LedgerEntry };

export interface SendLedger {
  lookup(account: string, draftId: string): Promise<LedgerEntry | null>;
  claim(account: string, draftId: string, now: number): Promise<ClaimResult>;
  markSent(account: string, draftId: string, record: SentRecord): Promise<void>;
  release(account: string, draftId: string): Promise<void>;
}

/** An in-flight marker expires after this, so a crashed send never blocks a draft forever. */
export const SENDING_TTL_SECONDS = 120;
/** How long a sent draft id is remembered. */
export const SENT_TTL_SECONDS = 90 * 24 * 3600;

const key = (account: string, draftId: string): string => `multimail-send:${account}:${draftId}`;

/** Expiry is the store's job (each row carries its own); this only reads the shape. */
function parse(text: string | null): LedgerEntry | null {
  if (text === null) return null;
  try {
    const v = JSON.parse(text) as { state?: unknown; messageId?: unknown; threadId?: unknown; sentAt?: unknown; since?: unknown };
    if (v.state === "sent" && typeof v.messageId === "string" && typeof v.threadId === "string" && typeof v.sentAt === "number") {
      return { state: "sent", record: { messageId: v.messageId, threadId: v.threadId, sentAt: v.sentAt } };
    }
    if (v.state === "sending" && typeof v.since === "number") return { state: "sending", since: v.since };
  } catch {
    return null;
  }
  return null;
}

const sendingJson = (now: number): string => JSON.stringify({ state: "sending", since: now });
const sentJson = (record: SentRecord): string => JSON.stringify({ state: "sent", ...record });

/** A live entry the store returned but that is unreadable still blocks the send: refusing is the safe side. */
function blocking(text: string, now: number): LedgerEntry {
  return parse(text) ?? { state: "sending", since: now };
}

export class DurableSendLedger implements SendLedger {
  constructor(private readonly namespace: DurableObjectNamespace<OAuthStore>) {}

  // A stub is request-scoped I/O and must not be reused across requests; the namespace binding may be.
  private stub(): DurableObjectStub<OAuthStore> {
    return this.namespace.get(this.namespace.idFromName(STORE_NAME));
  }

  async lookup(account: string, draftId: string): Promise<LedgerEntry | null> {
    const stored = await this.stub().get(key(account, draftId));
    return stored === null ? null : parse(stored.value);
  }

  async claim(account: string, draftId: string, now: number): Promise<ClaimResult> {
    const existing = await this.stub().ledgerClaim(key(account, draftId), sendingJson(now), SENDING_TTL_SECONDS);
    return existing === null ? { claimed: true } : { claimed: false, entry: blocking(existing, now) };
  }

  async markSent(account: string, draftId: string, record: SentRecord): Promise<void> {
    await this.stub().put(key(account, draftId), sentJson(record), { expirationTtl: SENT_TTL_SECONDS });
  }

  async release(account: string, draftId: string): Promise<void> {
    await this.stub().ledgerRelease(key(account, draftId));
  }
}

/** For tests: the same semantics in memory, with an injectable clock. */
export class MemorySendLedger implements SendLedger {
  private readonly entries = new Map<string, { readonly value: string; readonly expiresAt: number }>();
  constructor(private readonly now: () => number = () => Date.now()) {}

  private live(k: string): string | null {
    const e = this.entries.get(k);
    if (e === undefined) return null;
    if (e.expiresAt <= this.now()) {
      this.entries.delete(k);
      return null;
    }
    return e.value;
  }

  async lookup(account: string, draftId: string): Promise<LedgerEntry | null> {
    return parse(this.live(key(account, draftId)));
  }
  async claim(account: string, draftId: string, now: number): Promise<ClaimResult> {
    const k = key(account, draftId);
    const existing = this.live(k);
    if (existing !== null) return { claimed: false, entry: blocking(existing, now) };
    this.entries.set(k, { value: sendingJson(now), expiresAt: this.now() + SENDING_TTL_SECONDS * 1000 });
    return { claimed: true };
  }
  async markSent(account: string, draftId: string, record: SentRecord): Promise<void> {
    this.entries.set(key(account, draftId), { value: sentJson(record), expiresAt: this.now() + SENT_TTL_SECONDS * 1000 });
  }
  async release(account: string, draftId: string): Promise<void> {
    const k = key(account, draftId);
    if (parse(this.live(k))?.state === "sending") this.entries.delete(k);
  }
}
