/**
 * Strongly consistent storage for the OAuth layer.
 *
 * The OAuth library keeps clients, grants, tokens and sign-in transactions in a KV-shaped store.
 * Cloudflare KV is eventually consistent across locations (writes take up to 60 s to appear elsewhere,
 * and misses are cached). That broke the first real sign-in on 2026-11-03: the browser's callback wrote
 * the grant at one location and the client's server read it 0.6 s later at another, got "not found",
 * and the authorization code was refused. A single Durable Object with SQLite storage has no such window.
 */
import { DurableObject } from "cloudflare:workers";
import { decide, type RateDecision } from "../guard/ratelimit.js";

export interface StoredValue {
  readonly value: string;
  /** Absolute expiry, seconds since the epoch. Absent = never expires. */
  readonly expiration?: number;
  /** KV-style metadata as JSON text, when the writer supplied any. A string crosses the RPC boundary with a flat type. */
  readonly metadataJson?: string;
}

export interface PutOptions {
  readonly expirationTtl?: number;
  readonly expiration?: number;
  readonly metadataJson?: string;
}

export interface ListOptions {
  readonly prefix?: string;
  readonly limit?: number;
  readonly cursor?: string;
}

export interface ListKey {
  readonly name: string;
  readonly expiration?: number;
  readonly metadataJson?: string;
}

export type ListPage = { readonly keys: ListKey[]; readonly list_complete: true } | { readonly keys: ListKey[]; readonly list_complete: false; readonly cursor: string };

const SWEEP_INTERVAL_MS = 60 * 60 * 1000;
const MAX_LIST_LIMIT = 1000;

type Row = Record<string, SqlStorageValue> & {
  key: string;
  value: string;
  expiration: number | null;
  metadata: string | null;
};

function rowToStored(row: Row): StoredValue {
  const out: { -readonly [K in keyof StoredValue]: StoredValue[K] } = { value: row.value };
  if (row.expiration !== null) out.expiration = row.expiration;
  if (row.metadata !== null) out.metadataJson = row.metadata;
  return out;
}

function rowToListKey(row: Row): ListKey {
  const out: { -readonly [K in keyof ListKey]: ListKey[K] } = { name: row.key };
  if (row.expiration !== null) out.expiration = row.expiration;
  if (row.metadata !== null) out.metadataJson = row.metadata;
  return out;
}

export class OAuthStore extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.blockConcurrencyWhile(async () => {
      ctx.storage.sql.exec("CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL, expiration INTEGER, metadata TEXT)");
      // Rate-limit windows (src/guard/ratelimit.ts). Keys hold an OAuth client id or principal and a limit name; no content.
      ctx.storage.sql.exec("CREATE TABLE IF NOT EXISTS ratelimit (key TEXT PRIMARY KEY, window_start INTEGER NOT NULL, count INTEGER NOT NULL)");
      ctx.storage.sql.exec("CREATE INDEX IF NOT EXISTS kv_expiration ON kv (expiration)");
    });
  }

  private nowSeconds(): number {
    return Math.floor(Date.now() / 1000);
  }

  async get(key: string): Promise<StoredValue | null> {
    const row = this.ctx.storage.sql.exec<Row>("SELECT key, value, expiration, metadata FROM kv WHERE key = ?", key).toArray()[0];
    if (row === undefined) return null;
    if (row.expiration !== null && row.expiration <= this.nowSeconds()) {
      this.ctx.storage.sql.exec("DELETE FROM kv WHERE key = ?", key);
      return null;
    }
    return rowToStored(row);
  }

  async put(key: string, value: string, options: PutOptions = {}): Promise<void> {
    let expiration: number | null = null;
    if (options.expiration !== undefined) expiration = Math.floor(options.expiration);
    else if (options.expirationTtl !== undefined) expiration = this.nowSeconds() + Math.max(1, Math.floor(options.expirationTtl));
    const metadata = options.metadataJson ?? null;
    this.ctx.storage.sql.exec(
      "INSERT INTO kv (key, value, expiration, metadata) VALUES (?, ?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, expiration = excluded.expiration, metadata = excluded.metadata",
      key,
      value,
      expiration,
      metadata,
    );
    if ((await this.ctx.storage.getAlarm()) === null) await this.ctx.storage.setAlarm(Date.now() + SWEEP_INTERVAL_MS);
  }

  async delete(key: string): Promise<void> {
    this.ctx.storage.sql.exec("DELETE FROM kv WHERE key = ?", key);
  }

  /** Lexicographic by key, like KV. The cursor is the last key of the previous page. */
  async list(options: ListOptions = {}): Promise<ListPage> {
    const limit = Math.min(Math.max(Math.floor(options.limit ?? MAX_LIST_LIMIT), 1), MAX_LIST_LIMIT);
    const prefix = options.prefix ?? "";
    const after = options.cursor === undefined ? "" : decodeCursor(options.cursor);
    const rows = this.ctx.storage.sql
      .exec<Row>(
        "SELECT key, value, expiration, metadata FROM kv WHERE substr(key, 1, ?) = ? AND key > ? AND (expiration IS NULL OR expiration > ?) ORDER BY key LIMIT ?",
        prefix.length,
        prefix,
        after,
        this.nowSeconds(),
        limit + 1,
      )
      .toArray();
    const page = rows.slice(0, limit);
    const keys: ListKey[] = page.map(rowToListKey);
    const last = page[page.length - 1];
    if (rows.length > limit && last !== undefined) return { keys, list_complete: false, cursor: encodeCursor(last.key) };
    return { keys, list_complete: true };
  }

  /**
   * Atomic check-and-increment of one fixed window. Synchronous SQL with no await in between, so concurrent RPCs to this
   * object are serialised by its input gate and cannot both pass a limit.
   */
  async hit(key: string, limit: number, windowSeconds: number, nowMs: number): Promise<RateDecision> {
    const k = `${key}|${windowSeconds}`;
    const row = this.ctx.storage.sql.exec<{ window_start: number; count: number }>("SELECT window_start, count FROM ratelimit WHERE key = ?", k).toArray()[0];
    const r = decide(row === undefined ? undefined : { windowStart: row.window_start, count: row.count }, limit, windowSeconds, nowMs);
    if (r.next !== undefined) {
      this.ctx.storage.sql.exec("INSERT INTO ratelimit (key, window_start, count) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET window_start = excluded.window_start, count = excluded.count", k, r.next.windowStart, r.next.count);
    }
    if ((await this.ctx.storage.getAlarm()) === null) await this.ctx.storage.setAlarm(Date.now() + SWEEP_INTERVAL_MS);
    return r.decision;
  }

  /**
   * The send ledger's claim (src/gmail/ledger.ts), atomic like `hit`: returns the live entry's JSON when the draft is
   * already sent or a send is in flight, otherwise records an in-flight marker that expires after `ttlSeconds` and
   * returns null. Two concurrent sends of one draft can never both get null.
   */
  async ledgerClaim(key: string, sendingJson: string, ttlSeconds: number): Promise<string | null> {
    const row = this.ctx.storage.sql.exec<Row>("SELECT key, value, expiration, metadata FROM kv WHERE key = ?", key).toArray()[0];
    if (row !== undefined && (row.expiration === null || row.expiration > this.nowSeconds())) return row.value;
    this.ctx.storage.sql.exec(
      "INSERT INTO kv (key, value, expiration, metadata) VALUES (?, ?, ?, NULL) ON CONFLICT(key) DO UPDATE SET value = excluded.value, expiration = excluded.expiration, metadata = NULL",
      key,
      sendingJson,
      this.nowSeconds() + Math.max(1, Math.floor(ttlSeconds)),
    );
    if ((await this.ctx.storage.getAlarm()) === null) await this.ctx.storage.setAlarm(Date.now() + SWEEP_INTERVAL_MS);
    return null;
  }

  /** Drops an in-flight marker; never a sent record. */
  async ledgerRelease(key: string): Promise<void> {
    const row = this.ctx.storage.sql.exec<{ value: string }>("SELECT value FROM kv WHERE key = ?", key).toArray()[0];
    if (row === undefined) return;
    let state: unknown;
    try {
      state = (JSON.parse(row.value) as { state?: unknown }).state;
    } catch {
      return;
    }
    if (state === "sending") this.ctx.storage.sql.exec("DELETE FROM kv WHERE key = ?", key);
  }

  /** Hourly sweep of expired rows; reads already ignore them, this just reclaims space. */
  override async alarm(): Promise<void> {
    // Windows older than two days can never matter again (the longest window is one day).
    this.ctx.storage.sql.exec("DELETE FROM ratelimit WHERE window_start < ?", Math.floor(Date.now() / 1000) - 2 * 24 * 3600);
    this.ctx.storage.sql.exec("DELETE FROM kv WHERE expiration IS NOT NULL AND expiration <= ?", this.nowSeconds());
    const remaining = this.ctx.storage.sql.exec<{ n: number }>("SELECT (SELECT count(*) FROM kv WHERE expiration IS NOT NULL) + (SELECT count(*) FROM ratelimit) AS n").one().n;
    if (remaining > 0) await this.ctx.storage.setAlarm(Date.now() + SWEEP_INTERVAL_MS);
  }
}

function encodeCursor(key: string): string {
  return btoa(unescape(encodeURIComponent(key))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodeCursor(cursor: string): string {
  const pad = cursor.length % 4 === 0 ? "" : "=".repeat(4 - (cursor.length % 4));
  return decodeURIComponent(escape(atob(cursor.replace(/-/g, "+").replace(/_/g, "/") + pad)));
}
