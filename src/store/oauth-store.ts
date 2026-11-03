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

  /** Hourly sweep of expired rows; reads already ignore them, this just reclaims space. */
  override async alarm(): Promise<void> {
    this.ctx.storage.sql.exec("DELETE FROM kv WHERE expiration IS NOT NULL AND expiration <= ?", this.nowSeconds());
    const remaining = this.ctx.storage.sql.exec<{ n: number }>("SELECT count(*) AS n FROM kv WHERE expiration IS NOT NULL").one().n;
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
