/**
 * Rate limits (handoff §6 "rate limits per client token"). Fixed windows counted in the OAuth Durable Object, so a
 * check-and-increment is atomic: two parallel requests cannot both slip under a limit. A fixed window can admit up to
 * twice the limit across a window boundary; the limits below are set with that in mind.
 */
import { STORE_NAME } from "../store/consistent-kv.js";
import type { OAuthStore } from "../store/oauth-store.js";

export interface RateDecision {
  readonly allowed: boolean;
  readonly count: number;
  /** Seconds until the current window ends; 0 when allowed. */
  readonly retryAfterSeconds: number;
}

export interface RateLimiter {
  hit(key: string, limit: number, windowSeconds: number): Promise<RateDecision>;
}

export interface Limits {
  /** MCP HTTP requests per client token (principal + OAuth client) per minute. */
  readonly mcpPerMinute: number;
  /** create_draft + update_draft per principal per hour. */
  readonly draftsPerHour: number;
  /** send_draft per principal per hour, and per day. */
  readonly sendsPerHour: number;
  readonly sendsPerDay: number;
}

export const DEFAULT_LIMITS: Limits = { mcpPerMinute: 120, draftsPerHour: 120, sendsPerHour: 20, sendsPerDay: 100 };

/** Parses an optional override such as MCP_RATE_LIMIT_PER_MINUTE; out-of-range or junk values fall back to the default. */
export function parseLimit(raw: string | undefined, fallback: number, min: number, max: number): number {
  if (raw === undefined || !/^\d{1,6}$/.test(raw.trim())) return fallback;
  const n = Number(raw.trim());
  return n >= min && n <= max ? n : fallback;
}

/** The pure window arithmetic, shared by the Durable Object and the in-memory limiter. */
export function decide(prev: { readonly windowStart: number; readonly count: number } | undefined, limit: number, windowSeconds: number, nowMs: number): { readonly decision: RateDecision; readonly next?: { readonly windowStart: number; readonly count: number } } {
  const nowSec = Math.floor(nowMs / 1000);
  const windowStart = Math.floor(nowSec / windowSeconds) * windowSeconds;
  const count = prev !== undefined && prev.windowStart === windowStart ? prev.count : 0;
  if (count >= limit) return { decision: { allowed: false, count, retryAfterSeconds: Math.max(1, windowStart + windowSeconds - nowSec) } };
  return { decision: { allowed: true, count: count + 1, retryAfterSeconds: 0 }, next: { windowStart, count: count + 1 } };
}

/** Production limiter: one RPC to the store Durable Object per check. */
export class DurableRateLimiter implements RateLimiter {
  constructor(private readonly namespace: DurableObjectNamespace<OAuthStore>) {}
  hit(key: string, limit: number, windowSeconds: number): Promise<RateDecision> {
    const stub = this.namespace.get(this.namespace.idFromName(STORE_NAME));
    return stub.hit(key, limit, windowSeconds, Date.now());
  }
}

/** Tests: the same arithmetic in memory, with an injectable clock. */
export class MemoryRateLimiter implements RateLimiter {
  private readonly windows = new Map<string, { windowStart: number; count: number }>();
  constructor(private readonly now: () => number = () => Date.now()) {}
  async hit(key: string, limit: number, windowSeconds: number): Promise<RateDecision> {
    const k = `${key}|${windowSeconds}`;
    const r = decide(this.windows.get(k), limit, windowSeconds, this.now());
    if (r.next !== undefined) this.windows.set(k, { ...r.next });
    return r.decision;
  }
}
