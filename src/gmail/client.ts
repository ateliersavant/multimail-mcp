/**
 * A thin Gmail REST client. Every request names the mailbox twice: in the path (`users/<address>/…`) and in the
 * delegated token's subject. Gmail refuses a mismatch, which makes "wrong token for this mailbox" structurally
 * impossible to get past. Rule 6: any non-2xx answer is a typed, loud error; nothing here ever returns an empty
 * result in place of a failure.
 */
import type { FetchLike } from "../net/egress.js";
import type { ResolvedMailbox } from "../tenants/registry.js";
import type { DelegationTokenSource } from "./delegation.js";

export const GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1/users/";

export type GmailErrorCode = "gmail_unauthorized" | "gmail_forbidden" | "gmail_not_found" | "gmail_rate_limited" | "gmail_bad_request" | "gmail_unavailable" | "gmail_error" | "gmail_malformed_response" | "gmail_bad_id";

export class GmailApiError extends Error {
  constructor(
    readonly code: GmailErrorCode,
    readonly status: number,
    readonly account: string,
    message: string,
  ) {
    super(message);
    this.name = "GmailApiError";
  }
}

/** Gmail ids are opaque hex strings; anything else never reaches a URL. */
const GMAIL_ID = /^[A-Za-z0-9_-]{1,128}$/;
export function assertGmailId(kind: "thread" | "message", id: string, account: string): void {
  if (!GMAIL_ID.test(id)) throw new GmailApiError("gmail_bad_id", 0, account, `"${id.slice(0, 40)}" is not a valid Gmail ${kind} id for ${account}.`);
}

export interface GmailHeader {
  readonly name: string;
  readonly value: string;
}

export interface GmailPartBody {
  readonly size?: number;
  readonly data?: string;
  readonly attachmentId?: string;
}

export interface GmailPart {
  readonly partId?: string;
  readonly mimeType?: string;
  readonly filename?: string;
  readonly headers?: readonly GmailHeader[];
  readonly body?: GmailPartBody;
  readonly parts?: readonly GmailPart[];
}

export interface GmailMessage {
  readonly id: string;
  readonly threadId: string;
  readonly labelIds?: readonly string[];
  readonly snippet?: string;
  readonly historyId?: string;
  readonly internalDate?: string;
  readonly sizeEstimate?: number;
  readonly payload?: GmailPart;
}

export interface GmailThread {
  readonly id: string;
  readonly historyId?: string;
  readonly messages?: readonly GmailMessage[];
}

export interface GmailThreadListPage {
  readonly threads: readonly { readonly id: string; readonly snippet?: string; readonly historyId?: string }[];
  readonly nextPageToken?: string;
  readonly resultSizeEstimate?: number;
}

export interface GmailLabel {
  readonly id: string;
  readonly name: string;
  readonly type?: string;
}

export interface ListThreadsParams {
  readonly q: string;
  readonly maxResults: number;
  readonly pageToken?: string;
  readonly labelIds?: readonly string[];
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function statusToCode(status: number): GmailErrorCode {
  if (status === 401) return "gmail_unauthorized";
  if (status === 403) return "gmail_forbidden";
  if (status === 404) return "gmail_not_found";
  if (status === 429) return "gmail_rate_limited";
  if (status === 400 || status === 412) return "gmail_bad_request";
  if (status >= 500) return "gmail_unavailable";
  return "gmail_error";
}

/** Google's `error.status` is a fixed enum (NOT_FOUND, PERMISSION_DENIED, …): safe to repeat, unlike `error.message`. */
async function googleStatusEnum(res: Response): Promise<string | undefined> {
  try {
    const body: unknown = await res.json();
    if (!isRecord(body) || !isRecord(body["error"])) return undefined;
    const s = body["error"]["status"];
    return typeof s === "string" && /^[A-Z_]{1,40}$/.test(s) ? s : undefined;
  } catch {
    return undefined;
  }
}

function describe(code: GmailErrorCode, status: number, account: string, what: string, reason: string | undefined): string {
  const tail = reason !== undefined ? `, ${reason}` : "";
  switch (code) {
    case "gmail_unauthorized":
      return `Gmail rejected the delegated credentials for ${account} while ${what} (HTTP 401${tail}). The service account may not be authorised for domain-wide delegation with the Gmail scope in this tenant. No mail was read.`;
    case "gmail_forbidden":
      return `Gmail refused access to ${account} while ${what} (HTTP 403${tail}). Check the domain-wide delegation authorisation and that the mailbox belongs to this tenant. No mail was read.`;
    case "gmail_not_found":
      return `Gmail has no such item for ${account} while ${what} (HTTP 404${tail}). The id may be wrong or the item may have been deleted.`;
    case "gmail_rate_limited":
      return `Gmail rate limit reached for ${account} while ${what} (HTTP 429${tail}). Nothing was returned; retry later rather than assuming the mailbox is empty.`;
    case "gmail_bad_request":
      return `Gmail rejected the request for ${account} while ${what} (HTTP ${status}${tail}). Check the query syntax or ids.`;
    case "gmail_unavailable":
      return `Gmail returned a server error for ${account} while ${what} (HTTP ${status}${tail}). Nothing was returned; retry later.`;
    default:
      return `Gmail returned HTTP ${status}${tail} for ${account} while ${what}. Nothing was returned.`;
  }
}

export interface GmailClientDeps {
  /** Must be the egress-checked fetch. */
  readonly fetch: FetchLike;
  readonly tokens: DelegationTokenSource;
}

export class GmailClient {
  constructor(private readonly deps: GmailClientDeps) {}

  /** GET `users/<address>/<path>` as the mailbox. One retry after a 401 with a freshly minted token. */
  private async get(target: ResolvedMailbox, path: string, params: Readonly<Record<string, string | readonly string[] | undefined>>, what: string): Promise<unknown> {
    const account = target.mailbox.address;
    const url = new URL(`${GMAIL_API_BASE}${encodeURIComponent(account)}/${path}`);
    for (const [k, v] of Object.entries(params)) {
      if (v === undefined) continue;
      if (typeof v === "string") url.searchParams.set(k, v);
      else for (const item of v) url.searchParams.append(k, item);
    }
    let res = await this.send(target, url);
    if (res.status === 401) {
      this.deps.tokens.invalidate(target);
      res = await this.send(target, url);
    }
    if (!res.ok) {
      const code = statusToCode(res.status);
      throw new GmailApiError(code, res.status, account, describe(code, res.status, account, what, await googleStatusEnum(res)));
    }
    try {
      return await res.json();
    } catch {
      throw new GmailApiError("gmail_malformed_response", res.status, account, `Gmail's response for ${account} while ${what} was not JSON. Nothing was returned.`);
    }
  }

  private async send(target: ResolvedMailbox, url: URL): Promise<Response> {
    const token = await this.deps.tokens.tokenFor(target);
    return this.deps.fetch(url.toString(), { method: "GET", headers: { authorization: `Bearer ${token}`, accept: "application/json" } });
  }

  async listThreads(target: ResolvedMailbox, p: ListThreadsParams): Promise<GmailThreadListPage> {
    const raw = await this.get(target, "threads", { q: p.q, maxResults: String(p.maxResults), pageToken: p.pageToken, labelIds: p.labelIds }, "searching threads");
    if (!isRecord(raw)) throw this.malformed(target, "searching threads");
    // Gmail omits `threads` entirely when the query matches nothing; that is a real empty result, not a failure.
    const threads = raw["threads"] === undefined ? [] : raw["threads"];
    if (!Array.isArray(threads)) throw this.malformed(target, "searching threads");
    const out: { id: string; snippet?: string; historyId?: string }[] = [];
    for (const t of threads) {
      if (!isRecord(t) || typeof t["id"] !== "string") throw this.malformed(target, "searching threads");
      out.push({ id: t["id"], ...(typeof t["snippet"] === "string" ? { snippet: t["snippet"] } : {}), ...(typeof t["historyId"] === "string" ? { historyId: t["historyId"] } : {}) });
    }
    const next = raw["nextPageToken"];
    const estimate = raw["resultSizeEstimate"];
    return { threads: out, ...(typeof next === "string" && next.length > 0 ? { nextPageToken: next } : {}), ...(typeof estimate === "number" ? { resultSizeEstimate: estimate } : {}) };
  }

  async getThread(target: ResolvedMailbox, id: string, format: "full" | "metadata", metadataHeaders?: readonly string[]): Promise<GmailThread> {
    assertGmailId("thread", id, target.mailbox.address);
    const raw = await this.get(target, `threads/${encodeURIComponent(id)}`, { format, metadataHeaders }, `reading thread ${id}`);
    if (!isRecord(raw) || typeof raw["id"] !== "string") throw this.malformed(target, `reading thread ${id}`);
    const messages = raw["messages"];
    if (messages !== undefined && !Array.isArray(messages)) throw this.malformed(target, `reading thread ${id}`);
    return raw as unknown as GmailThread;
  }

  async getMessage(target: ResolvedMailbox, id: string): Promise<GmailMessage> {
    assertGmailId("message", id, target.mailbox.address);
    const raw = await this.get(target, `messages/${encodeURIComponent(id)}`, { format: "full" }, `reading message ${id}`);
    if (!isRecord(raw) || typeof raw["id"] !== "string" || typeof raw["threadId"] !== "string") throw this.malformed(target, `reading message ${id}`);
    return raw as unknown as GmailMessage;
  }

  async listLabels(target: ResolvedMailbox): Promise<readonly GmailLabel[]> {
    const raw = await this.get(target, "labels", {}, "listing labels");
    if (!isRecord(raw) || !Array.isArray(raw["labels"])) throw this.malformed(target, "listing labels");
    const out: GmailLabel[] = [];
    for (const l of raw["labels"]) {
      if (!isRecord(l) || typeof l["id"] !== "string" || typeof l["name"] !== "string") throw this.malformed(target, "listing labels");
      out.push({ id: l["id"], name: l["name"], ...(typeof l["type"] === "string" ? { type: l["type"] } : {}) });
    }
    return out;
  }

  private malformed(target: ResolvedMailbox, what: string): GmailApiError {
    return new GmailApiError("gmail_malformed_response", 200, target.mailbox.address, `Gmail's response for ${target.mailbox.address} while ${what} had an unexpected shape. Nothing was returned.`);
  }
}
