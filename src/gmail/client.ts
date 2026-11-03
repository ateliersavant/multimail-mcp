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
export function assertGmailId(kind: "thread" | "message" | "draft", id: string, account: string): void {
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

/** One entry of Gmail's "Send mail as" list (users.settings.sendAs). */
export interface GmailSendAs {
  readonly sendAsEmail: string;
  readonly displayName?: string;
  readonly isPrimary: boolean;
  readonly isDefault: boolean;
  readonly treatAsAlias?: boolean;
  /** `accepted`, `pending`, `verificationStatusUnspecified`, or absent (Google: applies only to custom "from" aliases). */
  readonly verificationStatus?: string;
}

/** What drafts.create / drafts.update return. */
export interface GmailDraftRef {
  readonly id: string;
  readonly message: { readonly id: string; readonly threadId: string; readonly labelIds?: readonly string[] };
}

export interface GmailDraft {
  readonly id: string;
  readonly message: GmailMessage;
}

export interface GmailDraftListPage {
  readonly drafts: readonly GmailDraftRef[];
  readonly nextPageToken?: string;
  readonly resultSizeEstimate?: number;
}

/** What drafts.send returns: the sent message's ids. */
export interface GmailSentRef {
  readonly id: string;
  readonly threadId: string;
  readonly labelIds?: readonly string[];
}

type Method = "GET" | "POST" | "PUT" | "DELETE";
/** Reads say "No mail was read"; writes say nothing was changed. The wording matters to a model deciding to retry. */
type Effect = "read" | "write";

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

function describe(code: GmailErrorCode, status: number, account: string, what: string, reason: string | undefined, effect: Effect = "read"): string {
  const tail = reason !== undefined ? `, ${reason}` : "";
  if (effect === "write") return describeWrite(code, status, account, what, tail);
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

function describeWrite(code: GmailErrorCode, status: number, account: string, what: string, tail: string): string {
  switch (code) {
    case "gmail_unauthorized":
      return `Gmail rejected the delegated credentials for ${account} while ${what} (HTTP 401${tail}). Nothing was created, changed or sent.`;
    case "gmail_forbidden":
      return `Gmail refused ${what} for ${account} (HTTP 403${tail}). Nothing was created, changed or sent.`;
    case "gmail_not_found":
      return `Gmail has no such item for ${account} while ${what} (HTTP 404${tail}). Nothing was changed.`;
    case "gmail_rate_limited":
      return `Gmail rate limit reached for ${account} while ${what} (HTTP 429${tail}). Nothing was created, changed or sent; retry later.`;
    case "gmail_bad_request":
      return `Gmail rejected ${what} for ${account} (HTTP ${status}${tail}). Nothing was created, changed or sent. Check the addresses, ids and content.`;
    case "gmail_unavailable":
      return `Gmail returned a server error for ${account} while ${what} (HTTP ${status}${tail}). The change may or may not have been applied: check (for example with list_drafts) before trying again.`;
    default:
      return `Gmail returned HTTP ${status}${tail} for ${account} while ${what}. Check the result before trying again.`;
  }
}

export interface GmailClientDeps {
  /** Must be the egress-checked fetch. */
  readonly fetch: FetchLike;
  readonly tokens: DelegationTokenSource;
}

export class GmailClient {
  constructor(private readonly deps: GmailClientDeps) {}

  /** GET `users/<address>/<path>` as the mailbox. */
  private get(target: ResolvedMailbox, path: string, params: Readonly<Record<string, string | readonly string[] | undefined>>, what: string): Promise<unknown> {
    return this.request(target, "GET", path, params, undefined, what, "read");
  }

  /**
   * One call to `users/<address>/<path>` as the mailbox. One retry after a 401 with a freshly minted token: a 401 means
   * Google rejected the credentials before doing anything, so the retry is safe even for a send. A 204 is `undefined`.
   */
  private async request(target: ResolvedMailbox, method: Method, path: string, params: Readonly<Record<string, string | readonly string[] | undefined>>, body: unknown, what: string, effect: Effect): Promise<unknown> {
    const account = target.mailbox.address;
    const url = new URL(`${GMAIL_API_BASE}${encodeURIComponent(account)}/${path}`);
    for (const [k, v] of Object.entries(params)) {
      if (v === undefined) continue;
      if (typeof v === "string") url.searchParams.set(k, v);
      else for (const item of v) url.searchParams.append(k, item);
    }
    let res = await this.send(target, url, method, body);
    if (res.status === 401) {
      this.deps.tokens.invalidate(target);
      res = await this.send(target, url, method, body);
    }
    if (!res.ok) {
      const code = statusToCode(res.status);
      throw new GmailApiError(code, res.status, account, describe(code, res.status, account, what, await googleStatusEnum(res), effect));
    }
    if (res.status === 204) return undefined;
    try {
      return await res.json();
    } catch {
      throw new GmailApiError("gmail_malformed_response", res.status, account, `Gmail's response for ${account} while ${what} was not JSON. Nothing was returned.`);
    }
  }

  private async send(target: ResolvedMailbox, url: URL, method: Method = "GET", body?: unknown): Promise<Response> {
    const token = await this.deps.tokens.tokenFor(target);
    const headers: Record<string, string> = { authorization: `Bearer ${token}`, accept: "application/json" };
    if (body === undefined) return this.deps.fetch(url.toString(), { method, headers });
    return this.deps.fetch(url.toString(), { method, headers: { ...headers, "content-type": "application/json" }, body: JSON.stringify(body) });
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

  /** One message's headers and labels only (no body): used to confirm a send and to read a reply's threading headers. */
  async getMessageMetadata(target: ResolvedMailbox, id: string, headers: readonly string[]): Promise<GmailMessage> {
    assertGmailId("message", id, target.mailbox.address);
    const raw = await this.get(target, `messages/${encodeURIComponent(id)}`, { format: "metadata", metadataHeaders: headers }, `reading message ${id}`);
    if (!isRecord(raw) || typeof raw["id"] !== "string" || typeof raw["threadId"] !== "string") throw this.malformed(target, `reading message ${id}`);
    return raw as unknown as GmailMessage;
  }

  async listSendAs(target: ResolvedMailbox): Promise<readonly GmailSendAs[]> {
    const what = 'reading the "Send mail as" settings';
    const raw = await this.get(target, "settings/sendAs", {}, what);
    if (!isRecord(raw)) throw this.malformed(target, what);
    const list = raw["sendAs"] === undefined ? [] : raw["sendAs"];
    if (!Array.isArray(list)) throw this.malformed(target, what);
    const out: GmailSendAs[] = [];
    for (const e of list) {
      if (!isRecord(e) || typeof e["sendAsEmail"] !== "string") throw this.malformed(target, what);
      out.push({
        sendAsEmail: e["sendAsEmail"],
        isPrimary: e["isPrimary"] === true,
        isDefault: e["isDefault"] === true,
        ...(typeof e["displayName"] === "string" ? { displayName: e["displayName"] } : {}),
        ...(typeof e["treatAsAlias"] === "boolean" ? { treatAsAlias: e["treatAsAlias"] } : {}),
        ...(typeof e["verificationStatus"] === "string" ? { verificationStatus: e["verificationStatus"] } : {}),
      });
    }
    return out;
  }

  async createDraft(target: ResolvedMailbox, raw: string, threadId?: string): Promise<GmailDraftRef> {
    if (threadId !== undefined) assertGmailId("thread", threadId, target.mailbox.address);
    const out = await this.request(target, "POST", "drafts", {}, { message: { raw, ...(threadId !== undefined ? { threadId } : {}) } }, "creating a draft", "write");
    return this.draftRef(target, out, "creating a draft");
  }

  async updateDraft(target: ResolvedMailbox, draftId: string, raw: string, threadId?: string): Promise<GmailDraftRef> {
    assertGmailId("draft", draftId, target.mailbox.address);
    if (threadId !== undefined) assertGmailId("thread", threadId, target.mailbox.address);
    const what = `updating draft ${draftId}`;
    const out = await this.request(target, "PUT", `drafts/${encodeURIComponent(draftId)}`, {}, { id: draftId, message: { raw, ...(threadId !== undefined ? { threadId } : {}) } }, what, "write");
    return this.draftRef(target, out, what);
  }

  async getDraft(target: ResolvedMailbox, draftId: string, format: "full" | "metadata"): Promise<GmailDraft> {
    assertGmailId("draft", draftId, target.mailbox.address);
    const what = `reading draft ${draftId}`;
    const raw = await this.get(target, `drafts/${encodeURIComponent(draftId)}`, { format }, what);
    if (!isRecord(raw) || typeof raw["id"] !== "string" || !isRecord(raw["message"]) || typeof raw["message"]["id"] !== "string" || typeof raw["message"]["threadId"] !== "string") throw this.malformed(target, what);
    return raw as unknown as GmailDraft;
  }

  async listDrafts(target: ResolvedMailbox, maxResults: number, pageToken?: string): Promise<GmailDraftListPage> {
    const what = "listing drafts";
    const raw = await this.get(target, "drafts", { maxResults: String(maxResults), pageToken }, what);
    if (!isRecord(raw)) throw this.malformed(target, what);
    const list = raw["drafts"] === undefined ? [] : raw["drafts"]; // omitted when there are none
    if (!Array.isArray(list)) throw this.malformed(target, what);
    const drafts = list.map((d) => this.draftRef(target, d, what));
    const next = raw["nextPageToken"];
    const estimate = raw["resultSizeEstimate"];
    return { drafts, ...(typeof next === "string" && next.length > 0 ? { nextPageToken: next } : {}), ...(typeof estimate === "number" ? { resultSizeEstimate: estimate } : {}) };
  }

  async deleteDraft(target: ResolvedMailbox, draftId: string): Promise<void> {
    assertGmailId("draft", draftId, target.mailbox.address);
    await this.request(target, "DELETE", `drafts/${encodeURIComponent(draftId)}`, {}, undefined, `deleting draft ${draftId}`, "write");
  }

  /** drafts.send. The caller owns rule 5 (confirmation, three outcomes); this only reports what Gmail answered. */
  async sendDraft(target: ResolvedMailbox, draftId: string): Promise<GmailSentRef> {
    assertGmailId("draft", draftId, target.mailbox.address);
    const what = `sending draft ${draftId}`;
    const raw = await this.request(target, "POST", "drafts/send", {}, { id: draftId }, what, "write");
    if (!isRecord(raw) || typeof raw["id"] !== "string" || typeof raw["threadId"] !== "string") throw this.malformed(target, what);
    const labelIds = Array.isArray(raw["labelIds"]) ? raw["labelIds"].filter((l): l is string => typeof l === "string") : undefined;
    return { id: raw["id"], threadId: raw["threadId"], ...(labelIds !== undefined ? { labelIds } : {}) };
  }

  private draftRef(target: ResolvedMailbox, raw: unknown, what: string): GmailDraftRef {
    if (!isRecord(raw) || typeof raw["id"] !== "string" || !isRecord(raw["message"]) || typeof raw["message"]["id"] !== "string" || typeof raw["message"]["threadId"] !== "string") throw this.malformed(target, what);
    const m = raw["message"];
    const labelIds = Array.isArray(m["labelIds"]) ? m["labelIds"].filter((l): l is string => typeof l === "string") : undefined;
    return { id: raw["id"], message: { id: m["id"] as string, threadId: m["threadId"] as string, ...(labelIds !== undefined ? { labelIds } : {}) } };
  }

  private malformed(target: ResolvedMailbox, what: string): GmailApiError {
    return new GmailApiError("gmail_malformed_response", 200, target.mailbox.address, `Gmail's response for ${target.mailbox.address} while ${what} had an unexpected shape. Nothing was returned.`);
  }
}
