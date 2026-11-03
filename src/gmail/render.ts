/**
 * Turns Gmail's MIME tree into what a model may see (handoff §4, threat T4): headers, a plain-text body with HTML
 * stripped, and attachments by metadata only. Bodies are bounded; a cut is always flagged, never silent.
 * Nothing here logs. Everything it returns is untrusted data and is labelled as such by the tool descriptions.
 */
import { b64urlDecode } from "../auth/encoding.js";
import { displayAddressList, stripInvisible } from "./address.js";
import type { GmailHeader, GmailMessage, GmailPart } from "./client.js";

/** Per-message body bound (characters after stripping). */
export const MAX_BODY_CHARS = 20_000;
/** Per-thread body budget across all messages. Messages past it come back with headers and an `omitted` body. */
export const MAX_THREAD_BODY_CHARS = 80_000;
/** Messages rendered per thread; longer threads are flagged. */
export const MAX_THREAD_MESSAGES = 100;
/** Header values are cut here, with a visible marker; address headers are rendered mailbox by mailbox instead. */
export const MAX_HEADER_CHARS = 2000;
/** HTML longer than this is cut before stripping (the stripper is linear, this bounds memory and CPU). */
export const MAX_HTML_INPUT_CHARS = 1_000_000;
/** Body data longer than this (base64url characters, about 3 MB) is cut before decoding. */
export const MAX_BODY_DATA_CHARS = 4_000_000;

export interface RenderedAttachment {
  readonly filename: string;
  readonly mimeType: string;
  readonly sizeBytes: number;
  readonly inline: boolean;
}

export interface RenderedBody {
  readonly text: string;
  /** Which part the text came from. `omitted` = the thread budget was spent before this message. */
  readonly source: "text/plain" | "text/html" | "none" | "omitted";
  readonly truncated: boolean;
  readonly originalChars: number;
}

export interface RenderedHeaders {
  readonly from?: string;
  readonly to?: string;
  readonly cc?: string;
  readonly bcc?: string;
  readonly replyTo?: string;
  readonly subject?: string;
  readonly date?: string;
  readonly rfc822MessageId?: string;
  readonly inReplyTo?: string;
  readonly references?: string;
}

export interface RenderedMessage {
  readonly messageId: string;
  readonly threadId: string;
  readonly labelIds: readonly string[];
  readonly internalDate?: string;
  readonly sizeEstimate?: number;
  readonly headers: RenderedHeaders;
  readonly snippet: string;
  readonly body: RenderedBody;
  readonly attachments: readonly RenderedAttachment[];
}

const NAMED_ENTITIES: Readonly<Record<string, string>> = {
  amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", ensp: " ", emsp: " ", thinsp: " ", zwnj: "‌", zwj: "‍",
  mdash: "—", ndash: "–", hellip: "…", lsquo: "‘", rsquo: "’", ldquo: "“", rdquo: "”", laquo: "«", raquo: "»",
  copy: "©", reg: "®", trade: "™", euro: "€", pound: "£", yen: "¥", cent: "¢", middot: "·", bull: "•", deg: "°",
  times: "×", divide: "÷", frac12: "½", frac14: "¼", frac34: "¾", eacute: "é", egrave: "è", agrave: "à", ccedil: "ç", uuml: "ü", ouml: "ö", auml: "ä", szlig: "ß",
};

export function decodeEntities(s: string): string {
  return s.replace(/&(#x[0-9a-f]{1,6}|#[0-9]{1,7}|[a-z][a-z0-9]{1,15});/gi, (whole, body: string) => {
    if (body[0] === "#") {
      const cp = body[1] === "x" || body[1] === "X" ? Number.parseInt(body.slice(2), 16) : Number.parseInt(body.slice(1), 10);
      if (!Number.isFinite(cp) || cp <= 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return whole;
      return String.fromCodePoint(cp);
    }
    return NAMED_ENTITIES[body.toLowerCase()] ?? whole;
  });
}

const DROPPED_BLOCKS: ReadonlySet<string> = new Set(["script", "style", "head", "title", "template", "noscript", "svg", "object", "iframe"]);
const BLOCK_TAGS: ReadonlySet<string> = new Set(["p", "div", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "pre", "table", "ul", "ol", "section", "article", "header", "footer", "hr", "dd", "dt", "address"]);

/**
 * HTML to text in one forward pass (linear time: every search moves strictly forward, so a hostile body cannot make
 * it quadratic). Removes scripts, styles, heads and comments wholesale (an unterminated one swallows the rest), turns
 * block boundaries and <br> into newlines, drops every other tag, decodes entities, then normalises whitespace. Not an
 * HTML parser: the aim is that no markup survives, not that layout is preserved.
 */
export function stripHtml(html: string): string {
  const input = html.length > MAX_HTML_INPUT_CHARS ? html.slice(0, MAX_HTML_INPUT_CHARS) : html;
  const lower = input.toLowerCase();
  const parts: string[] = [];
  let i = 0;
  while (i < input.length) {
    const lt = input.indexOf("<", i);
    if (lt < 0) {
      parts.push(input.slice(i));
      break;
    }
    parts.push(input.slice(i, lt));
    if (lower.startsWith("<!--", lt)) {
      const end = input.indexOf("-->", lt + 4);
      if (end < 0) break;
      parts.push(" ");
      i = end + 3;
      continue;
    }
    const gt = input.indexOf(">", lt + 1);
    if (gt < 0) {
      parts.push(" "); // an unterminated tag at the very end
      break;
    }
    const closing = lower.charCodeAt(lt + 1) === 47; // "/"
    const name = /^[a-z][a-z0-9]*/.exec(lower.slice(closing ? lt + 2 : lt + 1, Math.min(gt, lt + 40)))?.[0] ?? "";
    if (!closing && DROPPED_BLOCKS.has(name)) {
      const close = lower.indexOf(`</${name}`, gt + 1);
      if (close < 0) break;
      const closeGt = input.indexOf(">", close);
      parts.push(" ");
      i = closeGt < 0 ? input.length : closeGt + 1;
      continue;
    }
    if (name === "br") parts.push("\n");
    else if (name === "li" && !closing) parts.push("\n- ");
    else if (BLOCK_TAGS.has(name)) parts.push("\n");
    else parts.push(" ");
    i = gt + 1;
  }
  return normaliseWhitespace(decodeEntities(parts.join("")));
}

export function normaliseWhitespace(s: string): string {
  return s
    .replace(/\r\n?/g, "\n")
    .replace(/[ \t\f\v ]+/g, " ")
    .replace(/ *\n */g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function headerMap(headers: readonly GmailHeader[] | undefined): ReadonlyMap<string, string> {
  const m = new Map<string, string>();
  for (const h of headers ?? []) {
    if (typeof h.name !== "string" || typeof h.value !== "string") continue;
    const k = h.name.toLowerCase();
    if (!m.has(k)) m.set(k, h.value);
  }
  return m;
}

/** Every value of one header, in order (a message can carry a header twice; showing only the first would hide one). */
function headerValues(headers: readonly GmailHeader[] | undefined, name: string): string[] {
  const out: string[] = [];
  for (const h of headers ?? []) if (typeof h.name === "string" && typeof h.value === "string" && h.name.toLowerCase() === name) out.push(h.value);
  return out;
}

function charsetOf(contentType: string | undefined): string | undefined {
  if (contentType === undefined) return undefined;
  const m = /charset\s*=\s*"?([A-Za-z0-9._:-]{1,40})"?/i.exec(contentType);
  return m?.[1];
}

/** Gmail body data is base64url of the raw bytes; the part's charset decides how to read them. UTF-8 is the fallback. */
export function decodeBodyData(data: string, charset: string | undefined): string {
  const bytes = b64urlDecode(data.replace(/=+$/, ""));
  if (charset !== undefined) {
    try {
      return new TextDecoder(charset).decode(bytes);
    } catch {
      // unknown label in this runtime: fall through to UTF-8
    }
  }
  return new TextDecoder("utf-8").decode(bytes);
}

interface Collected {
  readonly plain: string[];
  readonly html: string[];
  readonly attachments: RenderedAttachment[];
  /** Set when a part's data was cut before decoding. */
  cut: boolean;
}

function collect(part: GmailPart, out: Collected): void {
  const mime = (part.mimeType ?? "application/octet-stream").toLowerCase();
  const headers = headerMap(part.headers);
  const filename = part.filename ?? "";
  const disposition = (headers.get("content-disposition") ?? "").toLowerCase();
  const isAttachment = filename !== "" || part.body?.attachmentId !== undefined || disposition.startsWith("attachment");
  if (isAttachment) {
    out.attachments.push({ filename, mimeType: mime, sizeBytes: part.body?.size ?? 0, inline: disposition.startsWith("inline") });
    return;
  }
  if (mime.startsWith("multipart/")) {
    for (const p of part.parts ?? []) collect(p, out);
    return;
  }
  let data = part.body?.data;
  if (typeof data !== "string" || data.length === 0) return;
  if (data.length > MAX_BODY_DATA_CHARS) {
    data = data.slice(0, MAX_BODY_DATA_CHARS);
    out.cut = true;
  }
  const charset = charsetOf(headers.get("content-type"));
  if (mime === "text/plain") out.plain.push(decodeBodyData(data, charset));
  else if (mime === "text/html") out.html.push(decodeBodyData(data, charset));
  else out.attachments.push({ filename, mimeType: mime, sizeBytes: part.body?.size ?? 0, inline: true });
}

export function renderBody(payload: GmailPart | undefined, maxChars: number): { readonly body: RenderedBody; readonly attachments: readonly RenderedAttachment[] } {
  const out: Collected = { plain: [], html: [], attachments: [], cut: false };
  if (payload !== undefined) collect(payload, out);
  let text: string;
  let source: RenderedBody["source"];
  if (out.plain.length > 0) {
    text = normaliseWhitespace(out.plain.join("\n\n"));
    source = "text/plain";
  } else if (out.html.length > 0) {
    const html = out.html.join("\n");
    text = stripHtml(html);
    source = "text/html";
  } else {
    text = "";
    source = "none";
  }
  const originalChars = text.length;
  const truncated = originalChars > maxChars || out.cut;
  return { body: { text: truncated ? text.slice(0, maxChars) : text, source, truncated, originalChars }, attachments: out.attachments };
}

/**
 * The text of a message's HTML part(s), stripped, or undefined when it has none. A draft's plain-text and HTML bodies
 * can differ, and most recipients read the HTML one: showing only the plain text would let a draft carry words the
 * user never saw.
 */
export function htmlPartText(payload: GmailPart | undefined, maxChars: number): { readonly text: string; readonly truncated: boolean } | undefined {
  const out: Collected = { plain: [], html: [], attachments: [], cut: false };
  if (payload !== undefined) collect(payload, out);
  if (out.html.length === 0) return undefined;
  const text = stripHtml(out.html.join("\n"));
  const truncated = text.length > maxChars || out.cut;
  return { text: truncated ? text.slice(0, maxChars) : text, truncated };
}

function internalDateIso(v: string | undefined): string | undefined {
  if (v === undefined || !/^\d{1,16}$/.test(v)) return undefined;
  const d = new Date(Number(v));
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

const ADDRESS_HEADERS: ReadonlySet<string> = new Set(["from", "to", "cc", "bcc", "reply-to"]);

/**
 * Header values for display. Address headers are parsed and shown mailbox by mailbox, so the real address is always
 * visible however long a display name is (a cut at a fixed length once let a sender end the visible part with someone
 * else's address). Every occurrence of a repeated header is shown. Invisible characters are removed. Other headers are
 * cut with a visible marker.
 */
export function renderHeaders(payload: GmailPart | undefined): RenderedHeaders {
  const headers = payload?.headers;
  const pick = (name: string): string | undefined => {
    const values = headerValues(headers, name);
    if (values.length === 0) return undefined;
    if (ADDRESS_HEADERS.has(name)) return values.map((v) => displayAddressList(v)).join(" | ");
    const v = normaliseWhitespace(stripInvisible(values.join(" | ")));
    return v.length > MAX_HEADER_CHARS ? `${v.slice(0, MAX_HEADER_CHARS)} …[truncated]` : v;
  };
  const out: { -readonly [K in keyof RenderedHeaders]: RenderedHeaders[K] } = {};
  const set = (key: keyof RenderedHeaders, name: string): void => {
    const v = pick(name);
    if (v !== undefined) out[key] = v;
  };
  set("from", "from");
  set("to", "to");
  set("cc", "cc");
  set("bcc", "bcc");
  set("replyTo", "reply-to");
  set("subject", "subject");
  set("date", "date");
  set("rfc822MessageId", "message-id");
  set("inReplyTo", "in-reply-to");
  set("references", "references");
  return out;
}

export function renderMessage(msg: GmailMessage, maxBodyChars: number = MAX_BODY_CHARS): RenderedMessage {
  const { body, attachments } = renderBody(msg.payload, maxBodyChars);
  const iso = internalDateIso(msg.internalDate);
  return {
    messageId: msg.id,
    threadId: msg.threadId,
    labelIds: Array.isArray(msg.labelIds) ? msg.labelIds.filter((l): l is string => typeof l === "string") : [],
    ...(iso !== undefined ? { internalDate: iso } : {}),
    ...(typeof msg.sizeEstimate === "number" ? { sizeEstimate: msg.sizeEstimate } : {}),
    headers: renderHeaders(msg.payload),
    snippet: typeof msg.snippet === "string" ? decodeEntities(msg.snippet) : "",
    body,
    attachments,
  };
}

/** Headers-only rendering for a message whose body fell outside the thread budget. */
export function renderMessageOmitted(msg: GmailMessage): RenderedMessage {
  const full = renderMessage(msg, 0);
  return { ...full, body: { text: "", source: "omitted", truncated: true, originalChars: full.body.originalChars } };
}

export interface RenderedThread {
  readonly threadId: string;
  readonly messageCount: number;
  readonly messages: readonly RenderedMessage[];
  /** True when at least one message lost its body to the per-thread budget or the message cap. */
  readonly bodiesOmitted: boolean;
}

export function renderThread(threadId: string, messages: readonly GmailMessage[], limits: { readonly maxBodyChars?: number; readonly maxThreadBodyChars?: number; readonly maxMessages?: number } = {}): RenderedThread {
  const maxBody = limits.maxBodyChars ?? MAX_BODY_CHARS;
  const budget = limits.maxThreadBodyChars ?? MAX_THREAD_BODY_CHARS;
  const maxMessages = limits.maxMessages ?? MAX_THREAD_MESSAGES;
  const rendered: RenderedMessage[] = [];
  let spent = 0;
  let omitted = false;
  messages.forEach((m, i) => {
    if (i >= maxMessages) {
      omitted = true;
      return;
    }
    if (spent >= budget) {
      rendered.push(renderMessageOmitted(m));
      omitted = true;
      return;
    }
    const allowed = Math.min(maxBody, budget - spent);
    const r = renderMessage(m, allowed);
    spent += r.body.text.length;
    if (r.body.truncated && allowed < maxBody) omitted = true; // cut by the thread budget, not just the per-message bound
    rendered.push(r);
  });
  return { threadId, messageCount: messages.length, messages: rendered, bodiesOmitted: omitted };
}

export interface ThreadSummary {
  readonly threadId: string;
  readonly subject?: string;
  readonly participants: readonly string[];
  readonly messageCount: number;
  readonly lastMessageDate?: string;
  readonly labelIds: readonly string[];
  readonly snippet: string;
}

/** Built from `threads.get?format=metadata`: the first message's subject, every distinct From, the last date, the union of labels. */
export function summariseThread(threadId: string, messages: readonly GmailMessage[], snippet: string | undefined): ThreadSummary {
  const participants: string[] = [];
  const labels = new Set<string>();
  let subject: string | undefined;
  let last: string | undefined;
  for (const m of messages) {
    const h = renderHeaders(m.payload);
    if (subject === undefined && h.subject !== undefined) subject = h.subject;
    if (h.from !== undefined && !participants.includes(h.from) && participants.length < 20) participants.push(h.from);
    for (const l of m.labelIds ?? []) if (typeof l === "string") labels.add(l);
    const iso = internalDateIso(m.internalDate);
    if (iso !== undefined && (last === undefined || iso > last)) last = iso;
  }
  const lastSnippet = messages.length > 0 ? messages[messages.length - 1]?.snippet : undefined;
  return {
    threadId,
    ...(subject !== undefined ? { subject } : {}),
    participants,
    messageCount: messages.length,
    ...(last !== undefined ? { lastMessageDate: last } : {}),
    labelIds: [...labels],
    snippet: decodeEntities(snippet ?? lastSnippet ?? ""),
  };
}
