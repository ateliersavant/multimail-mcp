/**
 * Builds the RFC 5322 message that becomes a Gmail draft. Every header value is checked for line breaks before it
 * is written (header injection would let a subject or a name smuggle in a Bcc), addresses are validated, non-ASCII
 * text is encoded (RFC 2047 for headers, base64 for bodies), and every size is bounded. Threading headers copied
 * from an existing message are untrusted and are kept only if they are well-formed message-id lists.
 */
import { b64urlEncode, utf8 } from "../auth/encoding.js";
import { parseAddressList, singleMailbox } from "./address.js";

export const MAX_RECIPIENTS = 50;
export const MAX_SUBJECT_CHARS = 500;
export const MAX_BODY_TEXT_CHARS = 100_000;
const MAX_DISPLAY_NAME_CHARS = 100;
const MAX_REFERENCES = 50;

export type MimeErrorCode = "invalid_address" | "header_injection" | "no_recipients" | "too_many_recipients" | "subject_too_long" | "body_too_large";

export class MimeError extends Error {
  constructor(
    readonly code: MimeErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "MimeError";
  }
}

/** Conservative: dot-atom local part, a hostname with at least one dot. No quoted local parts, no IP literals. */
const ADDRESS = /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$/;

export function assertAddress(field: string, address: string): void {
  if (address.length > 254 || !ADDRESS.test(address)) throw new MimeError("invalid_address", `${field}: "${address.slice(0, 80)}" is not a valid email address.`);
}

export function assertHeaderSafe(field: string, value: string): void {
  if (/[\r\n\0]/.test(value)) throw new MimeError("header_injection", `${field} contains a line break or NUL character, which could inject extra email headers. Remove it.`);
}

const PRINTABLE_ASCII = /^[\x20-\x7e]*$/;

/** RFC 2047 "B" encoded-words, each holding at most 45 bytes of UTF-8 (so each word stays under 75 characters). */
export function encodeWords(text: string): string {
  if (PRINTABLE_ASCII.test(text)) return text;
  const words: string[] = [];
  let chunk = "";
  let chunkBytes = 0;
  for (const ch of text) {
    const n = utf8(ch).length;
    if (chunkBytes + n > 45 && chunk !== "") {
      words.push(chunk);
      chunk = "";
      chunkBytes = 0;
    }
    chunk += ch;
    chunkBytes += n;
  }
  if (chunk !== "") words.push(chunk);
  return words.map((w) => `=?UTF-8?B?${btoa(String.fromCharCode(...utf8(w)))}?=`).join("\r\n ");
}

/** `Name <address>`, quoting or encoding the name as needed; the bare address when there is no usable name. */
export function formatMailbox(address: string, displayName?: string): string {
  const name = (displayName ?? "").trim();
  if (name === "" || /[\r\n\0]/.test(name) || name.length > MAX_DISPLAY_NAME_CHARS) return address;
  if (!PRINTABLE_ASCII.test(name)) return `${encodeWords(name)} <${address}>`;
  return `"${name.replace(/(["\\])/g, "\\$1")}" <${address}>`;
}

function base64Lines(text: string): string {
  const bytes = utf8(text);
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return (btoa(bin).match(/.{1,76}/g) ?? [""]).join("\r\n");
}

const MSG_ID = /^<[^<>\s]{1,250}>$/;

/** Keeps a References/In-Reply-To value only if it is a clean list of `<id>` tokens; anything else is dropped. */
export function sanitiseMessageIds(value: string | undefined, max: number = MAX_REFERENCES): string | undefined {
  if (value === undefined) return undefined;
  const ids = value.trim().split(/\s+/).filter((t) => t !== "");
  if (ids.length === 0 || !ids.every((t) => MSG_ID.test(t))) return undefined;
  return ids.slice(-max).join(" ");
}

/** "Re: <subject>" for a reply, without stacking prefixes; the original subject is untrusted, so it is flattened. */
export function replySubject(original: string | undefined): string {
  const flat = (original ?? "").replace(/[\r\n\0\t]+/g, " ").replace(/\s{2,}/g, " ").trim().slice(0, MAX_SUBJECT_CHARS - 4);
  if (flat === "") return "Re:";
  return /^re:/i.test(flat) ? flat : `Re: ${flat}`;
}

export interface MimeInput {
  readonly from: { readonly address: string; readonly displayName?: string };
  readonly to: readonly string[];
  readonly cc?: readonly string[];
  readonly bcc?: readonly string[];
  readonly subject: string;
  readonly text: string;
  readonly inReplyTo?: string;
  readonly references?: string;
}

/** `Name: a, b, c` folded with CRLF + space so no line exceeds 78 characters (each item is short and unbreakable). */
function foldList(name: string, items: readonly string[], separator: string): string {
  const lines: string[] = [];
  let line = `${name}:`;
  items.forEach((item, idx) => {
    const piece = `${item}${idx < items.length - 1 ? separator : ""}`;
    if (line.length + 1 + piece.length > 78 && line !== `${name}:`) {
      lines.push(line);
      line = ` ${piece}`;
    } else line += ` ${piece}`;
  });
  lines.push(line);
  return lines.join("\r\n");
}

export function recipientCount(i: Pick<MimeInput, "to" | "cc" | "bcc">): number {
  return i.to.length + (i.cc?.length ?? 0) + (i.bcc?.length ?? 0);
}

/** Validates everything, then returns the message with CRLF line endings. Throws MimeError and builds nothing on any problem. */
export function buildMime(i: MimeInput): string {
  assertAddress("from", i.from.address);
  const lists: [string, readonly string[]][] = [["to", i.to], ["cc", i.cc ?? []], ["bcc", i.bcc ?? []]];
  for (const [field, list] of lists) for (const a of list) assertAddress(field, a);
  const total = recipientCount(i);
  if (i.to.length === 0) throw new MimeError("no_recipients", "A draft needs at least one To recipient.");
  if (total > MAX_RECIPIENTS) throw new MimeError("too_many_recipients", `At most ${MAX_RECIPIENTS} recipients in To, Cc and Bcc together (got ${total}).`);
  assertHeaderSafe("subject", i.subject);
  if (i.subject.length > MAX_SUBJECT_CHARS) throw new MimeError("subject_too_long", `The subject is longer than ${MAX_SUBJECT_CHARS} characters.`);
  if (i.text.length > MAX_BODY_TEXT_CHARS) throw new MimeError("body_too_large", `body_text is longer than ${MAX_BODY_TEXT_CHARS} characters.`);
  if (i.inReplyTo !== undefined) assertHeaderSafe("in-reply-to", i.inReplyTo);
  if (i.references !== undefined) assertHeaderSafe("references", i.references);

  const headers: string[] = [`From: ${formatMailbox(i.from.address, i.from.displayName)}`, foldList("To", i.to, ",")];
  if ((i.cc ?? []).length > 0) headers.push(foldList("Cc", i.cc ?? [], ","));
  if ((i.bcc ?? []).length > 0) headers.push(foldList("Bcc", i.bcc ?? [], ","));
  headers.push(`Subject: ${encodeWords(i.subject)}`);
  const inReplyTo = sanitiseMessageIds(i.inReplyTo, 1);
  const references = sanitiseMessageIds(i.references);
  if (inReplyTo !== undefined) headers.push(`In-Reply-To: ${inReplyTo}`);
  if (references !== undefined) headers.push(foldList("References", references.split(" "), ""));
  headers.push("MIME-Version: 1.0");

  // One plain-text part and nothing else: what the user approves is exactly what every recipient's client shows.
  const textPart = ["Content-Type: text/plain; charset=UTF-8", "Content-Transfer-Encoding: base64", "", base64Lines(i.text)];
  return [...headers, ...textPart, ""].join("\r\n");
}

/** Gmail's `raw` field: the whole message, base64url without padding. */
export function toGmailRaw(mime: string): string {
  return b64urlEncode(utf8(mime));
}

/** The single sender of a From value (`Name <a@b>` or `a@b`), lowercased; undefined unless it is exactly one mailbox. */
export function extractAddress(headerValue: string | undefined): string | undefined {
  return singleMailbox(headerValue);
}

/** Distinct addresses across header values, read as RFC 5322 address lists (quoted names never count as addresses). */
export function addressesIn(...headerValues: readonly (string | undefined)[]): string[] {
  const out = new Set<string>();
  for (const v of headerValues) for (const m of parseAddressList(v ?? "").mailboxes) out.add(m.address.toLowerCase());
  return [...out];
}
