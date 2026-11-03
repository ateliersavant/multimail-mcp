/**
 * RFC 5322 address lists, read the way a mail client reads them: quoted strings, backslash escapes, comments and
 * angle-addrs are honoured, so a display name can never pass for an address. Used for display (the real address is
 * always shown, however long the name) and for every security decision about a From header (exactly one mailbox).
 */

export interface ParsedMailbox {
  /** Display name with quotes, escapes and comments removed; undefined when there is none. */
  readonly name?: string;
  /** The addr-spec exactly as written (callers lowercase for comparison). */
  readonly address: string;
}

export interface ParsedAddressList {
  readonly mailboxes: readonly ParsedMailbox[];
  /** Segments that are not a single readable mailbox (two angle-addrs, no address, junk). */
  readonly unparsed: readonly string[];
}

const ADDR_SPEC = /^[^\s<>()",;:@\\[\]]+@[^\s<>()",;:@\\[\]]+$/;

/** Unicode format characters (zero-width, bidi controls, soft hyphen…) and blank fillers: invisible, never meaningful. */
const INVISIBLE = /[\p{Cf}\u115F\u1160\u3164\uFFA0\u2800]/gu;

export function stripInvisible(s: string): string {
  return s.replace(INVISIBLE, "");
}

/** Splits at top-level commas and group delimiters, outside quotes, comments and angle brackets. Linear time. */
function splitTopLevel(value: string): string[] {
  const out: string[] = [];
  let cur = "";
  let inQuote = false;
  let escape = false;
  let comment = 0;
  let angle = false;
  for (const ch of value) {
    if (escape) {
      cur += ch;
      escape = false;
      continue;
    }
    if ((inQuote || comment > 0) && ch === "\\") {
      cur += ch;
      escape = true;
      continue;
    }
    if (inQuote) {
      if (ch === '"') inQuote = false;
      cur += ch;
      continue;
    }
    if (comment > 0) {
      if (ch === "(") comment++;
      else if (ch === ")") comment--;
      cur += ch;
      continue;
    }
    if (angle) {
      if (ch === ">") angle = false;
      cur += ch;
      continue;
    }
    if (ch === '"') inQuote = true;
    else if (ch === "(") comment = 1;
    else if (ch === "<") angle = true;
    else if (ch === "," || ch === ";") {
      out.push(cur);
      cur = "";
      continue;
    } else if (ch === ":") {
      cur = ""; // a group's display name ("Team: a@x, b@y;") is not an address
      continue;
    }
    cur += ch;
  }
  out.push(cur);
  return out;
}

/** One segment: either `name <addr>` with exactly one top-level angle-addr, or a bare addr-spec. */
function parseSegment(segment: string): ParsedMailbox | undefined {
  let name = "";
  const angles: string[] = [];
  let inQuote = false;
  let escape = false;
  let comment = 0;
  let angle: string | undefined;
  for (const ch of segment) {
    if (angle !== undefined) {
      if (ch === ">") {
        angles.push(angle);
        angle = undefined;
      } else angle += ch;
      continue;
    }
    if (escape) {
      if (comment === 0) name += ch;
      escape = false;
      continue;
    }
    if ((inQuote || comment > 0) && ch === "\\") {
      escape = true;
      continue;
    }
    if (inQuote) {
      if (ch === '"') inQuote = false;
      else name += ch;
      continue;
    }
    if (comment > 0) {
      if (ch === "(") comment++;
      else if (ch === ")") comment--;
      continue;
    }
    if (ch === '"') inQuote = true;
    else if (ch === "(") comment = 1;
    else if (ch === "<") angle = "";
    else name += ch;
  }
  if (inQuote || comment > 0 || angle !== undefined) return undefined; // unbalanced
  if (angles.length > 1) return undefined;
  if (angles.length === 1) {
    const address = (angles[0] ?? "").trim().replace(/^@[^:]*:/, ""); // drop an obsolete source route
    if (!ADDR_SPEC.test(address)) return undefined;
    const n = stripInvisible(name).replace(/\s+/g, " ").trim();
    return n === "" ? { address } : { name: n, address };
  }
  const bare = name.trim();
  return ADDR_SPEC.test(bare) ? { address: bare } : undefined;
}

export function parseAddressList(value: string): ParsedAddressList {
  const mailboxes: ParsedMailbox[] = [];
  const unparsed: string[] = [];
  for (const raw of splitTopLevel(value)) {
    if (raw.trim() === "") continue;
    const m = parseSegment(raw);
    if (m === undefined) unparsed.push(raw.trim());
    else mailboxes.push(m);
  }
  return { mailboxes, unparsed };
}

/** The single sender of a From value, lowercased; undefined unless the value is exactly one readable mailbox. */
export function singleMailbox(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const p = parseAddressList(value);
  if (p.mailboxes.length !== 1 || p.unparsed.length > 0) return undefined;
  return p.mailboxes[0]?.address.toLowerCase();
}

const MAX_NAME_CHARS = 80;
const MAX_LISTED = 50;

/**
 * For display: every mailbox as `Name <address>` with long names cut (never the address), at most 50 listed and the
 * rest counted. Unreadable segments are shown cut and marked, so nothing is hidden and nothing is invented.
 */
export function displayAddressList(value: string): string {
  const p = parseAddressList(stripInvisible(value));
  const shown = p.mailboxes.slice(0, MAX_LISTED).map((m) => {
    if (m.name === undefined) return m.address;
    const name = m.name.length > MAX_NAME_CHARS ? `${m.name.slice(0, MAX_NAME_CHARS)}…` : m.name;
    // Quoted only when the name holds characters that could read as an address or a list; plain names stay plain.
    return /["\\,;:<>@()[\]]/.test(name) ? `"${name.replace(/(["\\])/g, "\\$1")}" <${m.address}>` : `${name} <${m.address}>`;
  });
  const extra = p.mailboxes.length - shown.length;
  if (extra > 0) shown.push(`(+${extra} more)`);
  for (const u of p.unparsed.slice(0, 5)) shown.push(`[unreadable: ${u.replace(/\s+/g, " ").slice(0, 120)}${u.length > 120 ? "…" : ""}]`);
  return shown.join(", ");
}
