import { describe, expect, it } from "vitest";
import { MimeError, addressesIn, buildMime, encodeWords, extractAddress, formatMailbox, replySubject, sanitiseMessageIds, toGmailRaw } from "../../src/gmail/mime.js";
import { parseRaw } from "../helpers/fake-gmail.js";

const base = { from: { address: "ada@example-studio.test", displayName: "Ada Lovelace" }, to: ["bill@vendor.test"], subject: "Invoice 1042", text: "Hello Bill,\n\nPaid.\n\nAda" };

function codeOf(fn: () => unknown): string | undefined {
  try {
    fn();
  } catch (e) {
    return e instanceof MimeError ? e.code : `not MimeError: ${String(e)}`;
  }
  return undefined;
}

describe("buildMime", () => {
  it("builds a plain-text message whose headers and body round-trip exactly, with CRLF line endings", () => {
    const mime = buildMime({ ...base, cc: ["c@vendor.test"], bcc: ["b@vendor.test"] });
    expect(mime).toContain("\r\n");
    expect(mime.replace(/\r\n/g, "")).not.toContain("\n");
    const p = parseRaw(toGmailRaw(mime));
    const h = Object.fromEntries(p.headers.map((x) => [x.name, x.value]));
    expect(h["From"]).toBe('"Ada Lovelace" <ada@example-studio.test>');
    expect(h["To"]).toBe("bill@vendor.test");
    expect(h["Cc"]).toBe("c@vendor.test");
    expect(h["Bcc"]).toBe("b@vendor.test");
    expect(h["Subject"]).toBe("Invoice 1042");
    expect(h["MIME-Version"]).toBe("1.0");
    expect(h["Content-Type"]).toBe("text/plain; charset=UTF-8");
    expect(p.text).toBe(base.text);
  });

  it("encodes non-ASCII subjects and names (RFC 2047) and bodies (base64, lines of at most 76)", () => {
    const subject = "Réunion jeudi — ordre du jour, café ☕ et 日本語のテキスト ".repeat(3).trim();
    const mime = buildMime({ ...base, from: { address: "ada@example-studio.test", displayName: "Adèle Ô" }, subject, text: "Ça va ? Très bien. ✓\n".repeat(200) });
    for (const line of mime.split("\r\n")) expect(line.length).toBeLessThanOrEqual(998);
    const bodyLines = mime.split("\r\n\r\n")[1]?.split("\r\n").filter((l) => l !== "") ?? [];
    for (const l of bodyLines) expect(l.length).toBeLessThanOrEqual(76);
    const p = parseRaw(toGmailRaw(mime));
    const h = Object.fromEntries(p.headers.map((x) => [x.name, x.value]));
    expect(h["Subject"]).toBe(subject);
    expect(h["From"]).toBe("Adèle Ô <ada@example-studio.test>");
    expect(p.text).toBe("Ça va ? Très bien. ✓\n".repeat(200));
    expect(encodeWords("plain ascii")).toBe("plain ascii");
  });

  it("adds an HTML alternative when given, keeping the plain text first", () => {
    const mime = buildMime({ ...base, html: "<p>Paid.</p>", boundary: "B1" });
    expect(mime).toContain('Content-Type: multipart/alternative; boundary="B1"');
    expect(mime.indexOf("text/plain")).toBeLessThan(mime.indexOf("text/html"));
    const p = parseRaw(toGmailRaw(mime));
    expect(p.text).toBe(base.text);
    expect(p.html).toBe("<p>Paid.</p>");
  });

  it("refuses header injection in the subject and threading headers, and builds nothing", () => {
    expect(codeOf(() => buildMime({ ...base, subject: "Hi\r\nBcc: evil@attacker.test" }))).toBe("header_injection");
    expect(codeOf(() => buildMime({ ...base, subject: "Hi\nBcc: evil@attacker.test" }))).toBe("header_injection");
    expect(codeOf(() => buildMime({ ...base, subject: "nul\0byte" }))).toBe("header_injection");
    expect(codeOf(() => buildMime({ ...base, inReplyTo: "<a@b>\r\nBcc: x@y.test" }))).toBe("header_injection");
  });

  it("refuses invalid addresses, names smuggling headers, empty To and too many recipients", () => {
    for (const bad of ["bill", "bill@", "@vendor.test", "bill@vendor", "bill vendor@x.test", "bill@vendor.test\r\nBcc: x@y.test", "<bill@vendor.test>", "Bill <bill@vendor.test>"]) {
      expect(codeOf(() => buildMime({ ...base, to: [bad] })), bad).toBe("invalid_address");
    }
    expect(codeOf(() => buildMime({ ...base, cc: ["nope"] }))).toBe("invalid_address");
    expect(codeOf(() => buildMime({ ...base, to: [] }))).toBe("no_recipients");
    expect(codeOf(() => buildMime({ ...base, to: Array.from({ length: 51 }, (_, i) => `r${i}@vendor.test`) }))).toBe("too_many_recipients");
    expect(codeOf(() => buildMime({ ...base, to: ["a@vendor.test"], cc: Array.from({ length: 30 }, (_, i) => `c${i}@vendor.test`), bcc: Array.from({ length: 20 }, (_, i) => `b${i}@vendor.test`) }))).toBe("too_many_recipients");
    // A display name with a line break is dropped, never written.
    expect(formatMailbox("ada@example-studio.test", "Ada\r\nBcc: evil@attacker.test")).toBe("ada@example-studio.test");
    expect(formatMailbox("ada@example-studio.test", 'Ada "The" \\Count')).toBe('"Ada \\"The\\" \\\\Count" <ada@example-studio.test>');
  });

  it("bounds subject and bodies", () => {
    expect(codeOf(() => buildMime({ ...base, subject: "s".repeat(501) }))).toBe("subject_too_long");
    expect(codeOf(() => buildMime({ ...base, text: "x".repeat(100_001) }))).toBe("body_too_large");
    expect(codeOf(() => buildMime({ ...base, html: "x".repeat(200_001) }))).toBe("body_too_large");
  });

  it("writes reply headers only when they are clean message-id lists", () => {
    const mime = buildMime({ ...base, inReplyTo: "<m-1@fake.test>", references: "<r-0@fake.test> <m-1@fake.test>" });
    expect(mime).toContain("In-Reply-To: <m-1@fake.test>");
    expect(mime).toContain("References: <r-0@fake.test> <m-1@fake.test>");
    const dirty = buildMime({ ...base, inReplyTo: "<m-1@fake.test> extra", references: "not an id; DROP" });
    expect(dirty).not.toContain("In-Reply-To");
    expect(dirty).not.toContain("References");
  });
});

describe("helpers", () => {
  it("sanitiseMessageIds keeps the last N clean ids and rejects anything else", () => {
    expect(sanitiseMessageIds("<a@x>  <b@x>\t<c@x>")).toBe("<a@x> <b@x> <c@x>");
    expect(sanitiseMessageIds("<a@x> <b@x> <c@x>", 1)).toBe("<c@x>");
    for (const bad of [undefined, "", "a@x", "<a@x> b", "<a b@x>", "<<a@x>>"]) expect(sanitiseMessageIds(bad), String(bad)).toBeUndefined();
  });

  it("replySubject prefixes once and flattens untrusted subjects", () => {
    expect(replySubject("Invoice 1042")).toBe("Re: Invoice 1042");
    expect(replySubject("RE: Invoice")).toBe("RE: Invoice");
    expect(replySubject("Line\r\nBcc: evil@attacker.test")).toBe("Re: Line Bcc: evil@attacker.test");
    expect(replySubject(undefined)).toBe("Re:");
  });

  it("extractAddress and addressesIn read header values", () => {
    expect(extractAddress('"Ada" <Ada@Example-Studio.test>')).toBe("ada@example-studio.test");
    expect(extractAddress("ada@example-studio.test")).toBe("ada@example-studio.test");
    expect(extractAddress("Ada Lovelace")).toBeUndefined();
    expect(extractAddress(undefined)).toBeUndefined();
    expect(addressesIn("a@x.test, Bob <b@x.test>", undefined, "a@x.test; c@x.test")).toEqual(["a@x.test", "b@x.test", "c@x.test"]);
  });
});
