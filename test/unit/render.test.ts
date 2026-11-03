import { describe, expect, it } from "vitest";
import type { GmailMessage } from "../../src/gmail/client.js";
import { MAX_BODY_CHARS, decodeBodyData, decodeEntities, renderBody, renderMessage, renderThread, stripHtml, summariseThread } from "../../src/gmail/render.js";
import { b64urlEncode, utf8 } from "../../src/auth/encoding.js";
import { STUDIO_ADA, gmailMessage, type FakeMessageSpec } from "../helpers/fake-gmail.js";

const spec = (over: Partial<FakeMessageSpec> = {}): FakeMessageSpec => ({
  id: "m1",
  threadId: "t1",
  from: "Sender <s@vendor.test>",
  to: STUDIO_ADA,
  subject: "Hello",
  date: "Tue, 3 Nov 2026 08:00:00 +0000",
  internalDate: Date.UTC(2026, 10, 3, 8, 0, 0),
  ...over,
});
const msg = (over: Partial<FakeMessageSpec> = {}): GmailMessage => gmailMessage(spec(over)) as unknown as GmailMessage;

describe("stripHtml", () => {
  it("removes scripts, styles, head, comments and every tag; keeps the text, including text hidden by CSS", () => {
    const html = '<html><head><title>T</title><style>p{color:red}</style></head><body><!-- c --><h1>Hi</h1><p>Three <b>new</b> faces &amp; one.</p><script>alert("x")</script><div style="display:none">hidden words</div><a href="https://x.test/">link</a></body></html>';
    const text = stripHtml(html);
    expect(text).toBe("Hi\n\nThree new faces & one.\n\nhidden words\nlink");
    expect(text).not.toMatch(/<[a-z!/]/i);
    expect(text).not.toContain("alert");
    expect(text).not.toContain("color:red");
  });

  it("turns <br>, block ends and list items into line breaks and collapses runs of whitespace", () => {
    expect(stripHtml("a<br>b<br/>c<BR />d")).toBe("a\nb\nc\nd");
    expect(stripHtml("<p>one</p>\n\n\n<p>two</p><ul><li>x</li><li>y</li></ul>")).toBe("one\n\ntwo\n\n- x\n- y");
    expect(stripHtml("<table><tr><td>a</td><td>b</td></tr></table>")).toBe("a b");
    expect(stripHtml("   lots   of \t space   here  ")).toBe("lots of space here");
  });

  it("decodes named, decimal and hex entities and leaves unknown or invalid ones alone", () => {
    expect(decodeEntities("&lt;b&gt; &amp; &quot;q&quot; &#39;s&#39; &nbsp;x &#8212; &#x1F600; &euro;")).toBe("<b> & \"q\" 's'  x — \u{1F600} €");
    expect(decodeEntities("&bogus; &#0; &#xD800; &#99999999;")).toBe("&bogus; &#0; &#xD800; &#99999999;");
  });

  it("survives malformed markup: unterminated tags, nested scripts, odd case", () => {
    expect(stripHtml("text <b>bold</b> <i>open <SCRIPT>bad()</SCRIPT></i> trailing <")).toBe("text bold open trailing");
    expect(stripHtml("<div><div><p>deep</p></div></div>")).toBe("deep");
    expect(stripHtml("")).toBe("");
  });
});

describe("decodeBodyData", () => {
  it("decodes base64url with or without padding, honouring the part charset", () => {
    expect(decodeBodyData(b64urlEncode(utf8("héllo wörld")), "UTF-8")).toBe("héllo wörld");
    expect(decodeBodyData(`${b64urlEncode(utf8("ab"))}==`, undefined)).toBe("ab");
    const latin1 = new Uint8Array([0x63, 0x61, 0x66, 0xe9]); // "café" in ISO-8859-1
    expect(decodeBodyData(b64urlEncode(latin1), "iso-8859-1")).toBe("café");
    expect(decodeBodyData(b64urlEncode(utf8("ok")), "no-such-charset-xyz")).toBe("ok"); // unknown label: UTF-8 fallback
  });
});

describe("renderMessage", () => {
  it("prefers text/plain over text/html in a multipart/alternative and lists attachments by metadata only", () => {
    const m = msg({ text: "plain body", html: "<p>html body</p>", attachments: [{ filename: "contract.pdf", mimeType: "application/pdf", size: 1000 }, { filename: "logo.png", mimeType: "image/png", size: 20, inline: true }] });
    const r = renderMessage(m);
    expect(r.body).toEqual({ text: "plain body", source: "text/plain", truncated: false, originalChars: 10 });
    expect(r.attachments).toEqual([
      { filename: "contract.pdf", mimeType: "application/pdf", sizeBytes: 1000, inline: false },
      { filename: "logo.png", mimeType: "image/png", sizeBytes: 20, inline: true },
    ]);
    expect(JSON.stringify(r)).not.toContain("attachmentId"); // nothing a client could use to fetch content
    expect(r.headers).toMatchObject({ from: "Sender <s@vendor.test>", to: STUDIO_ADA, subject: "Hello", rfc822MessageId: "<m1@fake.test>" });
    expect(r.internalDate).toBe("2026-11-03T08:00:00.000Z");
    expect(r.messageId).toBe("m1");
    expect(r.threadId).toBe("t1");
  });

  it("strips HTML when the message has no plain-text part, and flags the source", () => {
    const m = msg({ html: "<p>Only <b>html</b> here</p><script>evil()</script>" });
    const r = renderMessage(m);
    expect(r.body.source).toBe("text/html");
    expect(r.body.text).toBe("Only html here");
    expect(r.body.text).not.toContain("<");
  });

  it("renders a simple single-part message whose payload is the body itself", () => {
    const m = msg({ text: "just text" });
    expect((m.payload as { mimeType: string }).mimeType).toBe("text/plain");
    expect(renderMessage(m).body.text).toBe("just text");
  });

  it("bounds the body and flags truncation with the original length, never silently", () => {
    const long = "x".repeat(MAX_BODY_CHARS + 500);
    const r = renderMessage(msg({ text: long }));
    expect(r.body.text.length).toBe(MAX_BODY_CHARS);
    expect(r.body.truncated).toBe(true);
    expect(r.body.originalChars).toBe(MAX_BODY_CHARS + 500);
    const small = renderMessage(msg({ text: long }), 10);
    expect(small.body.text).toBe("xxxxxxxxxx");
  });

  it("a message with no readable part reports source none, not an empty success", () => {
    const r = renderMessage(msg({ attachments: [{ filename: "only.zip", mimeType: "application/zip", size: 5 }] }));
    expect(r.body).toEqual({ text: "", source: "none", truncated: false, originalChars: 0 });
    expect(r.attachments).toHaveLength(1);
  });

  it("decodes the snippet's entities and tolerates missing fields", () => {
    const r = renderMessage({ id: "x", threadId: "y", snippet: "a &amp; b &#39;c&#39;" });
    expect(r.snippet).toBe("a & b 'c'");
    expect(r.labelIds).toEqual([]);
    expect(r.headers).toEqual({});
    expect(r.body.source).toBe("none");
  });

  it("renderBody walks nested multipart/mixed inside multipart/related and treats non-text leaves as attachments", () => {
    const payload = {
      mimeType: "multipart/mixed",
      parts: [
        { mimeType: "multipart/related", parts: [{ mimeType: "multipart/alternative", parts: [{ mimeType: "text/plain", body: { data: b64urlEncode(utf8("deep text")) } }] }, { mimeType: "image/gif", body: { data: "R0lG", size: 4 }, headers: [{ name: "Content-Disposition", value: "inline" }] }] },
        { mimeType: "text/calendar", filename: "", body: { data: b64urlEncode(utf8("BEGIN:VCALENDAR")), size: 15 } },
      ],
    };
    const { body, attachments } = renderBody(payload, 100);
    expect(body.text).toBe("deep text");
    expect(attachments).toEqual([
      { filename: "", mimeType: "image/gif", sizeBytes: 4, inline: true },
      { filename: "", mimeType: "text/calendar", sizeBytes: 15, inline: true },
    ]);
  });
});

describe("renderThread", () => {
  it("keeps message order and spends a per-thread budget, omitting bodies (never headers) past it", () => {
    const messages = [msg({ id: "a", text: "1".repeat(40) }), msg({ id: "b", text: "2".repeat(40) }), msg({ id: "c", text: "3".repeat(40) })];
    const r = renderThread("t1", messages, { maxThreadBodyChars: 60 });
    expect(r.messages.map((m) => m.messageId)).toEqual(["a", "b", "c"]);
    expect(r.messageCount).toBe(3);
    expect(r.messages[0]?.body).toEqual({ text: "1".repeat(40), source: "text/plain", truncated: false, originalChars: 40 });
    expect(r.messages[1]?.body).toEqual({ text: "2".repeat(20), source: "text/plain", truncated: true, originalChars: 40 });
    expect(r.messages[2]?.body).toEqual({ text: "", source: "omitted", truncated: true, originalChars: 40 });
    expect(r.messages[2]?.headers.subject).toBe("Hello");
    expect(r.bodiesOmitted).toBe(true);
  });

  it("flags nothing when everything fits, and caps the number of messages", () => {
    const fits = renderThread("t1", [msg({ id: "a", text: "short" })]);
    expect(fits.bodiesOmitted).toBe(false);
    const capped = renderThread("t1", [msg({ id: "a", text: "x" }), msg({ id: "b", text: "y" })], { maxMessages: 1 });
    expect(capped.messages).toHaveLength(1);
    expect(capped.messageCount).toBe(2);
    expect(capped.bodiesOmitted).toBe(true);
  });
});

describe("summariseThread", () => {
  it("takes the first subject, distinct senders, the latest date, the union of labels and the list snippet", () => {
    const a = msg({ id: "a", from: "X <x@vendor.test>", subject: "Topic", internalDate: Date.UTC(2026, 10, 1), labelIds: ["INBOX"] });
    const b = msg({ id: "b", from: "Y <y@vendor.test>", subject: "Re: Topic", internalDate: Date.UTC(2026, 10, 2), labelIds: ["INBOX", "UNREAD"] });
    const c = msg({ id: "c", from: "X <x@vendor.test>", subject: "Re: Topic", internalDate: Date.UTC(2026, 10, 3), labelIds: ["SENT"] });
    const s = summariseThread("t1", [a, b, c], "list &amp; snippet");
    expect(s).toEqual({ threadId: "t1", subject: "Topic", participants: ["X <x@vendor.test>", "Y <y@vendor.test>"], messageCount: 3, lastMessageDate: "2026-11-03T00:00:00.000Z", labelIds: ["INBOX", "UNREAD", "SENT"], snippet: "list & snippet" });
  });
});
