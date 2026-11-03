import { describe, expect, it } from "vitest";
import { GmailApiError, assertGmailId } from "../../src/gmail/client.js";

const A = "ada@example-studio.test";
const ok = (kind: "thread" | "message" | "draft", id: string): boolean => {
  try {
    assertGmailId(kind, id, A);
    return true;
  } catch (e) {
    expect(e).toBeInstanceOf(GmailApiError);
    return false;
  }
};

describe("Gmail ids", () => {
  it("accepts both real draft id forms, r-… and s:…", () => {
    for (const id of ["r-5006678924166716795", "r5006678924166716795", "s:12908613898737284573"]) expect(ok("draft", id), id).toBe(true);
  });

  it("allows at most one colon, in draft ids only, and nothing that could leave the path segment", () => {
    for (const id of ["s:1:2", ":123", "s:", "a/b", "../x", "s:1/2", "a%2Fb", "a b", "a?b", "a#b", ""]) expect(ok("draft", id), id).toBe(false);
    for (const id of ["s:12908613898737284573", "a:b"]) {
      expect(ok("thread", id), id).toBe(false);
      expect(ok("message", id), id).toBe(false);
    }
    expect(ok("thread", "18c2f0a9b3d4e5f6")).toBe(true);
  });
});
