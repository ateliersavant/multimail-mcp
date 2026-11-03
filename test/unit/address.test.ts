import { describe, expect, it } from "vitest";
import { displayAddressList, parseAddressList, singleMailbox, stripInvisible } from "../../src/gmail/address.js";

describe("RFC 5322 address lists", () => {
  it("reads quoted names, escapes, comments and groups without mistaking a name for an address", () => {
    expect(parseAddressList(`"Doe, Jane" <jane@x.test>, (team) bob@y.test, Ops: a@z.test, b@z.test;`).mailboxes.map((m) => m.address)).toEqual(["jane@x.test", "bob@y.test", "a@z.test", "b@z.test"]);
    expect(parseAddressList(`"Fake <ceo@x.test>" <real@evil.test>`).mailboxes).toEqual([{ name: "Fake <ceo@x.test>", address: "real@evil.test" }]);
    expect(parseAddressList(`"unbalanced <a@x.test>`).unparsed).toHaveLength(1);
    expect(parseAddressList(`Two <a@x.test> <b@x.test>`).unparsed).toHaveLength(1);
  });

  it("singleMailbox: exactly one readable mailbox, whatever its position, or nothing", () => {
    expect(singleMailbox(`Ada <Ada@Example-Studio.test>`)).toBe("ada@example-studio.test");
    for (const v of [`Ada <ada@x.test>, extra@x.test`, `extra@x.test, Ada <ada@x.test>`, `Ada <ada@x.test>, junk`, `Team: ada@x.test, b@x.test;`, ``, undefined]) {
      expect(singleMailbox(v), String(v)).toBeUndefined();
    }
  });

  it("displayAddressList always shows the real address, cutting long names and never the address", () => {
    const shown = displayAddressList(`"${"A".repeat(2000)} <ceo@example-studio.test>" <attacker@evil.test>`);
    expect(shown).toContain("<attacker@evil.test>");
    expect(shown.length).toBeLessThan(200);
    expect(displayAddressList(Array.from({ length: 60 }, (_, i) => `r${i}@x.test`).join(", "))).toMatch(/\(\+10 more\)$/);
    expect(displayAddressList(`ok@x.test, <<<`)).toContain("[unreadable:");
  });

  it("removes invisible characters", () => {
    expect(stripInvisible("a​b‮c⠀")).toBe("abc");
  });
});
