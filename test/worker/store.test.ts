import { describe, expect, it } from "vitest";
import { env } from "cloudflare:workers";
import { withConsistentStore } from "../../src/store/env.js";

const kv = withConsistentStore(env).OAUTH_KV;
const now = () => Math.floor(Date.now() / 1000);

describe("Durable Object backed OAUTH_KV", () => {
  it("round-trips text and json, and reads back immediately after a write", async () => {
    await kv.put("grant:u1:g1", JSON.stringify({ clientId: "c1", scope: ["mail"] }));
    expect(await kv.get("grant:u1:g1")).toBe('{"clientId":"c1","scope":["mail"]}');
    expect(await kv.get("grant:u1:g1", { type: "json" })).toEqual({ clientId: "c1", scope: ["mail"] });
    expect(await kv.get("grant:u1:g1", "json")).toEqual({ clientId: "c1", scope: ["mail"] });
    expect(await kv.get("missing")).toBeNull();
    expect(await kv.get("missing", { type: "json" })).toBeNull();
  });

  it("overwrites in place and deletes", async () => {
    await kv.put("client:x", "1");
    await kv.put("client:x", "2");
    expect(await kv.get("client:x")).toBe("2");
    await kv.delete("client:x");
    expect(await kv.get("client:x")).toBeNull();
    await kv.delete("client:x"); // idempotent
  });

  it("honours expirationTtl and absolute expiration; expired keys read as absent and are not listed", async () => {
    await kv.put("token:a", "live", { expirationTtl: 3600 });
    await kv.put("token:b", "dead", { expiration: now() - 1 });
    await kv.put("token:c", "dead-too", { expirationTtl: 60 });
    // simulate time passing for c by rewriting with an absolute past expiry (the DO reads the clock itself)
    await kv.put("token:c", "dead-too", { expiration: now() - 10 });
    expect(await kv.get("token:a")).toBe("live");
    expect(await kv.get("token:b")).toBeNull();
    expect(await kv.get("token:c")).toBeNull();
    const page = await kv.list({ prefix: "token:" });
    expect(page.keys.map((k) => k.name)).toEqual(["token:a"]);
    expect(page.keys[0]?.expiration).toBeGreaterThan(now());
  });

  it("lists by prefix in key order with limit and cursor, and never leaks other prefixes", async () => {
    for (const k of ["list:03", "list:01", "list:02", "listx:99", "other:1"]) await kv.put(k, "v");
    const first = await kv.list({ prefix: "list:", limit: 2 });
    expect(first.keys.map((k) => k.name)).toEqual(["list:01", "list:02"]);
    expect(first.list_complete).toBe(false);
    const cursor = first.list_complete ? null : first.cursor;
    const second = await kv.list({ prefix: "list:", limit: 2, cursor });
    expect(second.keys.map((k) => k.name)).toEqual(["list:03"]);
    expect(second.list_complete).toBe(true);
    const all = await kv.list({ prefix: "list" });
    expect(all.keys.map((k) => k.name)).toEqual(["list:01", "list:02", "list:03", "listx:99"]);
  });

  it("keeps metadata with the value and returns it from getWithMetadata and list", async () => {
    await kv.put("meta:1", "v", { metadata: { userId: "u1", kind: "grant" }, expirationTtl: 600 });
    await kv.put("meta:2", "w");
    const withMeta = await kv.getWithMetadata<{ userId: string }>("meta:1");
    expect(withMeta.value).toBe("v");
    expect(withMeta.metadata).toEqual({ userId: "u1", kind: "grant" });
    const plain = await kv.getWithMetadata("meta:2");
    expect(plain).toMatchObject({ value: "w", metadata: null });
    const missing = await kv.getWithMetadata("meta:none");
    expect(missing).toMatchObject({ value: null, metadata: null });
    const listed = await kv.list<{ userId: string }>({ prefix: "meta:" });
    expect(listed.keys.map((k) => [k.name, k.metadata ?? null])).toEqual([["meta:1", { userId: "u1", kind: "grant" }], ["meta:2", null]]);
  });
});
