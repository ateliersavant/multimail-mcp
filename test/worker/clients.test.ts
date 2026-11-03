/**
 * The supported clients, as they really identify themselves: each test replays the client's published Client
 * ID Metadata Document (fetched 2026-11-03, test/fixtures/client-metadata) through the real Worker, with the global
 * fetch stubbed so nothing leaves the machine. Each must reach the consent page; the server's client policy
 * (src/oauth/client-policy.ts) must not refuse any of them.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { exports } from "cloudflare:workers";
import chatgpt from "../fixtures/client-metadata/chatgpt.json";
import claude from "../fixtures/client-metadata/claude.json";
import claudeCode from "../fixtures/client-metadata/claude-code.json";
import codex from "../fixtures/client-metadata/codex.json";

const ORIGIN = "https://mcp.example.test";
type Fetcher = { fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> };
const worker = (exports as unknown as { default: Fetcher }).default;

afterEach(() => vi.restoreAllMocks());

const CASES: { readonly name: string; readonly doc: { client_id: string; client_name: string; redirect_uris: string[] }; readonly redirect: string }[] = [
  { name: "Claude", doc: claude, redirect: "https://claude.ai/api/mcp/auth_callback" },
  { name: "Claude Code", doc: claudeCode, redirect: "http://localhost:49152/callback" },
  { name: "ChatGPT", doc: chatgpt, redirect: "https://chatgpt.com/connector_platform_oauth_redirect" },
  // Codex listens on a random loopback port; the document registers the callback without one.
  { name: "Codex", doc: codex, redirect: "http://127.0.0.1:53682/callback" },
];

describe("supported clients reach the consent page with their real metadata documents", () => {
  for (const c of CASES) {
    it(c.name, async () => {
      const fetched: string[] = [];
      vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL) => {
        const url = input instanceof Request ? input.url : String(input);
        fetched.push(url);
        if (url === c.doc.client_id) return new Response(JSON.stringify(c.doc), { headers: { "content-type": "application/json", "cache-control": "no-store" } });
        return new Response("not found", { status: 404 });
      });
      const q = new URLSearchParams({ response_type: "code", client_id: c.doc.client_id, redirect_uri: c.redirect, scope: "mail", state: "s", code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", code_challenge_method: "S256", resource: `${ORIGIN}/mcp` });
      const r = await worker.fetch(new Request(`${ORIGIN}/authorize?${q}`));
      const html = await r.text();
      expect(r.status, html.slice(0, 300)).toBe(200);
      expect(html).toContain(c.doc.client_name);
      // Only the document itself is ever fetched (once per lookup here, as the stub marks it uncacheable).
      expect(fetched.length).toBeGreaterThan(0);
      expect(new Set(fetched)).toEqual(new Set([c.doc.client_id]));
    });
  }
});
