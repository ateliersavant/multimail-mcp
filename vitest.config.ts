import { readFileSync } from "node:fs";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

const fixtureTenants = readFileSync(new URL("./fixtures/tenants.example.json", import.meta.url), "utf8");
// The real audit migration, applied to the test D1 database by test/worker/setup.ts before each file.
const migrations = await readD1Migrations(new URL("./migrations", import.meta.url).pathname);

export default defineConfig({
  test: {
    projects: [
      {
        // Pure modules: tenants, egress, audit, Google sign-in, config. Node runtime, fast.
        // test/adversarial: the adversarial review's proofs, kept as regression tests (see its README).
        test: { name: "unit", include: ["test/unit/**/*.test.ts", "test/adversarial/**/*.unit.test.ts"], environment: "node" },
      },
      {
        // The Worker itself (discovery endpoints, 401s, consent page, MCP over HTTP) in workerd.
        plugins: [
          cloudflareTest({
            wrangler: { configPath: "./wrangler.jsonc" },
            miniflare: {
              bindings: {
                PUBLIC_URL: "https://mcp.example.test",
                ALLOWED_PRINCIPALS: "ada@example-studio.test",
                GOOGLE_CLIENT_ID: "test-client-id.apps.googleusercontent.com",
                GOOGLE_CLIENT_SECRET: "test-client-secret",
                TENANTS_JSON: fixtureTenants,
                // SA_EXAMPLE_STUDIO is deliberately absent (missing secret path); the labs one is present but not a key.
                SA_EXAMPLE_LABS: "not-a-service-account-key",
                // Small per-client request limit so the 429 path is reachable in a test (production default: 120/min).
                MCP_RATE_LIMIT_PER_MINUTE: "40",
                // The test client registers with a redirect on this host (production allows only supported clients and loopback).
                CLIENT_REDIRECT_HOSTS: "client.example.test",
                TEST_MIGRATIONS: migrations,
              },
            },
          }),
        ],
        test: { name: "worker", include: ["test/worker/**/*.test.ts", "test/adversarial/**/*.worker.test.ts"], setupFiles: ["./test/worker/setup.ts"] },
      },
    ],
  },
});
