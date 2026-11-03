import { readFileSync } from "node:fs";
import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

const fixtureTenants = readFileSync(new URL("./fixtures/tenants.example.json", import.meta.url), "utf8");

export default defineConfig({
  test: {
    projects: [
      {
        // Pure modules: tenants, egress, audit, Google sign-in, config. Node runtime, fast.
        test: { name: "unit", include: ["test/unit/**/*.test.ts"], environment: "node" },
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
              },
            },
          }),
        ],
        test: { name: "worker", include: ["test/worker/**/*.test.ts"] },
      },
    ],
  },
});
