import { applyD1Migrations, type D1Migration } from "cloudflare:test";
import { env } from "cloudflare:workers";

// Every worker test file starts with the production audit schema in its D1 database.
await applyD1Migrations(env.AUDIT_DB, (env as unknown as { readonly TEST_MIGRATIONS: D1Migration[] }).TEST_MIGRATIONS);
