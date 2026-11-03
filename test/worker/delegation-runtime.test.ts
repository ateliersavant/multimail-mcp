import { beforeAll, describe, expect, it } from "vitest";
import { DelegationTokenSource } from "../../src/gmail/delegation.js";
import { GmailClient } from "../../src/gmail/client.js";
import { GOOGLE_EGRESS, createEgressFetch } from "../../src/net/egress.js";
import { TenantRegistry, loadTenantConfig } from "../../src/tenants/index.js";
import { env } from "cloudflare:workers";
import { FakeGoogle, LABS_GRACE, STUDIO_ADA, makeServiceAccount, sampleMailboxes, type TestServiceAccount } from "../helpers/fake-gmail.js";

// The crypto path (PKCS#8 import, RS256 sign) and the egress wrapper run here in workerd, not Node, over the fake Google.
let sa: TestServiceAccount;
beforeAll(async () => {
  sa = await makeServiceAccount("multimail-studio@fake-project.iam.gserviceaccount.test");
});

describe("delegation in the Workers runtime", () => {
  it("mints a token with WebCrypto, reuses it, and reads a mailbox through the egress wrapper", async () => {
    const registry = new TenantRegistry(loadTenantConfig(env.TENANTS_JSON));
    const ada = registry.requireMailbox(STUDIO_ADA);
    const google = new FakeGoogle([{ sa, mailboxes: [STUDIO_ADA] }], sampleMailboxes());
    const fetch = createEgressFetch(GOOGLE_EGRESS, google.fetch);
    const tokens = new DelegationTokenSource({ secrets: { SA_EXAMPLE_STUDIO: sa.json }, fetch });
    const gmail = new GmailClient({ fetch, tokens });
    const labels = await gmail.listLabels(ada);
    expect(labels.map((l) => l.id)).toEqual(["INBOX", "SENT", "Label_7"]);
    const page = await gmail.listThreads(ada, { q: "invoice", maxResults: 5 });
    expect(page.threads.map((t) => t.id)).toEqual(["t-invoice"]);
    expect(google.tokensIssued).toBe(1);
    // a mailbox outside this service account's tenant is refused by Google, loudly
    const grace = registry.requireMailbox(LABS_GRACE);
    const labsTokens = new DelegationTokenSource({ secrets: { SA_EXAMPLE_LABS: sa.json }, fetch });
    await expect(labsTokens.tokenFor(grace)).rejects.toMatchObject({ name: "DelegationError", code: "delegation_token_refused" });
  });
});
