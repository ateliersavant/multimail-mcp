import type { Mailbox, Tenant, TenantConfig } from "./types.js";

/**
 * Raised when the tenant file is malformed in any way. Rule 6: the server refuses to start.
 * `issues` lists every problem found, each prefixed with a JSON path.
 */
export class TenantConfigError extends Error {
  readonly issues: readonly string[];
  constructor(issues: readonly string[]) {
    super(`Invalid tenant configuration (${issues.length} issue${issues.length === 1 ? "" : "s"}):\n- ${issues.join("\n- ")}`);
    this.name = "TenantConfigError";
    this.issues = issues;
  }
}

// Deliberately strict: everything lowercase, no normalisation. Comparisons elsewhere are exact.
const TENANT_ID = /^[a-z0-9][a-z0-9-]{1,63}$/;
const SECRET_NAME = /^[A-Z][A-Z0-9_]{2,63}$/;
const HOSTNAME = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const LOCAL_PART = /^[a-z0-9](?:[a-z0-9._+-]{0,62}[a-z0-9])?$/;

const ROOT_KEYS = new Set(["$comment", "tenants"]);
const TENANT_KEYS = new Set(["id", "label", "domains", "serviceAccountSecret", "mailboxes"]);
const MAILBOX_KEYS = new Set(["address", "sendAs"]);

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Splits a lowercase email into [local, domain]; returns undefined if it is not one. */
export function splitAddress(address: string): readonly [string, string] | undefined {
  const at = address.lastIndexOf("@");
  if (at <= 0 || at === address.length - 1) return undefined;
  const local = address.slice(0, at);
  const domain = address.slice(at + 1);
  if (!LOCAL_PART.test(local) || !HOSTNAME.test(domain)) return undefined;
  return [local, domain];
}

/**
 * Parses and validates an already-decoded JSON value into a TenantConfig.
 * Throws TenantConfigError listing every issue. Never returns a partially valid config.
 */
export function parseTenantConfig(input: unknown): TenantConfig {
  const issues: string[] = [];
  const fail = (path: string, msg: string): void => {
    issues.push(`${path}: ${msg}`);
  };

  if (!isRecord(input)) {
    throw new TenantConfigError(["$: must be an object with a \"tenants\" array"]);
  }
  for (const k of Object.keys(input)) if (!ROOT_KEYS.has(k)) fail(`$.${k}`, "unknown key");
  const rawTenants = input["tenants"];
  if (!Array.isArray(rawTenants)) {
    throw new TenantConfigError([...issues, "$.tenants: must be an array"]);
  }
  if (rawTenants.length === 0) fail("$.tenants", "must list at least one tenant (an empty list would make every account unknown)");

  const seenTenantIds = new Map<string, string>();
  const seenDomains = new Map<string, string>();
  const seenSecrets = new Map<string, string>();
  const seenAddresses = new Map<string, string>();
  const tenants: Tenant[] = [];

  rawTenants.forEach((rawTenant: unknown, ti: number) => {
    const tp = `$.tenants[${ti}]`;
    if (!isRecord(rawTenant)) {
      fail(tp, "must be an object");
      return;
    }
    for (const k of Object.keys(rawTenant)) if (!TENANT_KEYS.has(k)) fail(`${tp}.${k}`, "unknown key");
    for (const k of TENANT_KEYS) if (!(k in rawTenant)) fail(`${tp}.${k}`, "missing");

    const id = rawTenant["id"];
    if (typeof id !== "string" || !TENANT_ID.test(id)) fail(`${tp}.id`, "must match /^[a-z0-9][a-z0-9-]{1,63}$/");
    else if (seenTenantIds.has(id)) fail(`${tp}.id`, `duplicate of ${seenTenantIds.get(id)}`);
    else seenTenantIds.set(id, `${tp}.id`);

    const label = rawTenant["label"];
    if (typeof label !== "string" || label.trim().length === 0 || label.length > 80) fail(`${tp}.label`, "must be a non-empty string (max 80 chars)");

    const secret = rawTenant["serviceAccountSecret"];
    if (typeof secret !== "string" || !SECRET_NAME.test(secret)) fail(`${tp}.serviceAccountSecret`, "must be a secret NAME matching /^[A-Z][A-Z0-9_]{2,63}$/ (never a key)");
    else if (seenSecrets.has(secret)) fail(`${tp}.serviceAccountSecret`, `shared with ${seenSecrets.get(secret)}; one service account per tenant`);
    else seenSecrets.set(secret, `${tp}.serviceAccountSecret`);

    const domains: string[] = [];
    const rawDomains = rawTenant["domains"];
    if (!Array.isArray(rawDomains) || rawDomains.length === 0) fail(`${tp}.domains`, "must be a non-empty array of lowercase hostnames");
    else {
      rawDomains.forEach((d: unknown, di: number) => {
        const dp = `${tp}.domains[${di}]`;
        if (typeof d !== "string" || !HOSTNAME.test(d)) fail(dp, "must be a lowercase hostname");
        else if (domains.includes(d)) fail(dp, "duplicate within tenant");
        else if (seenDomains.has(d)) fail(dp, `already belongs to ${seenDomains.get(d)}; a domain cannot belong to two tenants`);
        else {
          domains.push(d);
          seenDomains.set(d, `${tp}.domains[${di}]`);
        }
      });
    }
    const inTenant = (addr: string): boolean => {
      const parts = splitAddress(addr);
      return parts !== undefined && domains.includes(parts[1]);
    };

    const mailboxes: Mailbox[] = [];
    const rawMailboxes = rawTenant["mailboxes"];
    if (!Array.isArray(rawMailboxes) || rawMailboxes.length === 0) fail(`${tp}.mailboxes`, "must be a non-empty array");
    else {
      rawMailboxes.forEach((rawMailbox: unknown, mi: number) => {
        const mp = `${tp}.mailboxes[${mi}]`;
        if (!isRecord(rawMailbox)) {
          fail(mp, "must be an object");
          return;
        }
        for (const k of Object.keys(rawMailbox)) if (!MAILBOX_KEYS.has(k)) fail(`${mp}.${k}`, "unknown key");
        const address = rawMailbox["address"];
        let addressOk = false;
        if (typeof address !== "string" || splitAddress(address) === undefined) fail(`${mp}.address`, "must be a lowercase email address");
        else if (!inTenant(address)) fail(`${mp}.address`, "domain is not one of this tenant's domains");
        else if (seenAddresses.has(address)) fail(`${mp}.address`, `duplicate of ${seenAddresses.get(address)}`);
        else {
          seenAddresses.set(address, `${mp}.address`);
          addressOk = true;
        }

        const sendAs: string[] = [];
        const rawSendAs = rawMailbox["sendAs"];
        if (!Array.isArray(rawSendAs) || rawSendAs.length === 0) fail(`${mp}.sendAs`, "must be a non-empty array of lowercase email addresses");
        else {
          rawSendAs.forEach((s: unknown, si: number) => {
            const sp = `${mp}.sendAs[${si}]`;
            if (typeof s !== "string" || splitAddress(s) === undefined) fail(sp, "must be a lowercase email address");
            else if (!inTenant(s)) fail(sp, "domain is not one of this tenant's domains (cross-tenant send-as is impossible by construction)");
            else if (sendAs.includes(s)) fail(sp, "duplicate within mailbox");
            else sendAs.push(s);
          });
          if (addressOk && typeof address === "string" && !sendAs.includes(address)) fail(`${mp}.sendAs`, "must include the mailbox's own address");
        }
        if (addressOk && typeof address === "string") mailboxes.push({ address, sendAs });
      });
    }

    if (typeof id === "string" && typeof label === "string" && typeof secret === "string") {
      tenants.push({ id, label, domains, serviceAccountSecret: secret, mailboxes });
    }
  });

  if (issues.length > 0) throw new TenantConfigError(issues);
  return { tenants };
}

/** Parses JSON text then validates. Invalid JSON is a TenantConfigError too. */
export function loadTenantConfig(jsonText: string): TenantConfig {
  let decoded: unknown;
  try {
    decoded = JSON.parse(jsonText);
  } catch {
    // The parser's own message quotes part of the input (real addresses and domains) and this ends up in the Worker
    // log, so only the fact is reported. `npm run check:tenants` shows the exact position locally.
    throw new TenantConfigError(["$: not valid JSON (run npm run check:tenants on the file to see where)"]);
  }
  return parseTenantConfig(decoded);
}
