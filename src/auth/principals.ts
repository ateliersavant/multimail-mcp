import { splitAddress } from "../tenants/validate.js";

/** Rule 6 applies here too: an empty or malformed allowlist refuses to start rather than allowing nobody-or-everybody by accident. */
export class PrincipalConfigError extends Error {
  constructor(msg: string) {
    super(`ALLOWED_PRINCIPALS: ${msg}`);
    this.name = "PrincipalConfigError";
  }
}

/** Parses "a@x.test, b@y.test" (commas, spaces or newlines). Lowercase email addresses only; exact match later. */
export function parseAllowedPrincipals(raw: string | undefined): ReadonlySet<string> {
  if (raw === undefined || raw.trim().length === 0) throw new PrincipalConfigError("missing or empty; the server refuses to start without an allowlist");
  const out = new Set<string>();
  const parts = raw.split(/[\s,]+/).filter((p) => p.length > 0);
  parts.forEach((part, i) => {
    if (part !== part.toLowerCase() || splitAddress(part) === undefined) throw new PrincipalConfigError(`entry ${i + 1} is not a lowercase email address`);
    out.add(part);
  });
  if (out.size === 0) throw new PrincipalConfigError("no addresses found");
  return out;
}

export function isAllowedPrincipal(allowed: ReadonlySet<string>, email: string): boolean {
  return allowed.has(email);
}
