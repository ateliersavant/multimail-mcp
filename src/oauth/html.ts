export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] ?? c);
}

const STYLE = `body{font:16px/1.5 system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem;color:#1a1a1a;background:#fff}
h1{font-size:1.4rem}dl{display:grid;grid-template-columns:max-content 1fr;gap:.25rem 1rem}dt{color:#555}code{background:#f3f3f3;padding:.1rem .3rem;border-radius:3px}
button{font:inherit;padding:.6rem 1.2rem;border-radius:6px;border:1px solid #888;background:#fff;cursor:pointer;margin-right:.5rem}button.primary{background:#1a1a1a;color:#fff;border-color:#1a1a1a}
.warn{border-left:4px solid #c60;padding:.5rem 1rem;background:#fff7f0}`;

export function page(title: string, body: string, status = 200, extraHeaders?: Headers): Response {
  const headers = new Headers(extraHeaders);
  headers.set("content-type", "text/html; charset=utf-8");
  headers.set("content-security-policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
  headers.set("referrer-policy", "no-referrer");
  headers.set("x-content-type-options", "nosniff");
  headers.set("cache-control", "no-store");
  return new Response(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title><style>${STYLE}</style></head><body>${body}</body></html>`, { status, headers });
}
