/**
 * Presents the Durable Object store through the KV interface the OAuth library expects as `env.OAUTH_KV`.
 * Implements the shapes the library uses: get (text/json), getWithMetadata, put (string, expirationTtl/expiration,
 * metadata), delete, list (prefix/limit/cursor, with expiration and metadata per key). Anything else throws loudly.
 */
import type { ListOptions, OAuthStore, PutOptions } from "./oauth-store.js";

/** Metadata must survive JSON; anything else is a caller bug, surfaced instead of silently dropped. */
function toMetadataJson(value: unknown): string {
  const text = JSON.stringify(value);
  if (text === undefined) throw new TypeError("consistent-kv: metadata is not JSON-serialisable");
  return text;
}

function fromMetadataJson(text: string | undefined): unknown {
  return text === undefined ? null : (JSON.parse(text) as unknown);
}

type GetType = "text" | "json" | "arrayBuffer" | "stream";

function typeOf(options: unknown): GetType {
  if (typeof options === "string") return options as GetType;
  if (typeof options === "object" && options !== null && "type" in options && typeof (options as { type?: unknown }).type === "string") {
    return (options as { type: GetType }).type;
  }
  return "text";
}

/** The one store instance. Bump the suffix only with a migration plan: it would orphan every client, grant and token. */
const STORE_NAME = "oauth-v1";

export function createConsistentKv(namespace: DurableObjectNamespace<OAuthStore>): KVNamespace {
  // A stub is request-scoped I/O in Workers and must not be reused across requests; the namespace binding may be.
  const stub = (): DurableObjectStub<OAuthStore> => namespace.get(namespace.idFromName(STORE_NAME));
  const kv = {
    async get(key: string, options?: unknown): Promise<unknown> {
      const stored = await stub().get(key);
      if (stored === null) return null;
      switch (typeOf(options)) {
        case "text":
          return stored.value;
        case "json":
          return JSON.parse(stored.value) as unknown;
        case "arrayBuffer":
          return new TextEncoder().encode(stored.value).buffer;
        case "stream":
          return new Response(stored.value).body;
        default:
          throw new TypeError("consistent-kv: unsupported get type");
      }
    },
    async getWithMetadata(key: string, options?: unknown): Promise<unknown> {
      const stored = await stub().get(key);
      if (stored === null) return { value: null, metadata: null, cacheStatus: null };
      const type = typeOf(options);
      const value = type === "json" ? (JSON.parse(stored.value) as unknown) : type === "text" ? stored.value : await kv.get(key, options);
      return { value, metadata: fromMetadataJson(stored.metadataJson), cacheStatus: null };
    },
    async put(key: string, value: unknown, options?: { expirationTtl?: number; expiration?: number; metadata?: unknown }): Promise<void> {
      let text: string;
      if (typeof value === "string") text = value;
      else if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) text = new TextDecoder().decode(value as ArrayBuffer);
      else if (value instanceof ReadableStream) text = await new Response(value).text();
      else throw new TypeError("consistent-kv: unsupported put value");
      const putOptions: { -readonly [K in keyof PutOptions]: PutOptions[K] } = {};
      if (options?.expirationTtl !== undefined) putOptions.expirationTtl = options.expirationTtl;
      if (options?.expiration !== undefined) putOptions.expiration = options.expiration;
      if (options?.metadata !== undefined && options.metadata !== null) putOptions.metadataJson = toMetadataJson(options.metadata);
      await stub().put(key, text, putOptions);
    },
    async delete(key: string): Promise<void> {
      await stub().delete(key);
    },
    async list(options?: { prefix?: string | null; limit?: number; cursor?: string | null }): Promise<unknown> {
      const listOptions: { -readonly [K in keyof ListOptions]: ListOptions[K] } = {};
      if (options?.prefix !== undefined && options.prefix !== null) listOptions.prefix = options.prefix;
      if (options?.limit !== undefined) listOptions.limit = options.limit;
      if (options?.cursor !== undefined && options.cursor !== null) listOptions.cursor = options.cursor;
      const page = await stub().list(listOptions);
      const keys = page.keys.map((k) => ({
        name: k.name,
        ...(k.expiration !== undefined ? { expiration: k.expiration } : {}),
        ...(k.metadataJson !== undefined ? { metadata: fromMetadataJson(k.metadataJson) } : {}),
      }));
      return page.list_complete ? { keys, list_complete: true, cacheStatus: null } : { keys, list_complete: false, cursor: page.cursor, cacheStatus: null };
    },
  };
  return kv as unknown as KVNamespace;
}
