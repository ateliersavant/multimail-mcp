import { createConsistentKv } from "./consistent-kv.js";

/** The env the OAuth library sees: the real bindings plus `OAUTH_KV` backed by the Durable Object. */
export type ProviderEnv = Env & { readonly OAUTH_KV: KVNamespace };

const wrapped = new WeakMap<object, ProviderEnv>();

/** One wrapper per isolate per env object, so per-env caches elsewhere keep working. */
export function withConsistentStore(env: Env): ProviderEnv {
  const hit = wrapped.get(env);
  if (hit !== undefined) return hit;
  const result: ProviderEnv = Object.assign(Object.create(null) as object, env, { OAUTH_KV: createConsistentKv(env.OAUTH_STORE) }) as ProviderEnv;
  wrapped.set(env, result);
  return result;
}
