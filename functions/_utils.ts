export type Env = {
  TEMP_BUCKET: R2Bucket;
  TEMP_KV: KVNamespace;
  TURNSTILE_SECRET: string;
  TURNSTILE_SITE_KEY: string;
  QUOTA_BYTES?: string; // e.g. "5368709120"
  ENVIRONMENT?: string; // "production" | "preview" | "local"
};

export async function verifyTurnstile(secret: string, token: string | null, ip?: string) {
  if (!token) return { success: false, error: 'Missing Turnstile token' };
  const form = new FormData();
  form.append('secret', secret);
  form.append('response', token);
  if (ip) form.append('remoteip', ip);

  const resp = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: form });
  const data = await resp.json<any>();
  return { success: !!data.success, error: (data['error-codes'] || []).join(', ') };
}

export function genCode(): string {
  const n = Math.floor(Math.random() * 1_000_000);
  return n.toString().padStart(6, '0');
}

export async function recalcUsage(env: Env): Promise<number> {
  let sum = 0; let cursor: string | undefined = undefined;
  do {
    const list = await env.TEMP_BUCKET.list({ prefix: 'tmp/', limit: 1000, cursor });
    for (const o of list.objects) sum += o.size;
    cursor = list.truncated ? list.cursor : undefined;
  } while (cursor);
  return sum;
}

export async function getUsedBytes(env: Env, force = false): Promise<number> {
  const now = Date.now();
  const cached = await env.TEMP_KV.get('usage_cache', 'json') as { bytes: number; ts: number } | null;
  if (!force && cached && (now - cached.ts) < 10 * 60 * 1000) return cached.bytes;
  const bytes = await recalcUsage(env);
  await env.TEMP_KV.put('usage_cache', JSON.stringify({ bytes, ts: now }));
  return bytes;
}

export async function setUsedBytes(env: Env, bytes: number) {
  await env.TEMP_KV.put('usage_cache', JSON.stringify({ bytes, ts: Date.now() }));
}
