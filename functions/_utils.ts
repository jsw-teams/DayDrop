export async function verifyTurnstile(secret: string, token: string | null, ip?: string) {
  if (!token) return { success: false, error: 'Missing Turnstile token' };
  const form = new FormData();
  form.append('secret', secret);
  form.append('response', token);
  if (ip) form.append('remoteip', ip);

  const resp = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: form });
  const data = await resp.json<any>();
  return { success: !!data.success, error: data['error-codes']?.join(', ') };
}

export function genCode(): string {
  // 6 位数字，000000-999999
  const n = Math.floor(Math.random() * 1_000_000);
  return n.toString().padStart(6, '0');
}

export async function getUsedBytes(env: Env): Promise<number> {
  const cached = await env.TEMP_KV.get('used_bytes');
  if (cached) return Number(cached);
  // 回表统计
  let sum = 0; let cursor: string | undefined = undefined;
  do {
    const list = await env.TEMP_BUCKET.list({ prefix: 'tmp/', cursor, limit: 1000 });
    list.objects.forEach(o => sum += o.size);
    cursor = list.truncated ? list.cursor : undefined;
  } while (cursor);
  await env.TEMP_KV.put('used_bytes', String(sum));
  return sum;
}

export async function setUsedBytes(env: Env, bytes: number) {
  await env.TEMP_KV.put('used_bytes', String(bytes));
}

export type Env = {
  TEMP_BUCKET: R2Bucket;
  TEMP_KV: KVNamespace;
  TURNSTILE_SECRET: string;
  TURNSTILE_SITE_KEY: string;
  QUOTA_BYTES: string; // e.g. '5368709120'
};