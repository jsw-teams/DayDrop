import type { Env } from '../_utils';

export const onRequestGet: PagesFunction<Env> = async (ctx) => {
  const env = ctx.env as Env;
  const missing: string[] = [];
  if (!env.TEMP_BUCKET)        missing.push('R2 binding: TEMP_BUCKET');
  if (!env.TEMP_KV)            missing.push('KV binding: TEMP_KV');
  if (!env.TURNSTILE_SITE_KEY) missing.push('env: TURNSTILE_SITE_KEY');
  if (!env.TURNSTILE_SECRET)   missing.push('env: TURNSTILE_SECRET');

  const ok = missing.length === 0;
  return new Response(JSON.stringify({
    ok, missing,
    bindings: {
      hasR2: !!env.TEMP_BUCKET,
      hasKV: !!env.TEMP_KV,
      hasSiteKey: !!env.TURNSTILE_SITE_KEY,
      hasSecret: !!env.TURNSTILE_SECRET,
      quotaBytes: Number(env.QUOTA_BYTES || 0),
      environment: env.ENVIRONMENT || 'unknown'
    }
  }, null, 2), { headers: { 'Content-Type': 'application/json; charset=utf-8' }, status: ok ? 200 : 500 });
};
