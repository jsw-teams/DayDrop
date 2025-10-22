import type { Env } from '../_utils';

export const onRequestGet: PagesFunction<Env> = async (ctx) => {
  const env = ctx.env as Env;
  const missing: string[] = [];
  if (!env.TEMP_BUCKET)        missing.push('TEMP_BUCKET');
  if (!env.TEMP_KV)            missing.push('TEMP_KV');
  if (!env.TURNSTILE_SITE_KEY) missing.push('TURNSTILE_SITE_KEY');
  if (!env.TURNSTILE_SECRET)   missing.push('TURNSTILE_SECRET');

  return new Response(JSON.stringify({
    turnstileSiteKey: env.TURNSTILE_SITE_KEY || '',
    ready: missing.length === 0,
    missing
  }), { headers: { 'Content-Type': 'application/json; charset=utf-8' } });
};
