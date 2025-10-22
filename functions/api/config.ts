import type { Env } from '../_utils';

export const onRequestGet: PagesFunction<Env> = async (ctx) => {
  return new Response(JSON.stringify({ turnstileSiteKey: ctx.env.TURNSTILE_SITE_KEY }), { headers: { 'Content-Type': 'application/json' } });
};