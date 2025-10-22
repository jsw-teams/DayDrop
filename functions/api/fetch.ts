import { verifyTurnstile, Env } from '../_utils';

export const onRequestPost: PagesFunction<Env> = async (ctx) => {
  const { request, env } = ctx;
  const form = await request.formData();
  const code = (form.get('code') || '').toString();
  const token = form.get('cf-turnstile-response')?.toString() || null;

  if (!/^[0-9]{6}$/.test(code)) return json({ error: '口令格式错误' }, 400);

  const ip = request.headers.get('CF-Connecting-IP') || undefined;
  const chk = await verifyTurnstile(env.TURNSTILE_SECRET, token, ip);
  if (!chk.success) return json({ error: `人机验证失败：${chk.error || ''}` }, 400);

  const rec = await env.TEMP_KV.get(`code:${code}`, 'json') as { key: string; filename: string } | null;
  if (!rec) return json({ error: '口令不存在或已过期' }, 404);

  const obj = await env.TEMP_BUCKET.get(rec.key);
  if (!obj) return json({ error: '文件已被删除' }, 410);

  const headers = new Headers();
  if (obj.httpMetadata?.contentType) headers.set('Content-Type', obj.httpMetadata.contentType);
  headers.set('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(rec.filename)}`);
  headers.set('Cache-Control', 'no-store');
  return new Response(obj.body, { headers });
};

function json(data: any, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json; charset=utf-8' } });
}
