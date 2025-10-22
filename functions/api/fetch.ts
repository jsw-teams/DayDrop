import { verifyTurnstile, Env } from '../_utils';

export const onRequestPost: PagesFunction<Env> = async (ctx) => {
  const { request, env } = ctx;
  const form = await request.formData();
  const code = (form.get('code') || '').toString();
  const token = form.get('cf-turnstile-response')?.toString() || null;

  if (!/^[0-9]{6}$/.test(code)) {
    return new Response(JSON.stringify({ error: '口令格式错误' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }

  const ip = request.headers.get('CF-Connecting-IP') || undefined;
  const chk = await verifyTurnstile(env.TURNSTILE_SECRET, token, ip);
  if (!chk.success) {
    return new Response(JSON.stringify({ error: `人机验证失败：${chk.error || ''}` }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }

  const val = await env.TEMP_KV.get(`code:${code}`, 'json');
  if (!val) {
    return new Response(JSON.stringify({ error: '口令不存在或已过期' }), { status: 404, headers: { 'Content-Type': 'application/json' } });
  }
  const { key, filename } = val as { key: string; filename: string };

  const obj = await env.TEMP_BUCKET.get(key);
  if (!obj) {
    // 对象可能已被 R2 生命周期清理
    return new Response(JSON.stringify({ error: '文件已被删除' }), { status: 410, headers: { 'Content-Type': 'application/json' } });
  }

  const headers = new Headers();
  const meta = obj.httpMetadata || {};
  if (meta.contentType) headers.set('Content-Type', meta.contentType);
  headers.set('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(filename)}`);
  headers.set('Cache-Control', 'no-store');

  return new Response(obj.body, { headers });
};