import { verifyTurnstile, genCode, getUsedBytes, setUsedBytes, Env } from '../_utils';

export const onRequestPost: PagesFunction<Env> = async (ctx) => {
  const { request, env } = ctx;
  const form = await request.formData();
  const file = form.get('file');
  const note = (form.get('note') || '').toString().slice(0, 500);
  const token = form.get('cf-turnstile-response')?.toString() || null;

  if (!(file instanceof File)) {
    return json({ error: '缺少文件' }, 400);
  }

  const ip = request.headers.get('CF-Connecting-IP') || undefined;
  const chk = await verifyTurnstile(env.TURNSTILE_SECRET, token, ip);
  if (!chk.success) return json({ error: `人机验证失败：${chk.error || ''}` }, 400);

  const size = file.size;
  const quota = Number(env.QUOTA_BYTES || 5368709120);

  // 先用缓存，逼近上限再强制回表
  let used = await getUsedBytes(env);
  if (used + size > quota) {
    const recalced = await getUsedBytes(env, true);
    if (recalced + size > quota) {
      return json({ error: '存储达到上限（5GB），请稍后再试' }, 413);
    }
    used = recalced;
  }

  const now = new Date();
  const expiresAt = new Date(now.getTime() + 24 * 60 * 60 * 1000);
  const safeName = (file.name || 'file').replace(/[^A-Za-z0-9_.-]/g, '_').slice(0, 80) || 'file';
  const key = `tmp/${now.toISOString().replace(/[:.]/g,'')}_${crypto.randomUUID()}_${safeName}`;

  await env.TEMP_BUCKET.put(key, file.stream(), {
    httpMetadata: {
      contentType: file.type || 'application/octet-stream',
      contentDisposition: `attachment; filename*=UTF-8''${encodeURIComponent(file.name)}`,
      cacheControl: 'no-store',
    },
    customMetadata: {
      note, expiresAt: String(expiresAt.getTime()), filename: file.name, size: String(size),
    }
  });

  // 生成 6 位口令，写 KV（TTL 24h）
  let code = genCode();
  for (let i = 0; i < 5; i++) {
    const exists = await env.TEMP_KV.get(`code:${code}`);
    if (!exists) break; else code = genCode();
  }
  await env.TEMP_KV.put(
    `code:${code}`,
    JSON.stringify({ key, filename: file.name, note, size, expiresAt: expiresAt.toISOString() }),
    { expirationTtl: 24 * 60 * 60 }
  );

  await setUsedBytes(env, used + size);
  return json({ code, expiresAt: expiresAt.toISOString() });
};

function json(data: any, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json; charset=utf-8' } });
}
