import { verifyTurnstile, genCode, getUsedBytes, setUsedBytes, Env } from '../_utils';

export const onRequestPost: PagesFunction<Env> = async (ctx) => {
  const { request, env } = ctx;
  const form = await request.formData();
  const file = form.get('file');
  const note = (form.get('note') || '').toString().slice(0, 500);
  const token = form.get('cf-turnstile-response')?.toString() || null;

  const ip = request.headers.get('CF-Connecting-IP') || undefined;
  const chk = await verifyTurnstile(env.TURNSTILE_SECRET, token, ip);
  if (!chk.success) {
    return new Response(JSON.stringify({ error: `人机验证失败：${chk.error || ''}` }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }

  if (!(file instanceof File)) {
    return new Response(JSON.stringify({ error: '缺少文件' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }

  const size = file.size;
  const quota = Number(env.QUOTA_BYTES || 5368709120);
  // 先用缓存，逼近上限时强制回表
  let used = await getUsedBytes(env);
  if (used + size > quota) {
    const recalced = await getUsedBytes(env, true);
    if (recalced + size > quota) {
      return new Response(JSON.stringify({ error: '存储达到上限（5GB），请稍后再试' }), { status: 413, headers: { 'Content-Type': 'application/json' } });
    }
    used = recalced;
  }

  const now = new Date();
  const expiresAt = new Date(now.getTime() + 24 * 60 * 60 * 1000);
  const keySafeName = (file.name || 'file').replace(/[^A-Za-z0-9_.-]/g, '_').slice(0, 80) || 'file';
  const objectKey = `tmp/${now.toISOString().replace(/[:.]/g,'')}_${crypto.randomUUID()}_${keySafeName}`;

  // 写入 R2（流式）
  await env.TEMP_BUCKET.put(objectKey, file.stream(), {
    httpMetadata: {
      contentType: file.type || 'application/octet-stream',
      contentDisposition: `attachment; filename*=UTF-8''${encodeURIComponent(file.name)}`,
      cacheControl: 'no-store',
    },
    customMetadata: {
      note,
      expiresAt: String(expiresAt.getTime()), // 仅用于前端展示；真正删除由 R2 生命周期完成
      filename: file.name,
      size: String(size),
    },
  });

  // 生成 6 位口令并写 KV（TTL 24h）
  let code = genCode();
  for (let i = 0; i < 5; i++) {
    const exists = await env.TEMP_KV.get(`code:${code}`);
    if (!exists) break; else code = genCode();
  }
  await env.TEMP_KV.put(
    `code:${code}`,
    JSON.stringify({ key: objectKey, filename: file.name, note, size, expiresAt: expiresAt.toISOString() }),
    { expirationTtl: 24 * 60 * 60 }
  );

  // 记录用量（非原子；靠接近上限时的回表消抖）
  await setUsedBytes(env, used + size);

  return new Response(JSON.stringify({ code, expiresAt: expiresAt.toISOString() }), { headers: { 'Content-Type': 'application/json' } });
};