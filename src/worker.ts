import type {
  Env,
  UploadMpuInitBody, UploadMpuInitResp,
  UploadMpuPresignBody, UploadMpuPresignResp,
  UploadMpuCompleteBody, UploadMpuAbortBody,
  DownloadUrlBody, DownloadUrlResp, FileRecord
} from "./types";
import { presignUrl } from "./signing";

const JSONH = { "content-type": "application/json; charset=utf-8" };
const DAY_MS = 86400000;
const DEF_TTL = 7 * DAY_MS;
const DEF_MAX = 5 * 1024 * 1024 * 1024;
const PART_SIZE = 8 * 1024 * 1024;

function now(){ return Date.now(); }
function ok(data: unknown, init: ResponseInit = {}){ return new Response(JSON.stringify(data), { headers: JSONH, ...init }); }
function bad(msg="bad request", code=400){ return ok({ error: msg }, { status: code }); }
function notfound(msg="not found"){ return bad(msg, 404); }

function corsHeaders(req: Request){
  const o = req.headers.get("Origin");
  const u = new URL(req.url);
  const allow = o && new URL(o).host === u.host ? o : `${u.protocol}//${u.host}`;
  return {
    "access-control-allow-origin": allow,
    "access-control-allow-methods": "GET,POST,OPTIONS",
    "access-control-allow-headers": "content-type",
    "access-control-max-age": "86400"
  };
}
async function handleOptions(req: Request){
  if (req.headers.get("Origin") && req.headers.get("Access-Control-Request-Method"))
    return new Response(null, { headers: corsHeaders(req) });
  return new Response(null, { headers: { allow: "GET, POST, OPTIONS" } });
}

async function verifyTurnstile(env: Env, token?: string, ip?: string | null){
  if (!token) return false;
  const fd = new FormData();
  fd.set("secret", env.TURNSTILE_SECRET_KEY);
  fd.set("response", token);
  if (ip) fd.set("remoteip", ip);
  const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body: fd });
  const j = (await r.json()) as { success: boolean };
  return !!j?.success;
}

/* —— 会话 token（auth） —— */
function makeAuth(): string {
  const b = new Uint8Array(24); crypto.getRandomValues(b);
  return btoa(String.fromCharCode(...b)).replace(/[+/=]/g,"").slice(0,32);
}
async function putUploadAuth(env: Env, uploadId: string, auth: string){
  await env.DAYDROP_KV.put(`auth:up:${uploadId}:${auth}`, "1", { expirationTtl: 30*60 });
}
async function hasUploadAuth(env: Env, uploadId: string, auth?: string){
  if (!auth) return false;
  return !!(await env.DAYDROP_KV.get(`auth:up:${uploadId}:${auth}`));
}
async function delUploadAuth(env: Env, uploadId: string, auth?: string){
  if (auth) await env.DAYDROP_KV.delete(`auth:up:${uploadId}:${auth}`);
}
async function putDownloadAuth(env: Env, code: string, auth: string){
  await env.DAYDROP_KV.put(`auth:dl:${code}:${auth}`, "1", { expirationTtl: 30*60 });
}
async function hasDownloadAuth(env: Env, code: string, auth?: string){
  if (!auth) return false;
  return !!(await env.DAYDROP_KV.get(`auth:dl:${code}:${auth}`));
}

/* —— 好记的取件码 —— */
const SYL_C = "BCDFGHJKMNPQRSTVWXYZ";
const SYL_V = "AEU";
function syl(){ const u8=new Uint8Array(2); crypto.getRandomValues(u8); return SYL_C[u8[0]%SYL_C.length] + SYL_V[u8[1]%SYL_V.length]; }
function humanCode(){ const u8=new Uint8Array(1); crypto.getRandomValues(u8); const d2=(u8[0]%100).toString().padStart(2,"0"); return `${syl()}${syl()}-${syl()}${syl()}-${d2}`; }
async function uniqueCode(env: Env){ for(let i=0;i<6;i++){ const c=humanCode(); if(!await env.DAYDROP_KV.get(`code:${c}`)) return c; } return humanCode(); }

async function getTotalBytes(env: Env){ return Number(await env.DAYDROP_KV.get("usage:total_bytes") || "0"); }
async function addTotalBytes(env: Env, delta: number){
  const cur = await getTotalBytes(env);
  const next = Math.max(0, cur + delta);
  await env.DAYDROP_KV.put("usage:total_bytes", String(next));
  return next;
}

async function abortMpu(env: Env, objectKey: string, uploadId: string){
  try{ const mpu = await env.DAYDROP_BUCKET.resumeMultipartUpload(objectKey, uploadId); await mpu.abort(); }catch{}
  await env.DAYDROP_KV.delete(`mpu:${uploadId}`);
}

/* ================== APIs ================== */

async function apiMpuInit(req: Request, env: Env){
  const ip = req.headers.get("CF-Connecting-IP");
  const body = await req.json() as UploadMpuInitBody;
  if(!body?.filename || !body?.contentType || !body?.size || !body?.turnstileToken) return bad("missing fields");
  if(!await verifyTurnstile(env, body.turnstileToken, ip)) return bad("turnstile failed", 401);

  const max = Number(env.MAX_TOTAL_BYTES || DEF_MAX);
  const cur = await getTotalBytes(env);
  if (cur + body.size > max) return bad("storage quota exceeded", 403);

  const d = new Date();
  const prefix = `${d.getUTCFullYear()}/${(d.getUTCMonth()+1+"").padStart(2,"0")}/${(d.getUTCDate()+"").padStart(2,"0")}`;
  const rid = crypto.randomUUID();
  const safe = body.filename.replace(/[^\w.\-~]/g, "_").slice(-120);
  const objectKey = `${prefix}/${rid}__${safe}`;

  const mpu = await env.DAYDROP_BUCKET.createMultipartUpload(objectKey, { httpMetadata: { contentType: body.contentType } });
  const uploadId = mpu.uploadId;

  const code = await uniqueCode(env);
  const resumeUntil = now() + 30*60*1000;

  await env.DAYDROP_KV.put(`mpu:${uploadId}`, JSON.stringify({
    code, objectKey, filename: body.filename, contentType: body.contentType,
    size: body.size, enc: null, resumeUntil
  }), { expirationTtl: 30*60 });

  const auth = makeAuth();
  await putUploadAuth(env, uploadId, auth);

  const resp: UploadMpuInitResp = { code, objectKey, uploadId, partSize: PART_SIZE, resumeUntil, auth };
  return new Response(JSON.stringify(resp), { headers: { ...JSONH, ...corsHeaders(req) } });
}

async function apiMpuPresign(req: Request, env: Env){
  const ip = req.headers.get("CF-Connecting-IP");
  const body = await req.json() as UploadMpuPresignBody;
  if(!body?.objectKey || !body?.uploadId || !Array.isArray(body?.partNumbers)) return bad("missing fields");

  let authorized = false;
  if (await hasUploadAuth(env, body.uploadId, body.auth)) authorized = true;
  else if (await verifyTurnstile(env, body.turnstileToken, ip)) authorized = true;
  if (!authorized) return bad("unauthorized", 401);

  const stateRaw = await env.DAYDROP_KV.get(`mpu:${body.uploadId}`);
  if(!stateRaw) return bad("mpu not found or expired", 410);
  const state = JSON.parse(stateRaw) as { resumeUntil: number; objectKey: string };
  if (state.resumeUntil < now()) {
    await abortMpu(env, body.objectKey, (body as any).uploadId);
    return bad("resume window passed; mpu aborted", 410);
  }

  const est = Math.max(0, Math.floor(body.estimatedSeconds || 0));
  const expires = Math.min(24*3600, Math.max(1800, est + 1800));

  const urls = await Promise.all(body.partNumbers.map(async n => {
    const u = await presignUrl(env, "PUT", body.objectKey, expires, { partNumber: n, uploadId: body.uploadId });
    return { partNumber: n, url: u.toString() };
  }));

  await env.DAYDROP_KV.put(`mpu:${body.uploadId}`, stateRaw, { expirationTtl: 30*60 });
  const resp: UploadMpuPresignResp = { urls, expiresAt: now() + expires*1000 };
  return new Response(JSON.stringify(resp), { headers: { ...JSONH, ...corsHeaders(req) } });
}

async function apiMpuComplete(req: Request, env: Env){
  const ip = req.headers.get("CF-Connecting-IP");
  const body = await req.json() as UploadMpuCompleteBody;
  if(!body?.objectKey || !body?.uploadId || !Array.isArray(body?.parts)) return bad("missing fields");

  let authorized = false;
  if (await hasUploadAuth(env, body.uploadId, body.auth)) authorized = true;
  else if (await verifyTurnstile(env, body.turnstileToken, ip)) authorized = true;
  if (!authorized) return bad("unauthorized", 401);

  // 先保证按 partNumber 升序且 etag 非空
  const parts = body.parts
    .filter(p => p && typeof p.partNumber === "number" && p.etag && String(p.etag).trim() !== "")
    .sort((a,b)=>a.partNumber-b.partNumber);
  if (parts.length === 0) return bad("no parts", 400);

  // 调用 complete，捕获 10025 → 返回明确错误
  try {
    const mpu = await env.DAYDROP_BUCKET.resumeMultipartUpload(body.objectKey, body.uploadId);
    await mpu.complete(parts);
  } catch (e:any) {
    const msg = String(e?.message || "");
    if (msg.includes("10025")) {
      // 立即放弃此次 MPU，避免后台残留
      try {
        const mpu = await env.DAYDROP_BUCKET.resumeMultipartUpload(body.objectKey, body.uploadId);
        await mpu.abort();
      } catch {}
      return bad("parts_not_found_or_mismatch (10025)", 400);
    }
    // 其他异常仍抛出 500（保持原行为）
    return bad("complete_failed", 500);
  }

  const createdAt = Date.now();
  const ttlMs = Number(env.DEFAULT_TTL_SECONDS ? Number(env.DEFAULT_TTL_SECONDS)*1000 : 7*86400000);
  const record: FileRecord = {
    code: body.code,
    objectKey: body.objectKey,
    filename: body.filename,
    contentType: body.contentType,
    size: body.size,
    createdAt,
    expiresAt: createdAt + ttlMs,
    downloads: 0,
    enc: body.enc ?? null
  };

  await env.DAYDROP_KV.put(`code:${body.code}`, JSON.stringify(record), { expiration: Math.floor(record.expiresAt/1000) });
  await env.DAYDROP_KV.put(`obj:${body.objectKey}`, body.code, { expiration: Math.floor(record.expiresAt/1000) });
  await delUploadAuth(env, body.uploadId, body.auth);
  return ok({ ok: true });
}


async function apiMpuAbort(req: Request, env: Env){
  const ip = req.headers.get("CF-Connecting-IP");
  const body = await req.json() as UploadMpuAbortBody;
  if(!body?.objectKey || !body?.uploadId) return bad("missing fields");

  let authorized = false;
  if (await hasUploadAuth(env, body.uploadId, body.auth)) authorized = true;
  else if (await verifyTurnstile(env, body.turnstileToken, ip)) authorized = true;
  if (!authorized) return bad("unauthorized", 401);

  await abortMpu(env, body.objectKey, body.uploadId);
  await delUploadAuth(env, body.uploadId, body.auth);
  return ok({ ok: true });
}

/* ============ 下载：先校验取件码与文件存在性，不存在则清理 KV 并报错 ============ */
async function objectExists(env: Env, key: string): Promise<boolean> {
  try {
    // Cloudflare R2 支持 head；若运行时不支持则 fallback 到 get
    // @ts-ignore
    if (typeof env.DAYDROP_BUCKET.head === "function") {
      // @ts-ignore
      const h = await env.DAYDROP_BUCKET.head(key);
      return !!h;
    }
  } catch {}
  try {
    const obj = await env.DAYDROP_BUCKET.get(key, { range: { offset: 0, length: 1 } });
    if (obj && "body" in obj && obj.body) obj.body.cancel();
    return !!obj;
  } catch { return false; }
}

async function apiDownloadUrl(req: Request, env: Env){
  const ip = req.headers.get("CF-Connecting-IP");
  const body = await req.json() as DownloadUrlBody;
  if(!body?.code) return bad("missing fields");

  let authorized = false, newAuth: string | undefined;
  if (await hasDownloadAuth(env, body.code, body.auth)) authorized = true;
  else if (await verifyTurnstile(env, body.turnstileToken, ip)) { authorized = true; newAuth = makeAuth(); await putDownloadAuth(env, body.code, newAuth); }
  if (!authorized) return bad("unauthorized", 401);

  const rec = await env.DAYDROP_KV.get<FileRecord>(`code:${body.code}`, "json");
  if(!rec) return notfound("invalid code");

  // ✅ 先校验对象是否仍存在；若不存在，清理 KV 并返回错误
  const exists = await objectExists(env, rec.objectKey);
  if (!exists) {
    await env.DAYDROP_KV.delete(`code:${body.code}`);
    await env.DAYDROP_KV.delete(`obj:${rec.objectKey}`);
    return notfound("file missing");
  }
  if(rec.expiresAt < now()) return bad("expired", 410);

  const est = Math.max(0, Math.floor(body.estimatedSeconds || 0));
  const expires = Math.min(24*3600, Math.max(1800, est + 1800));
  const url = await presignUrl(env, "GET", rec.objectKey, expires);

  const resp: DownloadUrlResp = {
    downloadUrl: url.toString(),
    meta: { filename: rec.filename, contentType: rec.contentType, size: rec.size, enc: rec.enc ?? null, supportsRange: true },
    expiresAt: now() + expires*1000,
    auth: newAuth
  };
  return new Response(JSON.stringify(resp), { headers: { ...JSONH, ...corsHeaders(req) } });
}

/* —— 兜底：前端拉 site key —— */
async function apiSiteKey(req: Request, env: Env) {
  return new Response(JSON.stringify({ siteKey: env.TURNSTILE_SITE_KEY || "" }), { headers: { ...JSONH, ...corsHeaders(req) } });
}

function injectTurnstileSiteKey(resp: Response, siteKey: string) {
  const rw = new HTMLRewriter()
    .on('meta[name="turnstile-sitekey"]', { element(el){ el.setAttribute("content", siteKey || ""); } })
    .on("div.cf-turnstile", { element(el){ el.setAttribute("data-sitekey", siteKey || ""); } });
  return rw.transform(resp);
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const p = new URL(req.url).pathname;
    if (req.method === "OPTIONS" && p.startsWith("/api/")) return handleOptions(req);

    if (p === "/api/upload-mpu-init"     && req.method === "POST") return apiMpuInit(req, env);
    if (p === "/api/upload-mpu-presign"  && req.method === "POST") return apiMpuPresign(req, env);
    if (p === "/api/upload-mpu-complete" && req.method === "POST") return apiMpuComplete(req, env);
    if (p === "/api/upload-mpu-abort"    && req.method === "POST") return apiMpuAbort(req, env);
    if (p === "/api/download-url"        && req.method === "POST") return apiDownloadUrl(req, env);
    if (p === "/api/sitekey"             && req.method === "GET")  return apiSiteKey(req, env);

    if (env.ASSETS) {
      const r = await env.ASSETS.fetch(req);
      const ct = r.headers.get("content-type") || "";
      return ct.includes("text/html") ? injectTurnstileSiteKey(r, env.TURNSTILE_SITE_KEY || "") : r;
    }
    return new Response("Not Found", { status: 404 });
  }
} satisfies ExportedHandler<Env>;
