// ===== 基础工具 =====
export const $ = (q) => document.querySelector(q);
export function toast(msg, time = 2000) {
  const t = $(".toast") || (() => {
    const x = document.createElement("div");
    x.className = "toast"; document.body.appendChild(x); return x;
  })();
  t.textContent = msg; t.classList.add("show");
  setTimeout(()=>t.classList.remove("show"), time);
}
export function formatBytes(n){ if(!Number.isFinite(n))return"-"; const u=["B","KB","MB","GB","TB"];let i=0;while(n>=1024&&i<u.length-1){n/=1024;i++}return `${n.toFixed(n>=100?0:n>=10?1:2)} ${u[i]}`; }

// ===== SiteKey 兜底 =====
let SITE_KEY = document.querySelector('meta[name="turnstile-sitekey"]')?.content || "";
export async function ensureSiteKey(){
  if (SITE_KEY && SITE_KEY !== "%TURNSTILE_SITE_KEY%") return SITE_KEY;
  try {
    const r = await fetch("/api/sitekey"); const j = await r.json();
    if (j?.siteKey) SITE_KEY = j.siteKey;
  } catch {}
  return SITE_KEY;
}

// ===== Turnstile 可靠加载 =====
function injectTurnstileScript(){
  return new Promise((resolve,reject)=>{
    const old = document.querySelector('script[data-ts]'); if (old) old.remove();
    const s = document.createElement("script");
    s.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?onload=__ts_onload&render=explicit#"+Date.now();
    s.async = true; s.defer = true; s.setAttribute("data-ts","1");
    window.__ts_onload = ()=>resolve();
    s.onerror = ()=>reject(new Error("验证脚本加载失败"));
    document.head.appendChild(s);
  });
}
async function readyTurnstile(timeout=8000){
  if (window.turnstile) { try{ await new Promise(r=>window.turnstile.ready(r)); }catch{} return true; }
  return await new Promise((res)=>{ let t=0; const it=setInterval(()=>{ t+=200; if(window.turnstile){ clearInterval(it); try{window.turnstile.ready(()=>res(true));}catch{res(true);} } if(t>=timeout){clearInterval(it); res(false);} },200); });
}
async function ensureTurnstileLoaded(){
  if (await readyTurnstile()) return true;
  try { await injectTurnstileScript(); } catch {}
  return await readyTurnstile(10000);
}

// ===== 自动注入“三步模态”DOM（若 HTML 中缺失也能工作） =====
const MODAL_HTML = `
  <div class="modal-card">
    <!-- Step1 验证 -->
    <div id="step1" class="step active">
      <div class="modal-title">请完成人机验证</div>
      <div id="ts-container"></div>
      <div class="modal-error" id="ts-error"></div>
      <div class="modal-hint" id="ts-hint">若长时间不出现验证，请点击“刷新验证”或检查脚本拦截扩展。</div>
      <div class="modal-actions">
        <button id="ts-reload" class="btn">刷新验证</button>
        <button id="modal-cancel" class="btn">取消</button>
      </div>
    </div>
    <!-- Step2 进度 -->
    <div id="step2" class="step">
      <div class="modal-title" id="modal-title">处理中…</div>
      <div class="progress"><i id="modal-bar"></i></div>
      <div class="small" id="modal-tip"></div>
      <div class="modal-actions">
        <button id="modal-stop" class="btn">取消</button>
      </div>
    </div>
    <!-- Step3 完成 -->
    <div id="step3" class="step">
      <div class="modal-title" id="modal-done-title">完成</div>
      <div class="small hidden" id="modal-code-wrap">取件码：<kbd class="code" id="modal-code">——</kbd> <a id="modal-copy" href="javascript:void(0)">复制</a></div>
      <div class="modal-actions" style="justify-content:flex-end">
        <button id="modal-close" class="btn primary">关闭</button>
      </div>
    </div>
  </div>`;
function ensureModal(){
  let m = $("#modal");
  if (!m) { m = document.createElement("div"); m.id = "modal"; m.className = "modal"; document.body.appendChild(m); }
  if (!m.querySelector(".modal-card")) m.innerHTML = MODAL_HTML;
  return m;
}

// ===== 统一步骤模态控制 =====
export function stepModal(){
  const modal = ensureModal();
  const s1 = $('#step1'), s2 = $('#step2'), s3 = $('#step3');
  const bar = $('#modal-bar'), tip = $('#modal-tip');
  const err = $('#ts-error'), hint = $('#ts-hint');
  const btnReload = $('#ts-reload'), btnCancel = $('#modal-cancel');
  const btnStop   = $('#modal-stop'), btnClose = $('#modal-close');

  let onCancel = null, onStop = null, onClose = null;

  function open(){ modal.classList.add("show"); }
  function close(){ modal.classList.remove("show"); }
  function activate(step){ [s1,s2,s3].forEach(el=>el.classList.remove("active")); step.classList.add("active"); }
  function setProgress(p){ bar.style.width = `${Math.max(1, Math.min(100, p))}%`; }
  function setTip(text){ tip.textContent = text || ""; }

  async function challenge(){
    err.textContent = ""; hint.classList.remove("hidden");
    const siteKey = await ensureSiteKey();
    if (!siteKey) { err.textContent = "未配置 TURNSTILE_SITE_KEY，请到 Worker 变量设置。"; throw new Error("sitekey missing"); }
    const ok = await ensureTurnstileLoaded();
    if (!ok) { err.textContent = "无法加载验证脚本，请“刷新验证”或检查拦截。"; throw new Error("script load failed"); }

    $('#ts-container').innerHTML = "";
    return new Promise((resolve, reject)=>{
      try{
        const id = window.turnstile.render($('#ts-container'), {
          sitekey: siteKey,
          callback: (token)=>{ resolve(token); },
          "error-callback": ()=>{ err.textContent="验证遇到错误，请刷新重试"; },
          "expired-callback": ()=>{ err.textContent="验证已过期，请刷新重试"; },
          theme: "auto"
        });
        btnReload.onclick = async ()=>{ err.textContent=""; $('#ts-container').innerHTML=""; try{ await challenge().then(resolve).catch(reject);}catch{} };
        btnCancel.onclick = ()=>{ reject(new Error("cancelled")); };
      }catch(e){ err.textContent="渲染失败，请刷新验证"; reject(e); }
    });
  }

  btnClose.onclick = ()=>{ close(); onClose?.(); };
  btnStop.onclick  = ()=> onStop?.();
  btnCancel.onclick= ()=> onCancel?.();

  return { open, close, activate, setProgress, setTip, step1:s1, step2:s2, step3:s3,
           onCancel:(fn)=>onCancel=fn, onStop:(fn)=>onStop=fn, onClose:(fn)=>onClose=fn, challenge };
}

// ===== 取件码=密钥（浏览器端加解密） =====
async function getKeyFromPass(pass, saltB64, iterations=250000){
  const enc=new TextEncoder(); const salt=saltB64?Uint8Array.from(atob(saltB64),c=>c.charCodeAt(0)):crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial=await crypto.subtle.importKey("raw",enc.encode(pass),"PBKDF2",false,["deriveKey"]);
  const key=await crypto.subtle.deriveKey({name:"PBKDF2",hash:"SHA-256",salt,iterations},keyMaterial,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
  return { key, salt };
}
export async function encryptWithCode(file, code){
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const { key, salt } = await getKeyFromPass(code, null);
  const buf=await file.arrayBuffer(); const ct=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,buf);
  return {
    blob:new Blob([ct],{type:file.type||"application/octet-stream"}),
    meta:{ method:"AES-GCM", saltB64:btoa(String.fromCharCode(...new Uint8Array(salt))), ivB64:btoa(String.fromCharCode(...iv)), iterations:250000 }
  };
}
export async function decryptWithCode(blob, code, encMeta){
  const { method, saltB64, ivB64, iterations } = encMeta; if(method!=="AES-GCM") throw new Error("未知加密算法");
  const enc=new TextEncoder(); const salt=Uint8Array.from(atob(saltB64),c=>c.charCodeAt(0));
  const keyMaterial=await crypto.subtle.importKey("raw",enc.encode(code),"PBKDF2",false,["deriveKey"]);
  const key=await crypto.subtle.deriveKey({name:"PBKDF2",hash:"SHA-256",salt,iterations},keyMaterial,{name:"AES-GCM",length:256},false,["decrypt"]);
  const iv=Uint8Array.from(atob(ivB64),c=>c.charCodeAt(0));
  const buf=await blob.arrayBuffer(); const pt=await crypto.subtle.decrypt({name:"AES-GCM",iv},key,buf);
  return new Blob([pt]);
}

// 方便外部用
export function copyToClip(text){ return navigator.clipboard.writeText(text).then(()=>toast("已复制到剪贴板")); }
