import { $, toast, formatBytes, stepModal, encryptWithCode, copyToClip } from "./app.js";

const fileEl = $("#file");
const encryptChk = $("#encrypt");
const startBtn = $("#start");
const info = $("#info");

let picked;
fileEl.addEventListener("change", () => {
  picked = fileEl.files?.[0];
  if (picked) info.textContent = `${picked.name} · ${formatBytes(picked.size)}`;
});

const PART_SIZE = 8 * 1024 * 1024;
function partCount(b){ return Math.max(1, Math.ceil(b.size / PART_SIZE)); }
function slicePart(b, pn){ const s=(pn-1)*PART_SIZE; const e=Math.min(b.size, s+PART_SIZE); return b.slice(s,e); }

// 统一清洗 ETag：去掉弱校验/引号
function cleanEtag(v){
  return (v || "").trim().replace(/^W\/"/, "").replace(/^W\//, "").replace(/^"|"$/g, "");
}

async function presign(objectKey, uploadId, partNumbers, estimatedSeconds, auth){
  const r = await fetch("/api/upload-mpu-presign", {
    method:"POST", headers:{ "content-type":"application/json" },
    body: JSON.stringify({ objectKey, uploadId, partNumbers, estimatedSeconds, auth })
  }).then(r=>r.json()).catch(()=>({error:"网络异常"}));
  if(!r?.urls) throw new Error(r?.error || "预签名失败");
  return r.urls;
}

startBtn.addEventListener("click", async () => {
  try{
    if(!picked){ toast("请选择文件"); return; }
    const modal = stepModal(); modal.open(); modal.activate(modal.step1);

    // Step1：Turnstile（仅 init 一次）
    let tsToken;
    try { tsToken = await modal.challenge(); }
    catch(e){ modal.close(); return toast(e?.message || "已取消"); }

    // Step2：开始上传
    modal.activate(modal.step2);
    modal.setProgress(1);
    modal.setTip("准备上传…");

    let canceled = false;
    const activeXhrs = new Set();
    modal.onStop(async ()=>{
      canceled = true; activeXhrs.forEach(x=>{ try{x.abort();}catch{} }); modal.setTip("正在取消…");
    });
    modal.onCancel(()=>{ canceled = true; activeXhrs.forEach(x=>{ try{x.abort();}catch{} }); modal.close(); });

    // init
    const estimatedSize = encryptChk.checked ? picked.size + 32 : picked.size;
    const init = await fetch("/api/upload-mpu-init", {
      method:"POST", headers:{ "content-type":"application/json" },
      body: JSON.stringify({
        filename: picked.name, contentType: picked.type || "application/octet-stream",
        size: estimatedSize, turnstileToken: tsToken
      })
    }).then(r=>r.json()).catch(()=>({error:"网络异常"}));
    if(!init?.uploadId){ modal.close(); return toast(init?.error || "创建分片上传失败"); }

    const { code, objectKey, uploadId, auth } = init;

    // 可选：端到端加密
    let payloadBlob = picked, encMeta = null;
    if (encryptChk.checked) {
      modal.setTip("本地加密中…");
      const enc = await encryptWithCode(picked, code);
      payloadBlob = enc.blob; encMeta = enc.meta;
    }

    const totalParts = partCount(payloadBlob);
    const CONCURRENCY = Math.min(6, Math.max(2, (navigator.hardwareConcurrency||4) >> 1));
    let completedBytes = 0; let lastSpeed = 1_000_000;
    const inflightMap = new Map(); const parts = new Array(totalParts); // {partNumber, etag}
    const started = Date.now(); const queue = Array.from({length: totalParts}, (_,i)=>i+1);

    function progressUpdate(){
      const running = Array.from(inflightMap.values()).reduce((a,b)=>a+b,0);
      const done = completedBytes + running;
      const p = (done / payloadBlob.size) * 100;
      modal.setProgress(p);
      const elapsed=(Date.now()-started)/1000; const speed=done/Math.max(1,elapsed);
      const remain=Math.max(0,(payloadBlob.size-done)/Math.max(1,speed));
      const text = remain>3600?`${(remain/3600).toFixed(1)}h`: remain>60?`${(remain/60).toFixed(1)}m`:`${remain.toFixed(0)}s`;
      lastSpeed = Math.max(1, speed);
      modal.setTip(`${p.toFixed(1)}% · 约 ${text}`);
    }

    async function uploadOne(pn){
      if (canceled) throw new Error("cancelled");
      const remain = payloadBlob.size - ((pn-1)*PART_SIZE);
      const est = Math.ceil(remain / Math.max(1, lastSpeed));
      const [{ url }] = await presign(objectKey, uploadId, [pn], est, auth);

      const blob = slicePart(payloadBlob, pn);
      const xhr = new XMLHttpRequest(); activeXhrs.add(xhr);
      const task = new Promise((resolve,reject)=>{
        xhr.onload = ()=> (xhr.status>=200 && xhr.status<300) ? resolve(null) : reject(new Error("上传失败"));
        xhr.onerror = ()=> reject(new Error("网络错误"));
        xhr.onabort = ()=> reject(new Error("cancelled"));
      });
      xhr.upload.onprogress = (e)=>{ if(e.lengthComputable){ inflightMap.set(pn, e.loaded); progressUpdate(); } };
      xhr.open("PUT", url, true);
      // 不强制设置 content-type，避免与签名头不一致
      xhr.send(blob);
      await task;
      activeXhrs.delete(xhr);

      const hdr = xhr.getResponseHeader("ETag") || xhr.getResponseHeader("etag") || "";
      const etag = cleanEtag(hdr);
      if (!etag) throw new Error("缺少 ETag，可能被浏览器拦截或网络异常");
      inflightMap.delete(pn);
      completedBytes += blob.size;
      parts[pn-1] = { partNumber: pn, etag };
      progressUpdate();
    }

    try{
      const workers = new Array(CONCURRENCY).fill(0).map(async ()=>{
        while (queue.length && !canceled){
          const pn = queue.shift();
          let tries = 0;
          for(;;){
            try{ await uploadOne(pn); break; }
            catch(e){ if(canceled) throw e; if(++tries >= 3) throw e; await new Promise(r=>setTimeout(r, 800)); }
          }
        }
      });
      await Promise.all(workers);
      if (canceled) throw new Error("cancelled");
    }catch(e){
      // 失败：清理 MPU
      try{ await fetch("/api/upload-mpu-abort", {
        method:"POST", headers:{ "content-type":"application/json" },
        body: JSON.stringify({ objectKey, uploadId, auth })
      }); }catch{}
      modal.close(); return toast(e.message || "上传失败");
    }

    // 合并前校验：必须每个分片都拿到非空 ETag
    const missing = parts.findIndex(p => !p || !p.etag);
    if (missing !== -1) {
      try{ await fetch("/api/upload-mpu-abort", {
        method:"POST", headers:{ "content-type":"application/json" },
        body: JSON.stringify({ objectKey, uploadId, auth })
      }); }catch{}
      modal.close();
      return toast(`合并失败：第 ${missing+1} 片缺少 ETag，请重试上传`);
    }

    // 合并
    modal.setTip("合并分片…");
    const fin = await fetch("/api/upload-mpu-complete", {
      method:"POST", headers:{ "content-type":"application/json" },
      body: JSON.stringify({
        objectKey, uploadId, parts, code,
        filename: picked.name, contentType: picked.type || "application/octet-stream",
        size: payloadBlob.size, enc: encMeta, auth
      })
    }).then(async r => {
      const j = await r.json().catch(()=>({}));
      if (!r.ok) throw j?.error ? new Error(j.error) : new Error("合并失败");
      return j;
    }).catch(async (e) => {
      // 典型：10025 分片不匹配/缺失 → 主动 abort
      try{ await fetch("/api/upload-mpu-abort", {
        method:"POST", headers:{ "content-type":"application/json" },
        body: JSON.stringify({ objectKey, uploadId, auth })
      }); }catch{}
      throw e;
    });

    if(!fin?.ok){ modal.close(); return toast(fin?.error || "合并失败"); }

    // Step3：显示取件码
    modal.activate(modal.step3);
    $("#modal-done-title").textContent = "上传完成";
    $("#modal-code-wrap").classList.remove("hidden");
    $("#modal-code").textContent = code;
    $("#modal-copy").onclick = ()=>copyToClip(code);
  }catch(e){
    console.error(e); toast(e.message || "出错了");
  }
});
