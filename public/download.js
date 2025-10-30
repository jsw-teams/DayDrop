import { $, toast, stepModal, decryptWithCode } from "./app.js";

const codeEl = $("#code-input");
const fetchBtn = $("#fetch");
let dlAuth = null; // 下载会话（首验后由后端下发）

function eta(done, total, startedAt){
  const elapsed=(Date.now()-startedAt)/1000;
  const speed=done/Math.max(1,elapsed);
  const remain=Math.max(0,(total-done)/Math.max(1,speed));
  const text = remain>3600?`${(remain/3600).toFixed(1)}h`: remain>60?`${(remain/60).toFixed(1)}m`:`${remain.toFixed(0)}s`;
  return { speed, text };
}
function setBar(modal, p){ modal.setProgress(Math.min(100, Math.max(1, p))); }

async function getSigned(code, estimatedSeconds, opts){
  const payload = dlAuth
    ? { code, estimatedSeconds, auth: dlAuth }
    : { code, estimatedSeconds, turnstileToken: opts.ts };
  const r = await fetch("/api/download-url", {
    method:"POST", headers:{ "content-type":"application/json" },
    body: JSON.stringify(payload)
  }).then(r=>r.json()).catch(()=>({error:"网络异常"}));
  if(!r?.downloadUrl) throw new Error(r?.error || "无效取件码或文件不存在");
  if (r.auth) dlAuth = r.auth; // 首次验证后颁发的会话 token
  return r;
}

fetchBtn.addEventListener("click", async () => {
  const code = codeEl.value.trim().toUpperCase();
  if(!code) return toast("请输入取件码");

  try{
    const modal = stepModal(); modal.open(); modal.activate(modal.step1);

    // 1) Turnstile（仅第一次需要）
    let tsToken;
    try { tsToken = await modal.challenge(); }
    catch(e){ modal.close(); return toast(e?.message || "已取消"); }

    // 2) 先检查取件码/文件存在
    modal.activate(modal.step2);
    $("#modal-title").textContent = "检查取件码…";
    setBar(modal, 8);
    modal.setTip("正在确认文件是否存在…");

    let signed;
    try {
      signed = await getSigned(code, 60, { ts: tsToken }); // 不存在/过期会抛错
    } catch (e) {
      modal.close();
      return toast(e.message || "取件码无效或文件不存在");
    }

    // 3) 真正下载（必要时续签）→ 解密 → 直接关闭模态
    $("#modal-title").textContent = "正在下载…";
    modal.setTip("开始下载…");

    let controller = new AbortController();
    modal.onStop(()=>{ try{ controller.abort(); }catch{} modal.setTip("正在取消…"); });
    modal.onCancel(()=>{ try{ controller.abort(); }catch{} modal.close(); });

    const { meta } = signed;
    let received = 0; const total = meta.size; const started = Date.now(); const chunks = [];

    while (received < total) {
      controller = new AbortController();
      const headers = received > 0 ? { Range: `bytes=${received}-` } : {};
      const resp = await fetch(signed.downloadUrl, { headers, signal: controller.signal });
      if (!(resp.ok || resp.status === 206) || !resp.body) throw new Error("下载失败");
      const reader = resp.body.getReader();

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
        received += value.byteLength;
        const p = (received / Math.max(1,total)) * 100;
        setBar(modal, p);
        const { text } = eta(received, total, started);
        modal.setTip(`${p.toFixed(1)}% · 约 ${text}`);
      }

      if (received < total) {
        const remaining = total - received;
        const { speed } = eta(received, total, started);
        signed = await getSigned(code, Math.ceil(remaining / Math.max(1, speed)), {}); // 续签用 dlAuth
      }
    }

    let blob = new Blob(chunks, { type: meta.contentType || "application/octet-stream" });
    if (meta?.enc) {
      $("#modal-title").textContent = "解密中…";
      modal.setTip("正在本地解密（不会上传数据）");
      try { blob = await decryptWithCode(blob, code, meta.enc); }
      catch { modal.close(); return toast("解密失败：取件码不正确或数据损坏"); }
    }

    // 触发浏览器保存
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = meta.filename || "download";
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(()=>URL.revokeObjectURL(url), 10_000);

    // ✅ 结束：不展示 Step3，直接关闭 + 提示
    modal.close();
    toast("下载完成");
  }catch(e){
    console.error(e);
    toast(e.message || "出错了");
  }
});
