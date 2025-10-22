# DayDrop / 临时文件（Cloudflare Pages + R2 + KV + Turnstile）

- 6 位数字口令，Turnstile 验证
- R2 保存对象，**1 天后自动删除**（建议在 R2 设置 prefix=tmp/ 的 1 day 生命周期）
- 总用量限制：默认 5GiB（`QUOTA_BYTES` 可改）
- 上传可备注；取回后流式下载

## 部署（通过 GitHub 导入到 Pages）
1. 推到 GitHub。
2. Cloudflare Pages → Connect to Git → 选择仓库。
3. Build：
   - Framework：None
   - Command：None
   - Output：`public`
4. **Functions / Bindings（Production & Preview 都要配）**
   - R2：`TEMP_BUCKET`
   - KV：`TEMP_KV`
   - Env：`TURNSTILE_SITE_KEY`、`TURNSTILE_SECRET`、`QUOTA_BYTES=5368709120`、`ENVIRONMENT=production|preview`
5. R2 → Lifecycle：`prefix=tmp/`，`expire=1 day`（推荐）。

> 若面板提示“此项目绑定由 wrangler.toml 管理”，请从仓库移除 `pages_build_output_dir` 或把 `wrangler.toml` 改名为 `wrangler.local.toml` 并重发版。

## 运行自检
访问 `/api/health`，若 `ok: true` 表示绑定齐全。

## 使用
- `/` 取回：输入 6 位口令 → 通过验证 → 下载
- `/upload.html` 上传：返回 6 位口令（可一键复制）
- 加 `?bg=off` 关闭随机壁纸，或 `?bg=<url>` 指定自定义壁纸

## 开发
```bash
npx wrangler pages dev public --config wrangler.local.toml
