## 部署到 Cloudflare Pages（GitHub）

1. Cloudflare Dashboard → Workers & Pages → Create → Pages → Connect to Git → 选仓库
2. Build：Framework=None；Command=None；Output=`public`
3. Functions：开启；绑定 R2=`TEMP_BUCKET`、KV=`TEMP_KV`
4. Env：`TURNSTILE_SITE_KEY`、`TURNSTILE_SECRET`、`QUOTA_BYTES=5368709120`、`ENVIRONMENT=(production|preview)`
5. R2 生命周期：`prefix=tmp/`，`Expire=1 day`
