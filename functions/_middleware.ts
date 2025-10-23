// functions/_middleware.ts
// -------------------------------------------------------------
// 访问控制中间件（Cloudflare Pages Functions）
// - 地区封禁：451（RFC 7725 合规；优先级最高；内联渲染 HTML）
// - ASN 黑名单：403
// - UA 白名单：仅放行“国际浏览器”（桌面+手机：Chrome/Chromium、Edge、Firefox、Safari、Opera）
//   其余一律 403（命令行/SDK/国产/空 UA 等）
//
// 诊断：通过响应头 X-Policy-Decision / X-Blocked-Country 辅助排查 itdog 测试差异
// -------------------------------------------------------------

type Env = {
  ENVIRONMENT?: string; // "production" | "preview" | "local"
  FORCE_BLOCK_TEST?: string; // "1" 时强制启用拦截，便于 itdog/灰度测试
};

/** 你的说明页（请替换为实际地址） */
const LEGAL_LINK_CN = 'https://www.gov.cn/gongbao/content/2000/content_60531.htm';
const LEGAL_LINK_GENERIC = 'https://www.gov.cn/zhengce/2021-12/25/content_5712883.htm';

/** 地区与 ASN 黑名单 */
const BLOCKED_COUNTRIES = new Set(['CN', 'HK', 'MO']);
const BLOCKED_ASNS = new Set<number>([
  // 阿里
  34947,37963,45102,45103,45104,59028,59051,59052,59053,59054,59055,134963,211914,
  // 腾讯
  45090,132203,132591,133478,137876,
  // 华为
  55990,61348,63655,63727,131444,136907,139124,139144,140723,141180,149167,200756,206204,206798,265443,269939,
  // 百度云
  38365,38627,45076,45085,55967,63288,63728,63729,131138,131139,131140,131141,133746,199506,
  // 优刻得
  9786,59077,135377
]);

/** 可选：是否把 Samsung Internet 视为国际浏览器（默认 false => 拒绝） */
const ALLOW_SAMSUNG_INTERNET = false;

/** —— 国际浏览器允许列表 ————————————————————————————— */
function isInternationalBrowserUA(ua: string): boolean {
  if (!ua) return false;
  if (isDomesticOrCustomizedUA(ua)) return false; // 先行排除国产/容器/CLI

  ua = ua.toLowerCase();

  const isEdge = /\bedg(?:e|ios|a)?\/\d+/i.test(ua);
  const isChromium = /\bchromium\/\d+/i.test(ua);
  const isChromeLike =
    (/\b(?:chrome|crios|brave|vivaldi)\/\d+/i.test(ua) || isChromium) &&
    !/\bedg(?:e|ios|a)?\/\d+/i.test(ua) &&
    !/\b(?:opr|opios)\/\d+/i.test(ua);
  const isOpera = /\b(?:opr|opios)\/\d+/i.test(ua);
  const isFirefox = /\bfirefox\/\d+/i.test(ua) || /\bfxios\/\d+/i.test(ua);
  const isSafari =
    /\bversion\/\d+(?:\.\d+)*.*\bsafari\/\d+/i.test(ua) &&
    !/\b(?:chrome|crios|edg\w*|opr|opios)\//i.test(ua);
  const isSamsung = /\bsamsungbrowser\/\d+/i.test(ua);

  return (
    isEdge || isChromeLike || isOpera || isFirefox || isSafari ||
    (ALLOW_SAMSUNG_INTERNET && isSamsung)
  );
}

/** —— 国产/定制/容器/CLI UA 显式拒绝（可按需补充） ———————————— */
function isDomesticOrCustomizedUA(ua: string): boolean {
  if (!ua) return true; // 空 UA 直接拒绝
  const s = ua.toLowerCase();

  const patterns = [
    // 国产通用/大厂
    /\bucbrowser\/|\buc\s?applewebkit/i,
    /\bqqbrowser\/|\bmqqbrowser\/|\bqq\/\d/i,
    /\b2345explorer\/|\bmaxthon\/|\btheworld\/|\blbbrowser\/|\bmetasr\/|\bse\s?360|360se|360ee/i,
    /\bsogou(mobile)?browser\/|\bmetasr/i,
    /\bbaiduboxapp\/|\bbaidubrowser\/|\bbdapp/i,
    // OEM/ROM
    /\bmiuibrowser\/|\bxiaomi\/|\bmi\s?browser/i,
    /\bhuaweibrowser\/|\bhonorbrowser\/|\bpetal(search)?\/|\bharmony/i,
    /\boppobrowser\/|\bheytapbrowser\/|\brealmebrowser\//i,
    /\bvivobrowser\/|\bvivo\w*browser\//i,
    /\bmeizubrowser\/|\bflyme/i,
    /\boneplus(?:browser)?\//i,
    /\bztebrowser\/|\bnubia\w*browser\//i,
    /\bhisensebrowser\//i,
    // 容器/聚合
    /\bquark(?:browser)?\/|\baliapp\(/i,
    /\btoutiaomicroapp\/|\bbytedance|aweme|douyin/i,
    /\bmicromessenger\/|\bwxwork\/|\bwechatdevtools\//i,
    // 命令行/SDK
    /\bcurl\/|\bwget\/|\bhttpie\/|\bpostman(?:runtime|agent)?\/|\baxios\/|\bpython-requests\/|\bgo-http-client\/|\bokhttp\/|\bjava\/|\bnode-fetch\//i
  ];

  return patterns.some((re) => re.test(s));
}

/** —— 生成 451（内联 HTML 渲染） ——————————————————————— */
function render451HTML(linkHref: string, country?: string): string {
  const title = '451 Unavailable For Legal Reasons';
  const legalCN = `
    <section>
      <h2>无法访问（法律原因）</h2>
      <p>根据适用法律法规与监管要求，来自您所在地区的访问已被限制。</p>
      <ul>
        <li>执行主体：本站运营方（详见“说明链接”）。</li>
        <li>法律依据：参见《中华人民共和国网络安全法》第1、10、50、58条等。</li>
        <li>如需进一步了解或申诉，请访问“说明链接”。</li>
      </ul>
    </section>`;
  const legalEN = `
    <section>
      <h2>Access Restricted for Legal Reasons</h2>
      <p>Your access has been denied due to applicable laws and regulatory requirements.</p>
      <ul>
        <li>Blocking Entity: Site Operator (see "More info").</li>
        <li>Legal Basis: See references on the info page.</li>
        <li>For details or appeals, follow the "More info" link.</li>
      </ul>
    </section>`;

  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta http-equiv="x-ua-compatible" content="ie=edge">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<style>
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,Apple Color Emoji,Segoe UI Emoji;
       margin:0;padding:2rem;background:#0b1220;color:#e6ecff;}
  main{max-width:820px;margin:0 auto;}
  .card{background:#121a2b;border:1px solid #1f2a44;border-radius:16px;padding:24px;box-shadow:0 6px 30px rgba(0,0,0,.35)}
  h1{font-size:1.75rem;margin:0 0 .5rem}
  h2{font-size:1.125rem;margin:1.25rem 0 .5rem;color:#b9cffb}
  p,li{line-height:1.6}
  a{color:#9ec1ff}
  .muted{opacity:.8}
  .kvs{display:flex;gap:1rem;flex-wrap:wrap;margin:.75rem 0}
  .kv{background:#0f1626;border:1px solid #1f2a44;border-radius:10px;padding:.5rem .75rem;font-size:.9rem}
</style>
</head>
<body>
<main>
  <div class="card">
    <h1>${title}</h1>
    <p class="muted">Unavailable For Legal Reasons</p>
    <div class="kvs">
      ${country ? `<div class="kv">Country: ${country}</div>` : ``}
      <div class="kv">Status: 451</div>
    </div>
    ${legalCN}
    ${legalEN}
    <p><a href="${linkHref}" rel="blocked-by">说明链接 / More info</a></p>
  </div>
</main>
</body>
</html>`;
}

/** 451 响应（RFC 7725 合规，内联 HTML） */
function respond451Inline(linkHref: string, country?: string, method?: string) {
  const headers: HeadersInit = {
    'Content-Type': 'text/html; charset=utf-8',
    'Link': `<${linkHref}>; rel="blocked-by"`,
    'Vary': 'Accept, Accept-Encoding, cf-ipcountry',
    'Cache-Control': 'no-store',
    ...(country ? { 'X-Blocked-Country': country } : {}),
    'X-Policy-Decision': '451-country'
  };

  // HEAD 请求返回空体但状态依旧 451
  if (method && method.toUpperCase() === 'HEAD') {
    return new Response(null, { status: 451, headers });
  }

  const html = render451HTML(linkHref, country);
  return new Response(html, { status: 451, headers });
}

function txt(body: string, status = 403, extra: HeadersInit = {}) {
  return new Response(body + '\n', {
    status,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store',
      'Vary': 'User-Agent, Accept, Accept-Encoding, cf-ipcountry, cf-asn',
      'X-Policy-Decision': status === 403 ? '403' : String(status),
      ...extra
    }
  });
}

export const onRequest: PagesFunction<Env> = async (ctx) => {
  const { request, env } = ctx;

  // 非生产环境可放行；若设置 FORCE_BLOCK_TEST=1 则强制启用策略（便于 itdog 测试）
  const isProduction = env.ENVIRONMENT === 'production' || env.FORCE_BLOCK_TEST === '1';
  if (!isProduction) {
    return ctx.next();
  }

  // 调试开关：?debug=1 放行
  const url = new URL(request.url);
  if (url.searchParams.get('debug') === '1') return ctx.next();

  // —— 地理信息（优先 cf.country，回退 CF-IPCountry 头） ——
  const cf: any = (request as any).cf || {};
  const headerCountry = request.headers.get('CF-IPCountry') || undefined;
  const country = (cf.country as string | undefined) || headerCountry;
  const asn = Number(cf.asn);

  // 1) 地区封禁 → 451（优先级最高，内联渲染）
  if (country && BLOCKED_COUNTRIES.has(country)) {
    const link = country === 'CN' || country === 'HK' || country === 'MO'
      ? LEGAL_LINK_CN
      : LEGAL_LINK_GENERIC;
    return respond451Inline(link, country, request.method);
  }

  // 2) ASN 黑名单 → 403
  if (Number.isFinite(asn) && BLOCKED_ASNS.has(asn)) {
    return txt('Forbidden (ASN blocked)', 403, { 'X-Blocked-ASN': String(asn) });
  }

  // 3) UA 白名单（仅国际浏览器）→ 通过；其余一律 403
  const ua = request.headers.get('User-Agent') || '';
  if (!isInternationalBrowserUA(ua)) {
    return txt('Forbidden (browser not allowed)', 403, { 'X-UA': ua.slice(0, 128) });
  }

  // 放行其余请求
  return ctx.next();
};
