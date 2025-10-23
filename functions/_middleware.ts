// functions/_middleware.ts
// -------------------------------------------------------------
// 访问控制中间件（Cloudflare Pages Functions）
// - 地区封禁：451（RFC 7725 合规；优先级最高；内联渲染）
// - ASN 黑名单：403
// - UA 白名单：仅允许国际浏览器（Chrome/Chromium、Edge、Firefox、Safari、Opera）
// - 真实浏览器信号校验：要求常见 Client Hints / Fetch Metadata 等头；否则 403
// - 无调试/本地放行：策略默认生效
//
// 法律条文参考（gov.cn 官方页）：
// • 《互联网信息服务管理办法》：https://www.gov.cn/gongbao/content/2000/content_60531.htm
// • 《公安机关互联网安全监督检查规定》：https://www.gov.cn/zhengce/2021-12/25/content_5712883.htm
// -------------------------------------------------------------

type Env = Record<string, never>;

const LAW_LINK_IISMB = 'https://www.gov.cn/gongbao/content/2000/content_60531.htm';
const LAW_LINK_PSP = 'https://www.gov.cn/zhengce/2021-12/25/content_5712883.htm';

const BLOCKED_COUNTRIES = new Set(['CN', 'HK', 'MO']);
const BLOCKED_ASNS = new Set<number>([
  34947,37963,45102,45103,45104,59028,59051,59052,59053,59054,59055,134963,211914,
  45090,132203,132591,133478,137876,
  55990,61348,63655,63727,131444,136907,139124,139144,140723,141180,149167,200756,
  206204,206798,265443,269939,
  38365,38627,45076,45085,55967,63288,63728,63729,131138,131139,131140,131141,
  133746,199506,
  9786,59077,135377
]);

const ALLOW_SAMSUNG_INTERNET = false;

/** —— 国际浏览器允许列表（先过 UA，再验真实浏览器信号） ———————— */
function isInternationalBrowserUA(ua: string): boolean {
  if (!ua) return false;
  if (isDomesticOrCustomizedUA(ua)) return false;
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
    // 国产/聚合
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
    // 容器/平台内
    /\bquark(?:browser)?\/|\baliapp\(/i,
    /\btoutiaomicroapp\/|\bbytedance|aweme|douyin/i,
    /\bmicromessenger\/|\bwxwork\/|\bwechatdevtools\//i,
    // 命令行/SDK
    /\bcurl\/|\bwget\/|\bhttpie\/|\bpostman(?:runtime|agent)?\/|\baxios\/|\bpython-requests\/|\bgo-http-client\/|\bokhttp\/|\bjava\/|\bnode-fetch\//i
  ];
  return patterns.some((re) => re.test(s));
}

/** —— 看起来像“真实浏览器”的请求信号（对抗 itdog/脚本伪装） ———— */
function isLikelyNavigation(req: Request): boolean {
  const accept = req.headers.get('accept') || '';
  const dest = (req.headers.get('sec-fetch-dest') || '').toLowerCase();
  const isHtmlAccept = accept.includes('text/html');
  const isDocDest = dest === 'document' || dest === 'empty';
  const isRoot = new URL(req.url).pathname === '/';
  return isHtmlAccept || isDocDest || isRoot;
}

function hasBrowserSignals(req: Request): boolean {
  const h = req.headers;

  // 基本要求：Accept + Accept-Language + User-Agent 存在
  const accept = h.get('accept');
  const lang = h.get('accept-language');
  const ua = h.get('user-agent');
  if (!accept || !lang || !ua) return false;

  // Client Hints（Chromium 系列普遍具备；Firefox/Safari 可能较少，但会有 fetch 元数据）
  const chUa = h.get('sec-ch-ua');
  const chMobile = h.get('sec-ch-ua-mobile');
  const chPlat = h.get('sec-ch-ua-platform');

  // Fetch Metadata（Chromium 系列常见；Firefox/Safari 可能缺）
  const sfSite = h.get('sec-fetch-site');       // 'none' | 'same-origin' | 'cross-site'
  const sfMode = h.get('sec-fetch-mode');       // 'navigate' | 'no-cors' | ...
  const sfDest = h.get('sec-fetch-dest');       // 'document' | 'empty' | ...
  const uir = h.get('upgrade-insecure-requests'); // '1' 多见于顶级导航

  // 规则：导航/HTML 请求更严格；非导航请求略宽松
  const nav = isLikelyNavigation(req);

  const hasAnyClientHints = !!(chUa || chMobile || chPlat);
  const hasFetchMeta = !!(sfSite && sfMode && sfDest);

  // 1) 导航：必须具备 Fetch Metadata 且 uir=1（符合大多数真实浏览器）
  if (nav) {
    if (!hasFetchMeta) return false;
    if (uir !== '1') return false;
    // sec-fetch-mode 应为 navigate，dest 为 document/empty 较合理
    if (sfMode && sfMode !== 'navigate') return false;
    if (sfDest && !(sfDest === 'document' || sfDest === 'empty')) return false;
    return true;
  }

  // 2) 非导航：至少具备 Client Hints 或 Fetch Metadata 之一
  if (!hasAnyClientHints && !hasFetchMeta) return false;

  return true;
}

/** —— 451 内联页面 ————————————————————————————— */
function render451HTML(country?: string): string {
  const title = '451 Unavailable For Legal Reasons';
  const legalCN = `
    <section>
      <h2>无法访问（法律原因）</h2>
      <p>根据适用法律法规与监管要求，来自您所在地区的访问已被限制。</p>
      <div style="padding:.75rem 1rem;border-left:3px solid #304a7a;background:#0f1626">
        <p><strong>《互联网信息服务管理办法》</strong>
        (<a href="${LAW_LINK_IISMB}" target="_blank" rel="noopener">gov.cn</a>) — 互联网信息服务提供者应依法履行管理义务；禁止信息应依法处理，接受部门监督检查。</p>
        <p><strong>《公安机关互联网安全监督检查规定》</strong>
        (<a href="${LAW_LINK_PSP}" target="_blank" rel="noopener">gov.cn</a>) — 公安机关依法对互联网服务提供者开展安全监督检查；对违法信息或安全隐患可要求整改或采取措施。</p>
      </div>
    </section>`;
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>${title}</title>
<style>
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;background:#0b1220;color:#e6ecff;padding:2rem}
  main{max-width:820px;margin:auto}
  .card{background:#121a2b;border:1px solid #1f2a44;border-radius:16px;padding:24px}
  a{color:#9ec1ff}
</style>
</head>
<body>
<main>
  <div class="card">
    <h1>${title}</h1>
    <p>Unavailable For Legal Reasons</p>
    <p>Country: ${country || 'N/A'}</p>
    ${legalCN}
  </div>
</main>
</body>
</html>`;
}

function respond451Inline(country?: string, method?: string) {
  const headers: HeadersInit = {
    'Content-Type': 'text/html; charset=utf-8',
    'Link': `<${LAW_LINK_IISMB}>; rel="related", <${LAW_LINK_PSP}>; rel="related"`,
    'Cache-Control': 'no-store',
    'Vary': 'User-Agent, Accept, Accept-Language, Sec-CH-UA, Sec-CH-UA-Mobile, Sec-CH-UA-Platform, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, CF-IPCountry, cf-ipcountry, cf-asn',
    'X-Policy-Decision': '451-country'
  };
  if (country) (headers as any)['X-Blocked-Country'] = country;
  if (method && method.toUpperCase() === 'HEAD') return new Response(null, { status: 451, headers });
  return new Response(render451HTML(country), { status: 451, headers });
}

function txt(body: string, status = 403, extra: HeadersInit = {}) {
  return new Response(body + '\n', {
    status,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store',
      'Vary': 'User-Agent, Accept, Accept-Language, Sec-CH-UA, Sec-CH-UA-Mobile, Sec-CH-UA-Platform, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, CF-IPCountry, cf-ipcountry, cf-asn',
      'X-Policy-Decision': String(status),
      ...extra
    }
  });
}

export const onRequest: PagesFunction<Env> = async (ctx) => {
  const { request } = ctx;
  const cf: any = (request as any).cf || {};
  const country = cf.country || request.headers.get('CF-IPCountry') || undefined;
  const asn = Number(cf.asn);

  // 1) 地区封禁 → 451（优先级最高）
  if (country && BLOCKED_COUNTRIES.has(country)) {
    return respond451Inline(country, request.method);
  }

  // 2) ASN 黑名单 → 403
  if (Number.isFinite(asn) && BLOCKED_ASNS.has(asn)) {
    return txt('Forbidden (ASN blocked)', 403, { 'X-Blocked-ASN': String(asn) });
  }

  // 3) UA 白名单（国际浏览器）→ 再做“真实浏览器信号”校验
  const ua = request.headers.get('User-Agent') || '';
  if (!isInternationalBrowserUA(ua)) {
    return txt('Forbidden (browser not allowed)', 403, { 'X-UA': ua.slice(0, 160) });
  }

  // 4) 真实浏览器信号校验（关键：防止海外 itdog 拿到 200）
  if (!hasBrowserSignals(request)) {
    return txt('Forbidden (missing browser signals)', 403, {
      'X-UA': ua.slice(0, 160)
    });
  }

  return ctx.next();
};
