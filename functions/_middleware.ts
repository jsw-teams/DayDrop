// functions/_middleware.js
// -------------------------------------------------------------
// SEO & PageSpeed friendly + Aggressive hotlink protection (Hexo)
// - Country 451 (inline, gov.cn law links) > ASN 403 > UA/signal 403
// - UA whitelist: international browsers only
// - Crawlers & lab tools: bypass anti-bot signals (allow crawl & tests)
// - Critical SEO paths: always allow
// - Hexo subresources: same-origin (Sec-Fetch-Site+Referer) OR explicit CDN allowlist
// -------------------------------------------------------------

const LAW_LINK_IISMB = 'https://www.gov.cn/gongbao/content/2000/content_60531.htm';
const LAW_LINK_PSP  = 'https://www.gov.cn/zhengce/2021-12/25/content_5712883.htm';

const BLOCKED_COUNTRIES = new Set(['CN', 'HK', 'MO']);
const BLOCKED_ASNS = new Set([
  34947,37963,45102,45103,45104,59028,59051,59052,59053,59054,59055,134963,211914,
  45090,132203,132591,133478,137876,
  55990,61348,63655,63727,131444,136907,139124,139144,140723,141180,149167,200756,
  206204,206798,265443,269939,
  38365,38627,45076,45085,55967,63288,63728,63729,131138,131139,131140,131141,
  133746,199506,
  9786,59077,135377
]);

const ALLOW_SAMSUNG_INTERNET = false;

/** External CDNs you trust (hostname only) */
const ALLOWED_EXTERNAL_ORIGINS = new Set([
  // 'cdn.jsdelivr.net',
  // 'cdnjs.cloudflare.com',
  // 'fonts.gstatic.com',
]);

/** Critical SEO paths: always allow */
function isCriticalSEOPath(pathname) {
  if (pathname === '/robots.txt') return true;
  if (/^\/sitemap.*\.xml$/i.test(pathname)) return true;     // /sitemap.xml /sitemap-xxx.xml
  if (/^\/(atom|rss|feed)\.xml$/i.test(pathname)) return true;
  if (pathname === '/favicon.ico' || pathname === '/manifest.json') return true;
  if (pathname.startsWith('/.well-known/')) return true;     // acme-challenge, security.txt, etc.
  return false;
}

/** Crawlers (allow) */
function isCrawlerUA(ua) {
  if (!ua) return false;
  ua = ua.toLowerCase();
  return /(googlebot|google-InspectionTool|adsbot-google|mediapartners-google|bingbot|bingpreview|duckduckbot|baiduspider|yandex(bot|images|mobilebot)|applebot|petalbot|bytespider|facebookexternalhit|facebot|twitterbot|linkedinbot|slackbot|semrushbot|ahrefs(bot)?|mj12bot|dotbot|siteauditbot|screaming frog|seznambot)/i.test(ua);
}

/** Lab / performance tools (allow) */
function isLabToolUA(ua) {
  if (!ua) return false;
  ua = ua.toLowerCase();
  return /(lighthouse|chrome-lighthouse|pagespeed|google page speed|webpagetest|gtmetrix|pingdom|speedcurve|sitespeed\.io|calibreapp)/i.test(ua);
}

/* ---------- UA helpers ---------- */
function isInternationalBrowserUA(ua) {
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
  return isEdge || isChromeLike || isOpera || isFirefox || isSafari ||
         (ALLOW_SAMSUNG_INTERNET && isSamsung);
}

function isDomesticOrCustomizedUA(ua) {
  if (!ua) return true;
  const s = ua.toLowerCase();
  const patterns = [
    /\bucbrowser\/|\buc\s?applewebkit/i,
    /\bqqbrowser\/|\bmqqbrowser\/|\bqq\/\d/i,
    /\b2345explorer\/|\bmaxthon\/|\btheworld\/|\blbbrowser\/|\bmetasr\/|\bse\s?360|360se|360ee/i,
    /\bsogou(mobile)?browser\/|\bmetasr/i,
    /\bbaiduboxapp\/|\bbaidubrowser\/|\bbdapp/i,
    /\bmiuibrowser\/|\bxiaomi\/|\bmi\s?browser/i,
    /\bhuaweibrowser\/|\bhonorbrowser\/|\bpetal(search)?\/|\bharmony/i,
    /\boppobrowser\/|\bheytapbrowser\/|\brealmebrowser\//i,
    /\bvivobrowser\/|\bvivo\w*browser\//i,
    /\bmeizubrowser\/|\bflyme/i,
    /\boneplus(?:browser)?\//i,
    /\bztebrowser\/|\bnubia\w*browser\//i,
    /\bhisensebrowser\//i,
    /\bquark(?:browser)?\/|\baliapp\(/i,
    /\btoutiaomicroapp\/|\bbytedance|aweme|douyin/i,
    /\bmicromessenger\/|\bwxwork\/|\bwechatdevtools\//i,
    /\bcurl\/|\bwget\/|\bhttpie\/|\bpostman(?:runtime|agent)?\/|\baxios\/|\bpython-requests\/|\bgo-http-client\/|\bokhttp\/|\bjava\/|\bnode-fetch\//i
  ];
  return patterns.some((re) => re.test(s));
}

/* ---------- Resource / navigation detection ---------- */
function isLikelyNavigation(req) {
  const u = new URL(req.url);
  const accept = req.headers.get('accept') || '';
  const dest = (req.headers.get('sec-fetch-dest') || '').toLowerCase();
  const mode = (req.headers.get('sec-fetch-mode') || '').toLowerCase();
  const isHtmlAccept = accept.includes('text/html');
  const isDocDest = dest === 'document' || dest === 'empty';
  const looksLikeHtmlPath = u.pathname === '/' || u.pathname.endsWith('.html') || !/\.[a-z0-9]+$/i.test(u.pathname);
  return (isHtmlAccept && isDocDest && looksLikeHtmlPath) || mode === 'navigate';
}

function isHexoAssetPath(pathname) {
  if (pathname.startsWith('/css/') || pathname.startsWith('/js/') || pathname.startsWith('/images/') || pathname.startsWith('/img/') || pathname.startsWith('/assets/')) return true;
  if (/\.(css|js|mjs|map|png|jpg|jpeg|webp|gif|svg|ico|woff2?|ttf|otf)$/.test(pathname)) return true;
  if (/\/(sitemap|atom|rss|feed)\.xml$/.test(pathname)) return true;
  if (/\/search\.json$/.test(pathname)) return true;
  return false;
}

/* ---------- Aggressive hotlink checks ---------- */
function originOf(urlStr) { if (!urlStr) return null; try { return new URL(urlStr).origin; } catch { return null; } }
function hostnameOf(urlStr) { if (!urlStr) return null; try { return new URL(urlStr).hostname; } catch { return null; } }

function isAllowedSubresourceAggressive(req) {
  const url = new URL(req.url);
  const pathname = url.pathname;
  const fetchSite = (req.headers.get('sec-fetch-site') || '').toLowerCase();
  const referer = req.headers.get('referer') || '';
  const refererOrigin = originOf(referer);
  const reqOrigin = url.origin;
  const host = url.hostname;

  if (!isHexoAssetPath(pathname)) return false;

  if (ALLOWED_EXTERNAL_ORIGINS.has(host)) return true;

  if (fetchSite !== 'same-origin') return false;

  if (!refererOrigin) return false;
  if (refererOrigin !== reqOrigin) return false;

  return true;
}

/* ---------- 451 rendering ---------- */
function render451HTML(country) {
  const title = '451 Unavailable For Legal Reasons';
  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title>
<style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;background:#0b1220;color:#e6ecff;padding:2rem}main{max-width:820px;margin:auto}.card{background:#121a2b;border:1px solid #1f2a44;border-radius:16px;padding:24px}a{color:#9ec1ff}</style></head><body>
<main><div class="card"><h1>${title}</h1><p>Unavailable For Legal Reasons</p><p>Country: ${country||'N/A'}</p>
<div style="padding:.75rem 1rem;border-left:3px solid #304a7a;background:#0f1626">
<p><strong>《互联网信息服务管理办法》</strong> (<a href="${LAW_LINK_IISMB}" target="_blank" rel="noopener">gov.cn</a>)</p>
<p><strong>《公安机关互联网安全监督检查规定》</strong> (<a href="${LAW_LINK_PSP}" target="_blank" rel="noopener">gov.cn</a>)</p>
</div></div></main></body></html>`;
}

function respond451Inline(country, method) {
  const headers = {
    'Content-Type': 'text/html; charset=utf-8',
    'Link': `<${LAW_LINK_IISMB}>; rel="related", <${LAW_LINK_PSP}>; rel="related"`,
    'Cache-Control': 'no-store',
    'Vary': 'User-Agent, Accept, Accept-Language, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, CF-IPCountry, cf-ipcountry, cf-asn',
    'X-Policy-Decision': '451-country'
  };
  if (country) headers['X-Blocked-Country'] = country;
  if (method && method.toUpperCase() === 'HEAD') return new Response(null, { status: 451, headers });
  return new Response(render451HTML(country), { status: 451, headers });
}

function txt(body, status = 403, extra = {}) {
  return new Response(body + '\n', {
    status,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store',
      'Vary': 'User-Agent, Accept, Accept-Language, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, CF-IPCountry, cf-ipcountry, cf-asn',
      'X-Policy-Decision': String(status),
      ...extra
    }
  });
}

/* ---------- Main handler ---------- */
export const onRequest = async (ctx) => {
  const { request } = ctx;
  const url = new URL(request.url);
  const pathname = url.pathname;
  const cf = request.cf || {};
  const country = cf.country || request.headers.get('CF-IPCountry') || undefined;
  const asn = Number(cf.asn);
  const ua = request.headers.get('User-Agent') || '';

  // 0) Always-allow critical SEO paths
  if (isCriticalSEOPath(pathname)) {
    return ctx.next();
  }

  // 1) Country-based block -> 451
  if (country && BLOCKED_COUNTRIES.has(country)) {
    return respond451Inline(country, request.method);
  }

  // 2) ASN blacklist -> 403
  if (Number.isFinite(asn) && BLOCKED_ASNS.has(asn)) {
    return txt('Forbidden (ASN blocked)', 403, { 'X-Blocked-ASN': String(asn) });
  }

  // 3) Crawlers & Lab tools: allow (so SEO & PageSpeed/Lighthouse work)
  const crawler = isCrawlerUA(ua);
  const labTool = isLabToolUA(ua);
  if (crawler || labTool) {
    return ctx.next();
  }

  // 4) UA whitelist (international browsers)
  if (!isInternationalBrowserUA(ua)) {
    return txt('Forbidden (browser not allowed)', 403, { 'X-UA': ua.slice(0, 160) });
  }

  // 5) Navigation (HTML page): require navigation signals (kept to filter synthetic scripts)
  const isNav = isLikelyNavigation(request);
  if (isNav) {
    const h = request.headers;
    const sfSite = h.get('sec-fetch-site');
    const sfMode = h.get('sec-fetch-mode');
    const sfDest = h.get('sec-fetch-dest');
    const uir = h.get('upgrade-insecure-requests');
    if (!sfSite || !sfMode || !sfDest || uir !== '1' ||
        sfMode.toLowerCase() !== 'navigate' ||
        !['document','empty'].includes((sfDest||'').toLowerCase())) {
      return txt('Forbidden (missing navigation signals)', 403, { 'X-UA': ua.slice(0,160) });
    }
    return ctx.next();
  }

  // 6) Subresources: aggressive hotlink protection (Hexo)
  if (isHexoAssetPath(pathname)) {
    // crawlers/lab already bypassed; here enforce hotlink rules for normal traffic
    if (!isAllowedSubresourceAggressive(request)) {
      return txt('Forbidden (hotlink blocked)', 403);
    }
    return ctx.next();
  }

  // 7) Other requests: be conservative (require same-origin)
  const sfSite = (request.headers.get('sec-fetch-site') || '').toLowerCase();
  const referer = request.headers.get('referer') || '';
  const refOrigin = originOf(referer);
  if (sfSite === 'same-origin' && refOrigin === url.origin) {
    return ctx.next();
  }
  return txt('Forbidden (cross-site request blocked)', 403);
};
