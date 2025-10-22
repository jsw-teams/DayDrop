// functions/_middleware.ts
type Env = {
  ENVIRONMENT?: string; // "production" | "preview" | "local"
};

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

function isAllowedBrowser(ua: string): boolean {
  if (!ua) return false;
  ua = ua.toLowerCase();
  const isChrome = /chrome\/\d+|crios\/\d+/.test(ua);
  const isEdge   = /edg(e|ios)?\/\d+/.test(ua);
  const isFirefox= /firefox\/\d+/.test(ua);
  const isOpera  = /opr\/\d+/.test(ua);
  const isChromium = /chromium\/\d+/.test(ua);
  const isSafari = /version\/\d+.*safari\/\d+/.test(ua) && !isChrome && !isEdge && !isOpera;
  return isChrome || isEdge || isFirefox || isSafari || isOpera || isChromium;
}

function txt(body: string, status = 403, headers: HeadersInit = {}) {
  return new Response(body + '\n', { status, headers: { 'Content-Type': 'text/plain; charset=utf-8', ...headers } });
}

export const onRequest: PagesFunction<Env> = async (ctx) => {
  const { request, env } = ctx;

  // 预览/本地放行；生产才严格拦截
  if (env.ENVIRONMENT && env.ENVIRONMENT !== 'production') {
    return ctx.next();
  }

  // 调试开关：?debug=1 放行
  const url = new URL(request.url);
  if (url.searchParams.get('debug') === '1') return ctx.next();

  const cf: any = (request as any).cf || {};
  const country = cf.country as string | undefined;
  const asn = Number(cf.asn);

  // 1) 地区封禁 → 451
  if (country && BLOCKED_COUNTRIES.has(country)) {
    try {
      const res = await fetch(new URL('/451.html', url.origin).toString(), { cf: { cacheEverything: true } as any });
      if (res.ok) return new Response(res.body, { status: 451, headers: res.headers });
    } catch {}
    return txt('Unavailable For Legal Reasons (451)', 451);
  }

  // 2) ASN 黑名单 → 403
  if (Number.isFinite(asn) && BLOCKED_ASNS.has(asn)) {
    return txt('Forbidden (ASN blocked)', 403);
  }

  // 3) UA 白名单：只对“页面请求”生效（Accept: text/html 或路径以 .html 结尾）
  const accept = request.headers.get('Accept') || '';
  const isPage = accept.includes('text/html') || url.pathname.endsWith('.html') || url.pathname === '/';
  if (isPage) {
    const ua = request.headers.get('User-Agent') || '';
    if (!isAllowedBrowser(ua)) return txt('Forbidden (browser not allowed)', 403);
  }

  return ctx.next();
};
