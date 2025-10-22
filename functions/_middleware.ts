// functions/_middleware.ts
type Env = Record<string, never>;

const BLOCKED_COUNTRIES = new Set(['CN', 'HK', 'MO']);

// 你的 ASN 黑名单（整数）
const BLOCKED_ASNS = new Set<number>([
  // 阿里巴巴
  34947, 37963, 45102, 45103, 45104, 59028, 59051, 59052, 59053, 59054, 59055, 134963, 211914,
  // 腾讯
  45090, 132203, 132591, 133478, 137876,
  // 华为
  55990, 61348, 63655, 63727, 131444, 136907, 139124, 139144, 140723, 141180, 149167, 200756, 206204, 206798, 265443, 269939,
  // 百度云
  38365, 38627, 45076, 45085, 55967, 63288, 63728, 63729, 131138, 131139, 131140, 131141, 133746, 199506,
  // 优刻得(UCloud)
  9786, 59077, 135377,
]);

// 简单主流浏览器白名单（可按需增减）
// 说明：Safari 判断需排除包含 Chrome/Edg/OPR 的 UA；移动端使用 CriOS/EdgiOS。
function isAllowedBrowser(ua: string): boolean {
  if (!ua) return false;
  ua = ua.toLowerCase();

  const has = (s: string) => ua.includes(s);
  const isChrome = /chrome\/\d+/.test(ua) || /crios\/\d+/.test(ua);
  const isEdge   = /edg(e|ios)?\/\d+/.test(ua);
  const isFirefox= /firefox\/\d+/.test(ua);
  const isOpera  = /opr\/\d+/.test(ua);
  // Safari: 有 version/x safari/xxx，且不是 chrome/edge/opera
  const isSafari = /version\/\d+.*safari\/\d+/.test(ua) && !isChrome && !isEdge && !isOpera;

  const isChromium = /chromium\/\d+/.test(ua);

  return isChrome || isEdge || isFirefox || isSafari || isOpera || isChromium;
}

// 生成简短文本响应
function txt(body: string, status = 403, headers: HeadersInit = {}) {
  return new Response(body + '\n', { status, headers: { 'Content-Type': 'text/plain; charset=utf-8', ...headers } });
}

export const onRequest: PagesFunction<Env> = async (ctx) => {
  const { request } = ctx;
  const cf = (request as any).cf || {};

  // 1) 地区封禁 → 451
  const country = cf.country as string | undefined;
  if (country && BLOCKED_COUNTRIES.has(country)) {
    // 若存在自定义 451 页面，直接返回它
    try {
      const url = new URL(request.url);
      const res = await fetch(new URL('/451.html', url.origin).toString(), { cf: { cacheEverything: true } as any });
      if (res.ok) return new Response(res.body, { status: 451, headers: res.headers });
    } catch {}
    return txt('Unavailable For Legal Reasons (451)', 451);
  }

  // 2) 云厂商 ASN 黑名单 → 403
  const asn = Number(cf.asn);
  if (Number.isFinite(asn) && BLOCKED_ASNS.has(asn)) {
    return txt('Forbidden (ASN blocked)', 403);
  }

  // 3) 非主流浏览器 → 403 （你也可以只对页面路由生效，放行静态资源）
  const ua = request.headers.get('User-Agent') || '';
  if (!isAllowedBrowser(ua)) {
    return txt('Forbidden (browser not allowed)', 403);
  }

  // 放行
  return ctx.next();
};
