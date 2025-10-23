// functions/_middleware.ts
// -------------------------------------------------------------
// 访问控制中间件（Cloudflare Pages Functions）
// - 地区封禁：451（RFC 7725 合规）
// - ASN 黑名单：403
// - UA 白名单：对所有请求生效
//   • 支持「程序化客户端」例外（curl/wget/自定义 UA 等）
//   • 支持「路径」例外（healthz/.well-known/内部 API 等）
//
// 参考标准：
// • RFC 7725 (§3, §4): 451 用于因合法要求拒绝访问；应返回 Link: <URI>; rel="blocked-by"
//   https://datatracker.ietf.org/doc/html/rfc7725
//
// 相关法条（示例，便于在说明页引用；非法律意见）：
// • 《中华人民共和国网络安全法》：第1、10、50、58条（关于网络安全义务、处置/阻断措施等）
// -------------------------------------------------------------

type Env = {
  ENVIRONMENT?: string; // "production" | "preview" | "local"
};

/** 你的法条/透明度说明页（请替换为实际地址） */
const LEGAL_LINK_CN = 'https://www.gov.cn/gongbao/content/2000/content_60531.htm';   // 针对 CN/HK/MO 的中文说明页
const LEGAL_LINK_GENERIC = 'https://www.gov.cn/zhengce/2021-12/25/content_5712883.htm'; // 通用说明页

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

/** UA 白名单（主流浏览器 + Chromium 家族） */
function isAllowedBrowserUA(ua: string): boolean {
  if (!ua) return false;
  ua = ua.toLowerCase();

  const isEdge = /\bedg(?:e|ios|a)?\/\d+/i.test(ua); // Edg/ EdgiOS/ EdgA/
  const isChromium = /\bchromium\/\d+/i.test(ua);
  const isOpera = /\b(?:opr|opios)\/\d+/i.test(ua); // OPR/ OPiOS/
  const isFirefox = /\bfirefox\/\d+/i.test(ua) || /\bfxios\/\d+/i.test(ua); // FxiOS/
  const isChromeLike =
    (/\b(?:chrome|crios|brave|vivaldi)\/\d+/i.test(ua) || isChromium) &&
    !isEdge && !isOpera;

  // 纯正 Safari（排除 Chromium/Edge/Opera 伪装的 Safari）
  const isSafari =
    /\bversion\/\d+(?:\.\d+)*.*\bsafari\/\d+/i.test(ua) &&
    !/\b(?:chrome|crios|edg\w*|opr|opios)\//i.test(ua);

  return isEdge || isOpera || isFirefox || isChromeLike || isChromium || isSafari;
}

/** —— 程序化客户端例外 ————————————————————————————————
 * 允许常见命令行/探活/SDK UA；也允许你的 App 自定义前缀
 */
const PROGRAMMATIC_UA_REGEX: RegExp[] = [
  /\bcurl\/\d+/i,
  /\bwget\/\d+/i,
  /\bhttpie\/\d+/i,
  /\bpostman(runtime|agent)?\/\d+/i,
  /\baxios\/\d+/i,
  /\bpython-requests\/\d+/i,
  /\bgo-http-client\/\d+/i,
  /\bjava\/\d+/i,
  /\bokhttp\/\d+/i,
  /\bdart\/\d+/i,
  /\bnode-fetch\/\d+/i,
  /\bcloudflare-healthcheck\b/i
];

/** 你的移动/桌面 App 自定义 UA 前缀（示例：MyApp/1.2.3） */
const PROGRAMMATIC_UA_PREFIXES: string[] = [
  'myapp/',        // ← 改成你的 App UA 前缀（小写比较）
  'internal-bot/', // 内部机器人
];

/** 路径例外：跳过 UA 检查（但仍执行地区/ASN 检查） */
const UA_BYPASS_PATH_PREFIXES: string[] = [
  '/healthz',
  '/-/health',
  '/status',
  '/.well-known', // e.g. /.well-known/ai-plugin.json / security.txt / apple-app-site-association
  '/robots.txt',
  '/favicon.ico',
];

/** 可选：允许空 UA 的路径（某些负载均衡/探针可能不带 UA） */
const ALLOW_EMPTY_UA_ON_PATHS: string[] = [
  '/healthz',
  '/-/health',
];

/** 简易前缀匹配 */
function matchByPrefix(pathname: string, prefixes: string[]): boolean {
  for (const p of prefixes) {
    if (pathname.startsWith(p)) return true;
  }
  return false;
}

/** UA 是否属于程序化客户端 */
function isProgrammaticUA(ua: string): boolean {
  if (!ua) return false;
  const lower = ua.toLowerCase();
  if (PROGRAMMATIC_UA_PREFIXES.some((p) => lower.startsWith(p))) return true;
  return PROGRAMMATIC_UA_REGEX.some((re) => re.test(ua));
}

function txt(body: string, status = 403, headers: HeadersInit = {}) {
  return new Response(body + '\n', {
    status,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      ...headers
    }
  });
}

/** RFC 7725 合规 451 响应（优先返回 /451.html） */
async function respond451(url: URL, country?: string) {
  const linkTarget =
    country && (country === 'CN' || country === 'HK' || country === 'MO')
      ? LEGAL_LINK_CN
      : LEGAL_LINK_GENERIC;

  try {
    const pageRes = await fetch(new URL('/451.html', url.origin).toString(), {
      cf: { cacheEverything: true } as any
    });
    const headers = new Headers(pageRes.headers);

    headers.set('Link', `<${linkTarget}>; rel="blocked-by"`); // RFC 7725 §4
    headers.set('Vary', 'Accept, Accept-Encoding, cf-ipcountry');
    headers.set('Cache-Control', 'no-store');
    if (country) headers.set('X-Blocked-Country', country);
    if (!headers.get('Content-Type')) {
      headers.set('Content-Type', 'text/html; charset=utf-8');
    }

    return new Response(pageRes.body, { status: 451, headers });
  } catch {
    return new Response(
      `Unavailable For Legal Reasons (451)\nSee: ${linkTarget}\n`,
      {
        status: 451,
        headers: {
          'Content-Type': 'text/plain; charset=utf-8',
          'Link': `<${linkTarget}>; rel="blocked-by"`,
          'Vary': 'Accept, Accept-Encoding, cf-ipcountry',
          'Cache-Control': 'no-store',
          ...(country ? { 'X-Blocked-Country': country } : {})
        }
      }
    );
  }
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

  // Cloudflare 元信息
  const cf: any = (request as any).cf || {};
  const country = cf.country as string | undefined;
  const asn = Number(cf.asn);

  // 1) 地区封禁 → 451（RFC 7725 合规；按地区返回说明链接）
  if (country && BLOCKED_COUNTRIES.has(country)) {
    return respond451(url, country);
  }

  // 2) ASN 黑名单 → 403
  if (Number.isFinite(asn) && BLOCKED_ASNS.has(asn)) {
    return txt('Forbidden (ASN blocked)', 403, {
      'Vary': 'cf-asn, Accept, Accept-Encoding'
    });
  }

  // 3) 路径例外：跳过 UA 校验（但仍执行了上面的地区/ASN 检查）
  const pathname = url.pathname;
  const bypassUA = matchByPrefix(pathname, UA_BYPASS_PATH_PREFIXES);
  if (!bypassUA) {
    // 4) UA 白名单：对所有请求生效
    const ua = request.headers.get('User-Agent') || '';

    // （可选）空 UA 在部分路径容忍
    const allowEmptyUA = !ua && matchByPrefix(pathname, ALLOW_EMPTY_UA_ON_PATHS);

    const pass =
      allowEmptyUA ||
      isAllowedBrowserUA(ua) ||
      isProgrammaticUA(ua);

    if (!pass) {
      return txt('Forbidden (browser not allowed)', 403, {
        'Vary': 'User-Agent, Accept, Accept-Encoding'
      });
    }
  }

  // 其余请求放行
  return ctx.next();
};

