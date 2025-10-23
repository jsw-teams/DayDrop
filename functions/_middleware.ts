// functions/_middleware.ts
// -------------------------------------------------------------
// 访问控制中间件（Cloudflare Pages Functions）
// - 地区封禁：451（RFC 7725 合规；优先级最高）
// - ASN 黑名单：403
// - UA 白名单：仅放行“国际浏览器”（桌面 + 手机）
//   • 允许：Chrome/Chromium、Edge、Firefox、Safari、Opera（含 iOS/Android 变体）
//   • 明确拒绝：国产/定制浏览器、命令行/SDK、未知/空 UA 等 => 403
//
// 参考标准：RFC 7725 (§3, §4) — 451 返回应包含 Link: <URI>; rel="blocked-by"
// -------------------------------------------------------------

type Env = {
  ENVIRONMENT?: string; // "production" | "preview" | "local"
};

/** 你的法条/透明度说明页（请替换为实际地址） */
const LEGAL_LINK_CN = 'https://example.com/legal/blocked-cn';   // 面向 CN/HK/MO 的中文说明页
const LEGAL_LINK_GENERIC = 'https://example.com/legal/blocked'; // 其他地区通用说明页

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

/** 可选：是否把 Samsung Internet 视为国际浏览器（默认 false -> 拒绝） */
const ALLOW_SAMSUNG_INTERNET = false;

/** —— 国际浏览器：正向允许 ————————————————————————————————
 * 覆盖桌面与移动端（含 iOS WebKit 限制下的 UA 变体）
 */
function isInternationalBrowserUA(ua: string): boolean {
  if (!ua) return false;
  // 先做“国产浏览器”快速排除（见下方 denylist）
  if (isDomesticOrCustomizedUA(ua)) return false;

  ua = ua.toLowerCase();

  const isEdge = /\bedg(?:e|ios|a)?\/\d+/i.test(ua); // Edg/ EdgiOS/ EdgA/
  const isChromium = /\bchromium\/\d+/i.test(ua);

  // Chrome 家族（排除 Edge/Opera 以防重复）
  const isChromeLike =
    (/\b(?:chrome|crios|brave|vivaldi)\/\d+/i.test(ua) || isChromium) &&
    !/\bedg(?:e|ios|a)?\/\d+/i.test(ua) &&
    !/\b(?:opr|opios)\/\d+/i.test(ua);

  // Opera（桌面/移动 iOS 变体）
  const isOpera = /\b(?:opr|opios)\/\d+/i.test(ua);

  // Firefox（桌面/iOS）
  const isFirefox = /\bfirefox\/\d+/i.test(ua) || /\bfxios\/\d+/i.test(ua);

  // 纯正 Safari（排除 Chromium/Edge/Opera 的“Safari/”伪标识）
  const isSafari =
    /\bversion\/\d+(?:\.\d+)*.*\bsafari\/\d+/i.test(ua) &&
    !/\b(?:chrome|crios|edg\w*|opr|opios)\//i.test(ua);

  // （可选）Samsung Internet
  const isSamsung = /\bsamsungbrowser\/\d+/i.test(ua);

  return (
    isEdge ||
    isChromeLike ||
    isOpera ||
    isFirefox ||
    isSafari ||
    (ALLOW_SAMSUNG_INTERNET && isSamsung)
  );
}

/** —— 国产/定制浏览器：明确拒绝 ————————————————————————————
 * 常见国产浏览器 & OEM 浏览器 & 聚合容器 UA 关键字（按需扩充）
 */
function isDomesticOrCustomizedUA(ua: string): boolean {
  if (!ua) return true; // 空 UA 一律视为非国际浏览器
  const s = ua.toLowerCase();

  // 国产通用/大厂
  const patterns = [
    /\bucbrowser\/|\buc\s?applewebkit/i,  // UC
    /\bqqbrowser\/|\bmqqbrowser\/|\bqq\/\d/i, // QQ Browser/内置
    /\b2345explorer\/|\bmaxthon\/|\btheworld\/|\blbbrowser\/|\bmetasr\/|\bse\s?360|360se|360ee/i, // 2345/遨游/世界之窗/猎豹/搜狗壳/360
    /\bsogou(mobile)?browser\/|\bmetasr/i, // 搜狗
    /\bbaiduboxapp\/|\bbaidubrowser\/|\bbdapp/i, // 百度
  ];

  // 国内 OEM/ROM 浏览器（小米/华为/荣耀/OPPO/vivo/魅族/一加/海信/中兴等）
  const oem = [
    /\bmiuibrowser\/|\bxiaomi\/|\bmi\s?browser/i, // 小米
    /\bhuaweibrowser\/|\bhonorbrowser\/|\bpetal(search)?\/|\bharmony/i, // 华为/荣耀
    /\boppobrowser\/|\bheytapbrowser\/|\brealmebrowser\//i, // OPPO/HeyTap/realme
    /\bvivobrowser\/|\bvivo\w*browser\//i, // vivo
    /\bmeizubrowser\/|\bflyme/i, // 魅族
    /\boneplus(?:browser)?\//i, // 一加（少见，但保留）
    /\bztebrowser\/|\bnubia\w*browser\//i, // 中兴/努比亚
    /\bhisensebrowser\//i, // 海信
  ];

  // 其他“容器/聚合/代理”类
  const containers = [
    /\bquark(?:browser)?\/|\baliapp\(/i, // 夸克/阿里容器
    /\btoutiaomicroapp\/|\bbytedance|aweme|douyin/i, // 头条/抖音容器
    /\bmicromessenger\/|\bwxwork\/|\bwechatdevtools\//i, // 微信/企业微信/开发者工具
    /\bmetamaskmobile\//i, // 钱包内置 WebView（示例）
  ];

  // 命令行/SDK/库（即便国际，也不视为“国际浏览器”）
  const cliOrSdks = [
    /\bcurl\/|\bwget\/|\bhttpie\/|\bpostman(?:runtime|agent)?\/|\baxios\/|\bpython-requests\/|\bgo-http-client\/|\bokhttp\/|\bjava\/|\bnode-fetch\//i
  ];

  const hit =
    [...patterns, ...oem, ...containers, ...cliOrSdks].some((re) => re.test(s));

  return hit;
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

/** RFC 7725 合规 451 响应（优先使用 /451.html） */
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

  // 非生产环境：放行
  if (env.ENVIRONMENT && env.ENVIRONMENT !== 'production') {
    return ctx.next();
  }

  // 调试：?debug=1 放行
  const url = new URL(request.url);
  if (url.searchParams.get('debug') === '1') return ctx.next();

  const cf: any = (request as any).cf || {};
  const country = cf.country as string | undefined;
  const asn = Number(cf.asn);

  // 1) 地区封禁 → 451（优先级最高）
  if (country && BLOCKED_COUNTRIES.has(country)) {
    return respond451(url, country);
  }

  // 2) ASN 黑名单 → 403
  if (Number.isFinite(asn) && BLOCKED_ASNS.has(asn)) {
    return txt('Forbidden (ASN blocked)', 403, {
      'Vary': 'cf-asn, Accept, Accept-Encoding'
    });
  }

  // 3) UA 白名单（国际浏览器）→ 通过；否则一律 403
  const ua = request.headers.get('User-Agent') || '';
  if (!isInternationalBrowserUA(ua)) {
    return txt('Forbidden (browser not allowed)', 403, {
      'Vary': 'User-Agent, Accept, Accept-Encoding'
    });
  }

  // 放行其余请求
  return ctx.next();
};
