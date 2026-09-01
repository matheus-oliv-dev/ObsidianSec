/**
 * Technology Stack Fingerprinter (Inspirado no Wappalyzer & BuiltWith)
 * Detecta frameworks, CMS, servidores, CDNs, analytics e bibliotecas JS
 * a partir de cabeçalhos HTTP e padrões no HTML.
 */

export interface TechDetection {
  name: string;
  category: "FRAMEWORK" | "CMS" | "SERVER" | "CDN" | "ANALYTICS" | "LANGUAGE" | "JS_LIBRARY" | "SECURITY" | "CSS_FRAMEWORK";
  confidence: "HIGH" | "MEDIUM" | "LOW";
  version?: string;
  evidence: string;
}

export interface TechFingerprintReport {
  targetUrl: string;
  detections: TechDetection[];
  totalDetected: number;
  serverHeader: string;
  poweredBy: string;
  durationMs: number;
}

interface FingerprintRule {
  name: string;
  category: TechDetection["category"];
  headerCheck?: { name: string; pattern?: RegExp };
  bodyPattern?: RegExp;
  cookiePattern?: RegExp;
  confidence: TechDetection["confidence"];
}

const FINGERPRINT_RULES: FingerprintRule[] = [
  // Servers
  { name: "Nginx", category: "SERVER", headerCheck: { name: "server", pattern: /nginx/i }, confidence: "HIGH" },
  { name: "Apache", category: "SERVER", headerCheck: { name: "server", pattern: /Apache/i }, confidence: "HIGH" },
  { name: "Microsoft IIS", category: "SERVER", headerCheck: { name: "server", pattern: /Microsoft-IIS/i }, confidence: "HIGH" },
  { name: "Caddy", category: "SERVER", headerCheck: { name: "server", pattern: /Caddy/i }, confidence: "HIGH" },
  { name: "LiteSpeed", category: "SERVER", headerCheck: { name: "server", pattern: /LiteSpeed/i }, confidence: "HIGH" },
  { name: "Express.js", category: "SERVER", headerCheck: { name: "x-powered-by", pattern: /Express/i }, confidence: "HIGH" },

  // CDNs
  { name: "Cloudflare CDN", category: "CDN", headerCheck: { name: "cf-ray" }, confidence: "HIGH" },
  { name: "Fastly CDN", category: "CDN", headerCheck: { name: "x-fastly-request-id" }, confidence: "HIGH" },
  { name: "Akamai CDN", category: "CDN", headerCheck: { name: "x-akamai-transformed" }, confidence: "HIGH" },
  { name: "AWS CloudFront", category: "CDN", headerCheck: { name: "x-amz-cf-id" }, confidence: "HIGH" },
  { name: "Vercel Edge Network", category: "CDN", headerCheck: { name: "x-vercel-id" }, confidence: "HIGH" },
  { name: "Netlify", category: "CDN", headerCheck: { name: "x-nf-request-id" }, confidence: "HIGH" },

  // Frameworks (HTML body)
  { name: "Next.js", category: "FRAMEWORK", bodyPattern: /__NEXT_DATA__|_next\/static/i, confidence: "HIGH" },
  { name: "React", category: "JS_LIBRARY", bodyPattern: /data-reactroot|__react|react-root|reactDOM/i, confidence: "HIGH" },
  { name: "Vue.js", category: "JS_LIBRARY", bodyPattern: /__VUE__|v-app|vue-app|vue\.min\.js|vue\.js/i, confidence: "HIGH" },
  { name: "Nuxt.js", category: "FRAMEWORK", bodyPattern: /__NUXT__|_nuxt\//i, confidence: "HIGH" },
  { name: "Angular", category: "FRAMEWORK", bodyPattern: /ng-app|ng-version|angular\.min\.js|angular\.js/i, confidence: "HIGH" },
  { name: "Svelte", category: "FRAMEWORK", bodyPattern: /svelte-|__svelte/i, confidence: "MEDIUM" },
  { name: "Gatsby", category: "FRAMEWORK", bodyPattern: /gatsby-/i, confidence: "MEDIUM" },
  { name: "Remix", category: "FRAMEWORK", bodyPattern: /__remix|remix-run/i, confidence: "MEDIUM" },

  // CMS
  { name: "WordPress", category: "CMS", bodyPattern: /wp-content|wp-includes|wp-json/i, confidence: "HIGH" },
  { name: "Drupal", category: "CMS", bodyPattern: /Drupal\.settings|drupal\.js|sites\/default/i, confidence: "HIGH" },
  { name: "Joomla", category: "CMS", bodyPattern: /\/media\/system\/js\/|com_content|Joomla!/i, confidence: "HIGH" },
  { name: "Ghost CMS", category: "CMS", bodyPattern: /ghost-url|ghost\.js/i, confidence: "HIGH" },
  { name: "Shopify", category: "CMS", bodyPattern: /cdn\.shopify\.com|Shopify\.theme/i, confidence: "HIGH" },
  { name: "Squarespace", category: "CMS", bodyPattern: /squarespace\.com|sqsp/i, confidence: "HIGH" },
  { name: "Wix", category: "CMS", bodyPattern: /wix\.com|_wixCIDX/i, confidence: "HIGH" },

  // Backend Languages
  { name: "PHP", category: "LANGUAGE", headerCheck: { name: "x-powered-by", pattern: /PHP/i }, confidence: "HIGH" },
  { name: "ASP.NET", category: "LANGUAGE", headerCheck: { name: "x-powered-by", pattern: /ASP\.NET/i }, confidence: "HIGH" },
  { name: "Django", category: "FRAMEWORK", bodyPattern: /csrfmiddlewaretoken/i, confidence: "MEDIUM" },
  { name: "Ruby on Rails", category: "FRAMEWORK", headerCheck: { name: "x-request-id" }, bodyPattern: /csrf-token.*authenticity_token/i, confidence: "LOW" },
  { name: "Laravel", category: "FRAMEWORK", cookiePattern: /laravel_session|XSRF-TOKEN/i, confidence: "MEDIUM" },

  // JS Libraries
  { name: "jQuery", category: "JS_LIBRARY", bodyPattern: /jquery\.min\.js|jquery\.js|jquery-\d/i, confidence: "HIGH" },
  { name: "Lodash", category: "JS_LIBRARY", bodyPattern: /lodash\.min\.js|lodash\.js/i, confidence: "MEDIUM" },
  { name: "Moment.js", category: "JS_LIBRARY", bodyPattern: /moment\.min\.js|moment\.js/i, confidence: "MEDIUM" },

  // CSS Frameworks
  { name: "Tailwind CSS", category: "CSS_FRAMEWORK", bodyPattern: /tailwindcss|tailwind\.min\.css/i, confidence: "HIGH" },
  { name: "Bootstrap", category: "CSS_FRAMEWORK", bodyPattern: /bootstrap\.min\.css|bootstrap\.min\.js|bootstrap\.css/i, confidence: "HIGH" },
  { name: "Bulma", category: "CSS_FRAMEWORK", bodyPattern: /bulma\.min\.css|bulma\.css/i, confidence: "HIGH" },

  // Analytics
  { name: "Google Analytics", category: "ANALYTICS", bodyPattern: /google-analytics\.com|googletagmanager\.com|gtag\(/i, confidence: "HIGH" },
  { name: "Google Tag Manager", category: "ANALYTICS", bodyPattern: /googletagmanager\.com\/gtm\.js/i, confidence: "HIGH" },
  { name: "Matomo / Piwik", category: "ANALYTICS", bodyPattern: /matomo\.js|piwik\.js/i, confidence: "HIGH" },
  { name: "Plausible Analytics", category: "ANALYTICS", bodyPattern: /plausible\.io/i, confidence: "HIGH" },
  { name: "Hotjar", category: "ANALYTICS", bodyPattern: /hotjar\.com|_hjSettings/i, confidence: "HIGH" },
  { name: "Microsoft Clarity", category: "ANALYTICS", bodyPattern: /clarity\.ms/i, confidence: "HIGH" },

  // Security
  { name: "reCAPTCHA", category: "SECURITY", bodyPattern: /google\.com\/recaptcha|grecaptcha/i, confidence: "HIGH" },
  { name: "hCaptcha", category: "SECURITY", bodyPattern: /hcaptcha\.com|h-captcha/i, confidence: "HIGH" },
  { name: "Cloudflare Turnstile", category: "SECURITY", bodyPattern: /challenges\.cloudflare\.com\/turnstile/i, confidence: "HIGH" },
];

export async function fingerprintTechStack(targetUrl: string): Promise<TechFingerprintReport> {
  const startTime = Date.now();
  let url = targetUrl.trim();
  if (!url.startsWith("http://") && !url.startsWith("https://")) url = `https://${url}`;

  const detections: TechDetection[] = [];
  const detectedNames = new Set<string>();
  let serverHeader = "Unknown";
  let poweredBy = "N/A";

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);

    const res = await fetch(url, {
      method: "GET",
      signal: controller.signal,
      redirect: "follow",
      headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ObsidianSec/1.2.2" },
    });
    clearTimeout(timeout);

    const headers = res.headers;
    const body = await res.text();
    serverHeader = headers.get("server") || "Unknown";
    poweredBy = headers.get("x-powered-by") || "N/A";

    const rawSetCookies: string[] = [];
    if (typeof (headers as any).getSetCookie === "function") {
      rawSetCookies.push(...(headers as any).getSetCookie());
    } else {
      const sc = headers.get("set-cookie");
      if (sc) rawSetCookies.push(sc);
    }
    const cookieStr = rawSetCookies.join("; ");

    for (const rule of FINGERPRINT_RULES) {
      if (detectedNames.has(rule.name)) continue;
      let matched = false;
      let evidence = "";

      // Header check
      if (rule.headerCheck) {
        const val = headers.get(rule.headerCheck.name);
        if (val !== null) {
          if (!rule.headerCheck.pattern || rule.headerCheck.pattern.test(val)) {
            matched = true;
            evidence = `Header: ${rule.headerCheck.name}: ${val.slice(0, 60)}`;
          }
        }
      }

      // Body pattern check
      if (!matched && rule.bodyPattern) {
        const bodyMatch = body.match(rule.bodyPattern);
        if (bodyMatch) {
          matched = true;
          evidence = `HTML pattern: ${bodyMatch[0].slice(0, 50)}`;
        }
      }

      // Cookie check
      if (!matched && rule.cookiePattern && rule.cookiePattern.test(cookieStr)) {
        matched = true;
        evidence = `Cookie pattern: ${rule.cookiePattern.source}`;
      }

      if (matched) {
        detectedNames.add(rule.name);
        detections.push({
          name: rule.name,
          category: rule.category,
          confidence: rule.confidence,
          evidence,
        });
      }
    }
  } catch (err: any) {
    detections.push({
      name: "Connection Error",
      category: "SERVER",
      confidence: "LOW",
      evidence: `Failed to connect: ${err.message}`,
    });
  }

  return {
    targetUrl: url,
    detections,
    totalDetected: detections.length,
    serverHeader,
    poweredBy,
    durationMs: Date.now() - startTime,
  };
}
