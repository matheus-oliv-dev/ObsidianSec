/**
 * Open Redirect Detector (OWASP CWE-601)
 * Testa parâmetros comuns de redirecionamento para detectar
 * redirecionamentos abertos que podem ser usados em campanhas de phishing.
 */

export interface RedirectTestResult {
  parameter: string;
  payload: string;
  statusCode: number;
  redirected: boolean;
  redirectedTo: string;
  isOpenRedirect: boolean;
  riskLevel: "CRITICAL" | "HIGH" | "MEDIUM" | "INFO";
}

export interface OpenRedirectReport {
  targetUrl: string;
  totalTested: number;
  vulnerableCount: number;
  results: RedirectTestResult[];
  overallStatus: "SECURE" | "WARNING" | "VULNERABLE";
  durationMs: number;
}

const REDIRECT_PARAMS = [
  "url", "redirect", "redirect_url", "redirect_uri", "next",
  "return", "return_to", "returnTo", "dest", "destination",
  "redir", "continue", "forward", "go", "target", "out",
  "view", "login_url", "callback", "return_url", "checkout_url",
];

const EVIL_DOMAIN = "https://evil.chimeraguard-test.com";

async function testRedirectParam(baseUrl: string, param: string): Promise<RedirectTestResult> {
  const payload = `${baseUrl}${baseUrl.includes("?") ? "&" : "?"}${param}=${encodeURIComponent(EVIL_DOMAIN)}`;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);

    const res = await fetch(payload, {
      method: "GET",
      signal: controller.signal,
      redirect: "manual",
      headers: { "User-Agent": "ChimeraGuard-Redirect-Probe/1.2.2" },
    });
    clearTimeout(timeout);

    const statusCode = res.status;
    const location = res.headers.get("location") || "";
    const isRedirect = statusCode >= 300 && statusCode < 400;

    let isOpenRedirect = false;
    if (isRedirect && location) {
      try {
        const targetHost = new URL(location).hostname;
        const baseHost = new URL(baseUrl).hostname;
        isOpenRedirect = targetHost !== baseHost && location.includes("evil.chimeraguard-test.com");
      } catch {
        isOpenRedirect = location.includes("evil.chimeraguard-test.com");
      }
    }

    return {
      parameter: param,
      payload,
      statusCode,
      redirected: isRedirect,
      redirectedTo: location.slice(0, 200),
      isOpenRedirect,
      riskLevel: isOpenRedirect ? "CRITICAL" : "INFO",
    };
  } catch {
    return {
      parameter: param,
      payload,
      statusCode: 0,
      redirected: false,
      redirectedTo: "",
      isOpenRedirect: false,
      riskLevel: "INFO",
    };
  }
}

export async function detectOpenRedirects(targetUrl: string): Promise<OpenRedirectReport> {
  const startTime = Date.now();
  let url = targetUrl.trim();
  if (!url.startsWith("http://") && !url.startsWith("https://")) url = `https://${url}`;

  const tests = REDIRECT_PARAMS.map((param) => testRedirectParam(url, param));
  const results = await Promise.all(tests);

  const vulnerableCount = results.filter((r) => r.isOpenRedirect).length;

  let overallStatus: "SECURE" | "WARNING" | "VULNERABLE" = "SECURE";
  if (vulnerableCount > 0) overallStatus = "VULNERABLE";
  else if (results.some((r) => r.redirected)) overallStatus = "WARNING";

  return {
    targetUrl: url,
    totalTested: results.length,
    vulnerableCount,
    results: results.filter((r) => r.isOpenRedirect || r.redirected),
    overallStatus,
    durationMs: Date.now() - startTime,
  };
}
