/**
 * HTTP Method Enumeration Analyzer
 * Testa métodos HTTP perigosos (TRACE, PUT, DELETE, CONNECT) para detectar
 * vetores de ataque XST e upload/delete sem autenticação.
 */

export interface HttpMethodResult {
  method: string;
  statusCode: number;
  allowed: boolean;
  risky: boolean;
  riskLevel: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  description: string;
}

export interface HttpMethodReport {
  targetUrl: string;
  allowedMethods: string[];
  riskyMethods: string[];
  results: HttpMethodResult[];
  overallStatus: "SECURE" | "WARNING" | "CRITICAL";
  durationMs: number;
}

const METHOD_DEFINITIONS: Array<{ method: string; risky: boolean; riskLevel: HttpMethodResult["riskLevel"]; description: string }> = [
  { method: "GET", risky: false, riskLevel: "INFO", description: "Standard read method (expected to be enabled)." },
  { method: "POST", risky: false, riskLevel: "INFO", description: "Standard write method (expected to be enabled)." },
  { method: "HEAD", risky: false, riskLevel: "INFO", description: "Metadata-only request (expected to be enabled)." },
  { method: "OPTIONS", risky: false, riskLevel: "INFO", description: "CORS preflight / method discovery (may reveal allowed methods)." },
  { method: "PUT", risky: true, riskLevel: "HIGH", description: "File upload without auth — may allow arbitrary file writes on server." },
  { method: "DELETE", risky: true, riskLevel: "HIGH", description: "Resource deletion without auth — may allow removing server files." },
  { method: "PATCH", risky: false, riskLevel: "LOW", description: "Partial resource update (typically behind auth, low risk)." },
  { method: "TRACE", risky: true, riskLevel: "CRITICAL", description: "Cross-Site Tracing (XST) attack vector — reflects cookies and auth headers." },
];

async function testMethod(url: string, method: string, timeout: number): Promise<{ statusCode: number; error: boolean }> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    const res = await fetch(url, {
      method,
      signal: controller.signal,
      redirect: "manual",
      headers: { "User-Agent": "ObsidianSec-Method-Probe/1.2.2" },
    });
    clearTimeout(timer);
    return { statusCode: res.status, error: false };
  } catch {
    return { statusCode: 0, error: true };
  }
}

export async function analyzeHttpMethods(targetUrl: string): Promise<HttpMethodReport> {
  const startTime = Date.now();
  let url = targetUrl.trim();
  if (!url.startsWith("http://") && !url.startsWith("https://")) url = `https://${url}`;

  const results: HttpMethodResult[] = [];
  const allowedMethods: string[] = [];
  const riskyMethods: string[] = [];

  // Test all methods in parallel
  const tests = METHOD_DEFINITIONS.map(async (def) => {
    const { statusCode, error } = await testMethod(url, def.method, 3000);
    const isMethodNotAllowed = statusCode === 405 || statusCode === 501 || error;
    const allowed = !isMethodNotAllowed;

    if (allowed) allowedMethods.push(def.method);
    if (allowed && def.risky) riskyMethods.push(def.method);

    results.push({
      method: def.method,
      statusCode,
      allowed,
      risky: def.risky && allowed,
      riskLevel: (def.risky && allowed) ? def.riskLevel : "INFO",
      description: def.description,
    });
  });

  await Promise.all(tests);

  // Sort results by risk
  const riskOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  results.sort((a, b) => riskOrder[a.riskLevel] - riskOrder[b.riskLevel]);

  let overallStatus: "SECURE" | "WARNING" | "CRITICAL" = "SECURE";
  if (riskyMethods.includes("TRACE")) overallStatus = "CRITICAL";
  else if (riskyMethods.length > 0) overallStatus = "WARNING";

  return {
    targetUrl: url,
    allowedMethods,
    riskyMethods,
    results,
    overallStatus,
    durationMs: Date.now() - startTime,
  };
}
