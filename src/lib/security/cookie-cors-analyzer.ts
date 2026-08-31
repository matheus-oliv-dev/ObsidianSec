/**
 * Cookie & CORS Security Analyzer (Inspirado no Burp Suite Passive Scanner)
 * Realiza análise rigorosa e passiva de cabeçalhos Set-Cookie e políticas Cross-Origin Resource Sharing (CORS).
 */

export interface CookieAnalysisResult {
  name: string;
  isHttpOnly: boolean;
  isSecure: boolean;
  sameSite?: "Strict" | "Lax" | "None" | "Missing";
  hasPrefix: boolean;
  prefixType?: "__Host-" | "__Secure-" | "none";
  issues: string[];
  severity: "LOW" | "MEDIUM" | "HIGH" | "PASSED";
}

export interface CorsAnalysisResult {
  allowOrigin?: string;
  allowCredentials?: boolean;
  allowMethods?: string[];
  exposeHeaders?: string[];
  maxAge?: number;
  hasWildcardWithCredentials: boolean;
  hasInsecureOriginReflection: boolean;
  isMissingVaryOrigin: boolean;
  issues: string[];
  severity: "LOW" | "MEDIUM" | "HIGH" | "PASSED";
}

export interface HeaderAuditBurpResult {
  cookies: CookieAnalysisResult[];
  cors: CorsAnalysisResult;
  findingsCount: number;
}

/**
 * Analisa cabeçalhos Set-Cookie individuais
 */
export function analyzeSetCookieHeader(cookieStr: string): CookieAnalysisResult {
  const parts = cookieStr.split(";").map((p) => p.trim());
  const [nameValue, ...attributes] = parts;
  const name = nameValue.split("=")[0] || "";

  const attrLower = attributes.map((a) => a.toLowerCase());

  const isHttpOnly = attrLower.some((a) => a === "httponly");
  const isSecure = attrLower.some((a) => a === "secure");
  
  let sameSite: "Strict" | "Lax" | "None" | "Missing" = "Missing";
  const sameSiteAttr = attributes.find((a) => a.toLowerCase().startsWith("samesite="));
  if (sameSiteAttr) {
    const val = sameSiteAttr.split("=")[1]?.trim().toLowerCase();
    if (val === "strict") sameSite = "Strict";
    else if (val === "lax") sameSite = "Lax";
    else if (val === "none") sameSite = "None";
  }

  const issues: string[] = [];
  let prefixType: "__Host-" | "__Secure-" | "none" = "none";
  let hasPrefix = false;

  if (name.startsWith("__Host-")) {
    prefixType = "__Host-";
    hasPrefix = true;
  } else if (name.startsWith("__Secure-")) {
    prefixType = "__Secure-";
    hasPrefix = true;
  }

  if (!isHttpOnly) {
    issues.push("Ausência da flag 'HttpOnly': Cookie vulnerável a exfiltração via Cross-Site Scripting (XSS).");
  }
  if (!isSecure) {
    issues.push("Ausência da flag 'Secure': Cookie pode ser transmitido em conexões HTTP inseguras.");
  }
  if (sameSite === "Missing" || sameSite === "None") {
    issues.push("Configuração frouxa de SameSite: Cookie vulnerável a ataques de Cross-Site Request Forgery (CSRF).");
  }

  if (prefixType === "__Host-") {
    if (!isSecure) {
      issues.push("Prefixo __Host- exige flag 'Secure' ativa.");
    }
  }

  let severity: "LOW" | "MEDIUM" | "HIGH" | "PASSED" = "PASSED";
  if (!isHttpOnly && !isSecure) severity = "HIGH";
  else if (!isHttpOnly || !isSecure) severity = "MEDIUM";
  else if (sameSite === "Missing") severity = "LOW";

  return {
    name,
    isHttpOnly,
    isSecure,
    sameSite,
    hasPrefix,
    prefixType,
    issues,
    severity,
  };
}

/**
 * Analisa cabeçalhos CORS de resposta
 */
export function analyzeCorsHeaders(headers: Headers | Map<string, string> | Record<string, string>): CorsAnalysisResult {
  const getHeader = (key: string): string | null => {
    if (typeof (headers as any).get === "function") {
      return (headers as any).get(key);
    }
    const rec = headers as Record<string, string>;
    const lowerKey = key.toLowerCase();
    for (const [k, v] of Object.entries(rec)) {
      if (k.toLowerCase() === lowerKey) return v;
    }
    return null;
  };

  const allowOrigin = getHeader("access-control-allow-origin") || undefined;
  const allowCredsStr = getHeader("access-control-allow-credentials");
  const allowCredentials = allowCredsStr?.toLowerCase() === "true";
  const allowMethodsStr = getHeader("access-control-allow-methods");
  const allowMethods = allowMethodsStr ? allowMethodsStr.split(",").map((m) => m.trim()) : undefined;
  const exposeHeadersStr = getHeader("access-control-expose-headers");
  const exposeHeaders = exposeHeadersStr ? exposeHeadersStr.split(",").map((h) => h.trim()) : undefined;
  const maxAgeStr = getHeader("access-control-max-age");
  const maxAge = maxAgeStr ? parseInt(maxAgeStr, 10) : undefined;
  const vary = getHeader("vary") || "";

  const issues: string[] = [];
  let hasWildcardWithCredentials = false;
  let hasInsecureOriginReflection = false;
  let isMissingVaryOrigin = false;

  if (allowOrigin === "*" && allowCredentials) {
    hasWildcardWithCredentials = true;
    issues.push("CORS Crítico: 'Access-Control-Allow-Origin: *' combinado com 'Access-Control-Allow-Credentials: true' permite roubo de credenciais cross-origin.");
  }

  if (allowOrigin === "null") {
    issues.push("CORS Inseguro: 'Access-Control-Allow-Origin: null' pode ser explorado via iframes 'sandboxed' maliciosos.");
  }

  if (allowOrigin && allowOrigin !== "*" && !vary.toLowerCase().includes("origin")) {
    isMissingVaryOrigin = true;
    issues.push("Cache Poisoning Risk: Falta o cabeçalho 'Vary: Origin' quando origens dinâmicas são permitidas.");
  }

  let severity: "LOW" | "MEDIUM" | "HIGH" | "PASSED" = "PASSED";
  if (hasWildcardWithCredentials || allowOrigin === "null") severity = "HIGH";
  else if (issues.length > 0) severity = "MEDIUM";

  return {
    allowOrigin,
    allowCredentials,
    allowMethods,
    exposeHeaders,
    maxAge,
    hasWildcardWithCredentials,
    hasInsecureOriginReflection,
    isMissingVaryOrigin,
    issues,
    severity,
  };
}

/**
 * Auditoria consolidada estilo Burp Suite Passive Scanner
 */
export function runBurpHeaderAudit(headers: Headers | Record<string, string>, rawCookies: string[] = []): HeaderAuditBurpResult {
  const cookieResults = rawCookies.map(analyzeSetCookieHeader);
  const corsResult = analyzeCorsHeaders(headers);

  const findingsCount =
    cookieResults.filter((c) => c.severity !== "PASSED").length +
    (corsResult.severity !== "PASSED" ? 1 : 0);

  return {
    cookies: cookieResults,
    cors: corsResult,
    findingsCount,
  };
}