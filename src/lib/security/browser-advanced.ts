export interface CorsPolicyConfig {
  allowedOrigins: string[];
  allowCredentials?: boolean;
  allowedMethods?: string[];
  allowedHeaders?: string[];
}

/**
 * Validador estrito de política CORS contra Origin Reflection Inseguro e Null Origin.
 */
export function validateCorsOrigin(requestOrigin: string | null, config: CorsPolicyConfig): { allowed: boolean; originHeaderValue?: string } {
  if (!requestOrigin) {
    return { allowed: true };
  }

  // Bloqueio de Null Origin (comum em sandboxed iframes e data URIs)
  if (requestOrigin === "null" || requestOrigin === "") {
    return { allowed: false };
  }

  const normalized = requestOrigin.toLowerCase().trim();
  const isExplicitlyAllowed = config.allowedOrigins.some((allowed) => {
    return allowed.toLowerCase().trim() === normalized;
  });

  if (isExplicitlyAllowed) {
    return {
      allowed: true,
      originHeaderValue: requestOrigin,
    };
  }

  return { allowed: false };
}

/**
 * Validador de Fetch Metadata (Sec-Fetch-Site / Sec-Fetch-Mode) para proteção contra CSRF e XS-Leaks.
 */
export function validateFetchMetadata(headers: Headers, isMutatingMethod = false): boolean {
  const fetchSite = headers.get("sec-fetch-site");
  const fetchMode = headers.get("sec-fetch-mode");

  // Se for uma requisição mutativa disparada cross-site (ex: formulário ou script externo)
  if (isMutatingMethod && fetchSite === "cross-site" && fetchMode !== "cors") {
    return false; // Bloqueia CSRF
  }

  return true;
}
