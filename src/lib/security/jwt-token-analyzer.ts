/**
 * JWT Token Security Auditor & Decoder
 * Inspeciona tokens JWT em busca de vulnerabilidades (alg: none, expiração ausente,
 * algoritmos legados, vazamento de PII no payload) conforme RFC 7519 e OWASP ASVS.
 */

export interface JwtHeader {
  alg?: string;
  typ?: string;
  kid?: string;
  [key: string]: any;
}

export interface JwtPayload {
  sub?: string;
  iss?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  [key: string]: any;
}

export interface JwtAuditReport {
  rawToken: string;
  isValidStructure: boolean;
  header: JwtHeader;
  payload: JwtPayload;
  signaturePresent: boolean;
  algorithm: string;
  isExpired: boolean;
  expiresInSeconds?: number;
  hasExpiration: boolean;
  issues: Array<{ severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"; message: string }>;
  securityScore: number;
  status: "SECURE" | "WARNING" | "CRITICAL";
}

function base64UrlDecode(str: string): string {
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) {
    base64 += "=";
  }
  return Buffer.from(base64, "base64").toString("utf-8");
}

export function auditJwtToken(tokenStr: string): JwtAuditReport {
  const clean = tokenStr.trim();
  const parts = clean.split(".");

  if (parts.length !== 3) {
    return {
      rawToken: clean,
      isValidStructure: false,
      header: {},
      payload: {},
      signaturePresent: false,
      algorithm: "UNKNOWN",
      isExpired: false,
      hasExpiration: false,
      issues: [{ severity: "CRITICAL", message: "Formato de token JWT inválido. Deve conter 3 partes separadas por ponto (Header.Payload.Signature)." }],
      securityScore: 0,
      status: "CRITICAL",
    };
  }

  const [headerPart, payloadPart, signaturePart] = parts;
  let header: JwtHeader = {};
  let payload: JwtPayload = {};

  try {
    header = JSON.parse(base64UrlDecode(headerPart));
  } catch {
    return {
      rawToken: clean,
      isValidStructure: false,
      header: {},
      payload: {},
      signaturePresent: !!signaturePart,
      algorithm: "UNKNOWN",
      isExpired: false,
      hasExpiration: false,
      issues: [{ severity: "CRITICAL", message: "Falha ao decodificar o cabeçalho Base64URL do JWT." }],
      securityScore: 0,
      status: "CRITICAL",
    };
  }

  try {
    payload = JSON.parse(base64UrlDecode(payloadPart));
  } catch {
    return {
      rawToken: clean,
      isValidStructure: false,
      header,
      payload: {},
      signaturePresent: !!signaturePart,
      algorithm: header.alg || "UNKNOWN",
      isExpired: false,
      hasExpiration: false,
      issues: [{ severity: "CRITICAL", message: "Falha ao decodificar o payload Base64URL do JWT." }],
      securityScore: 0,
      status: "CRITICAL",
    };
  }

  const issues: Array<{ severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"; message: string }> = [];
  const algorithm = String(header.alg || "none").toUpperCase();
  const signaturePresent = signaturePart.length > 0;

  // 1. Checagem de alg: none
  if (algorithm === "NONE" || !signaturePresent) {
    issues.push({
      severity: "CRITICAL",
      message: "Vulnerabilidade Crítica 'alg: none': Token sem assinatura criptográfica, permitindo forja irrestrita de identidade.",
    });
  }

  // 2. Checagem de algoritmos fracos / legados
  if (algorithm === "HS256") {
    issues.push({
      severity: "LOW",
      message: "Algoritmo simétrico HS256: Requer segredo com no mínimo 256 bits de entropia. Prefira algoritmos assimétricos (RS256/ES256/EdDSA).",
    });
  }

  // 3. Checagem de Expiração (exp)
  const nowInSeconds = Math.floor(Date.now() / 1000);
  let isExpired = false;
  let expiresInSeconds: number | undefined;
  const hasExpiration = typeof payload.exp === "number";

  if (!hasExpiration) {
    issues.push({
      severity: "HIGH",
      message: "Ausência do claim 'exp' (Token Infinito): Tokens sem expiração permanecem válidos permanentemente se vazados.",
    });
  } else {
    expiresInSeconds = (payload.exp as number) - nowInSeconds;
    if (expiresInSeconds <= 0) {
      isExpired = true;
      issues.push({
        severity: "MEDIUM",
        message: `Token expirado há ${Math.abs(expiresInSeconds)} segundos.`,
      });
    }
  }

  // 4. Checagem de PII sensível no payload
  const sensitiveKeys = ["password", "senha", "credit_card", "secret", "cvv", "cpf", "ssn"];
  for (const k of Object.keys(payload)) {
    if (sensitiveKeys.some((s) => k.toLowerCase().includes(s))) {
      issues.push({
        severity: "HIGH",
        message: `Vazamento de PII/Segredo no payload: O claim '${k}' está exposto em texto claro (JWT não é criptografado, apenas assinado).`,
      });
    }
  }

  // Cálculo do Score
  let score = 100;
  for (const iss of issues) {
    if (iss.severity === "CRITICAL") score -= 60;
    else if (iss.severity === "HIGH") score -= 25;
    else if (iss.severity === "MEDIUM") score -= 15;
    else if (iss.severity === "LOW") score -= 5;
  }
  score = Math.max(0, score);

  let status: "SECURE" | "WARNING" | "CRITICAL" = "CRITICAL";
  if (score >= 80) status = "SECURE";
  else if (score >= 50) status = "WARNING";

  return {
    rawToken: clean,
    isValidStructure: true,
    header,
    payload,
    signaturePresent,
    algorithm,
    isExpired,
    expiresInSeconds,
    hasExpiration,
    issues,
    securityScore: score,
    status,
  };
}