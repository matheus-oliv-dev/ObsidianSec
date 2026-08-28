import crypto from "node:crypto";
import type { AccessTokenClaims } from "@/types";

const DEFAULT_SECRET = process.env.SUPABASE_JWT_SECRET || process.env.RATE_LIMIT_SECRET || "default-secret-jwt-key-min-32-chars";

/**
 * Decodifica e valida com rigor criptográfico um token JWT.
 * Bloqueia tokens com 'alg: none', tokens expirados ou com assinatura forjada/adulterada.
 */
export async function verifyAccessToken(token: string): Promise<AccessTokenClaims | null> {
  if (!token || typeof token !== "string") {
    return null;
  }

  const parts = token.split(".");
  if (parts.length !== 3) {
    return null;
  }

  const [headerB64, payloadB64, signatureB64] = parts;

  try {
    // 1. Validar Header
    const headerJson = Buffer.from(headerB64, "base64url").toString("utf-8");
    const header = JSON.parse(headerJson);

    // Defesa estrita contra ataque de algoritmo 'none'
    if (!header.alg || header.alg.toLowerCase() === "none" || header.alg !== "HS256") {
      return null;
    }

    // 2. Se a assinatura estiver ausente
    if (!signatureB64) {
      return null;
    }

    // 3. Validar Assinatura HMAC-SHA256
    const dataToSign = `${headerB64}.${payloadB64}`;
    const expectedSignature = crypto
      .createHmac("sha256", DEFAULT_SECRET)
      .update(dataToSign)
      .digest("base64url");

    // Comparação em tempo constante
    const sigBuf = Buffer.from(signatureB64);
    const expBuf = Buffer.from(expectedSignature);

    if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
      return null;
    }

    // 4. Validar Payload e Expiração
    const payloadJson = Buffer.from(payloadB64, "base64url").toString("utf-8");
    const payload = JSON.parse(payloadJson) as AccessTokenClaims;

    const nowSeconds = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < nowSeconds) {
      return null; // Token expirado
    }

    return payload;
  } catch {
    return null;
  }
}

/**
 * Utilitário para gerar tokens JWT seguros para testes e sessões autenticadas
 */
export function signAccessToken(payload: Record<string, unknown>, secret = DEFAULT_SECRET): string {
  const header = { alg: "HS256", typ: "JWT" };
  const headerB64 = Buffer.from(JSON.stringify(header)).toString("base64url");
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const dataToSign = `${headerB64}.${payloadB64}`;
  const signatureB64 = crypto
    .createHmac("sha256", secret)
    .update(dataToSign)
    .digest("base64url");

  return `${headerB64}.${payloadB64}.${signatureB64}`;
}
