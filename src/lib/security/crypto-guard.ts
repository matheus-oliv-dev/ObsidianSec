import crypto from "node:crypto";

/**
 * Validação rigorosa de algoritmos JWT para impedir Algorithm Confusion (ex: RSA -> HMAC).
 */
export function verifyJwtAlgorithm(tokenHeader: string, expectedAlg: "HS256" | "RS256" | "ES256"): { valid: boolean; error?: string } {
  try {
    const headerJson = Buffer.from(tokenHeader, "base64url").toString("utf-8");
    const header = JSON.parse(headerJson);

    if (!header.alg) {
      return { valid: false, error: "Cabeçalho JWT sem declaração de algoritmo." };
    }

    if (header.alg.toLowerCase() === "none") {
      return { valid: false, error: "Algoritmo 'none' rejeitado estritamente." };
    }

    if (header.alg !== expectedAlg) {
      return { valid: false, error: `Conflito de algoritmo: esperava ${expectedAlg}, recebido ${header.alg}` };
    }

    return { valid: true };
  } catch {
    return { valid: false, error: "Cabeçalho JWT malformado." };
  }
}

/**
 * Validação de State Parameter para proteção contra CSRF em fluxos OAuth 2.0 / OIDC.
 */
export function validateOAuthState(sessionState: string, callbackState: string): boolean {
  if (!sessionState || !callbackState) return false;
  const bufA = Buffer.from(sessionState);
  const bufB = Buffer.from(callbackState);

  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Validação de PKCE (Proof Key for Code Exchange) para OAuth 2.0.
 */
export function verifyPkceChallenge(codeVerifier: string, codeChallenge: string, method = "S256"): boolean {
  if (!codeVerifier || !codeChallenge) return false;

  if (method === "S256") {
    const computed = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
    const bufA = Buffer.from(computed);
    const bufB = Buffer.from(codeChallenge);
    if (bufA.length !== bufB.length) return false;
    return crypto.timingSafeEqual(bufA, bufB);
  }

  return codeVerifier === codeChallenge;
}

/**
 * Comparação em tempo constante contra Timing Attacks.
 */
export function timingSafeStringCompare(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}
