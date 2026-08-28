import crypto from "node:crypto";
import type { CaptchaChallenge, CaptchaVerifyResult } from "@/types";

const CAPTCHA_TTL_MS = 120 * 1000; // 2 minutos

function getSecret(): string {
  return process.env.CAPTCHA_SECRET || process.env.RATE_LIMIT_SECRET || "default-captcha-secret-key-32-chars";
}

/**
 * Cria a assinatura HMAC do desafio CAPTCHA para garantir que a resposta não foi adulterada
 */
function createSignature(answer: string, nonce: string, expiresAt: number): string {
  const secret = getSecret();
  const data = `${answer.toUpperCase().trim()}:${nonce}:${expiresAt}`;
  return crypto.createHmac("sha256", secret).update(data).digest("hex");
}

/**
 * Gera um desafio CAPTCHA com SVG e token HMAC assinado
 */
export function generateCaptchaChallenge(): CaptchaChallenge {
  const num1 = Math.floor(Math.random() * 9) + 1;
  const num2 = Math.floor(Math.random() * 9) + 1;
  const answer = String(num1 + num2);
  const nonce = crypto.randomBytes(16).toString("hex");
  const expiresAt = Date.now() + CAPTCHA_TTL_MS;

  const signature = createSignature(answer, nonce, expiresAt);
  // O token encapsula o payload e a assinatura
  const payload = Buffer.from(JSON.stringify({ nonce, expiresAt })).toString("base64url");
  const token = `${payload}.${signature}`;

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="140" height="45" viewBox="0 0 140 45">
    <rect width="100%" height="100%" fill="#1a1a24" rx="6"/>
    <text x="50%" y="55%" dominant-baseline="middle" text-anchor="middle" fill="#00ffcc" font-family="monospace" font-size="20" font-weight="bold">
      ${num1} + ${num2} = ?
    </text>
  </svg>`;

  return {
    token,
    nonce,
    expiresAt,
    svg,
  };
}

/**
 * Valida a resposta do desafio CAPTCHA contra o token assinado
 */
export function verifyCaptchaChallenge(
  token: string,
  userAnswer: string,
  nonce: string,
  expiresAt: number,
): CaptchaVerifyResult {
  if (!token || !userAnswer || !nonce || !expiresAt) {
    return { success: false, error: "Parâmetros de validação incompletos" };
  }

  if (Date.now() > expiresAt) {
    return { success: false, error: "Desafio CAPTCHA expirou" };
  }

  const parts = token.split(".");
  if (parts.length !== 2) {
    return { success: false, error: "Formato de token CAPTCHA inválido" };
  }

  const [, signature] = parts;
  const expectedSignature = createSignature(userAnswer, nonce, expiresAt);

  // Comparação em tempo constante (Anti-Timing Attack)
  const sigBuf = Buffer.from(signature, "hex");
  const expBuf = Buffer.from(expectedSignature, "hex");

  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return { success: false, error: "Resposta incorreta ou token adulterado" };
  }

  return { success: true };
}
