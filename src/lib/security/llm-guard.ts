import crypto from "node:crypto";
import { z } from "zod";

export interface LLMGuardConfig {
  maxInputLength?: number;
  blockKnownJailbreaks?: boolean;
  maskPII?: boolean;
}

export interface PromptSanitizationResult {
  safeText: string;
  isFlagged: boolean;
  flagReasons: string[];
  nonce: string;
  delimitedPrompt: string;
}

// Padrões heurísticos conhecidos de Prompt Injection / Jailbreaks
const JAILBREAK_PATTERNS = [
  /ignore\s+(all\s+)?(previous|prior)\s+instructions/i,
  /system\s+prompt\s+(leak|override|bypass)/i,
  /you\s+are\s+now\s+(in\s+developer\s+mode|unrestricted|DAN)/i,
  /reveal\s+(your\s+)?(initial|hidden|system)\s+instructions/i,
  /disregard\s+all\s+safety\s+guidelines/i,
];

// Padrões de dados sensíveis (PII) para mascaramento automático
const PII_PATTERNS = [
  { name: "CPF", regex: /\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b/g, mask: "[CPF_REDACTED]" },
  { name: "CARTAO_CREDITO", regex: /\b(?:\d{4}[ -]?){3}\d{4}\b/g, mask: "[CARD_REDACTED]" },
  { name: "EMAIL", regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, mask: "[EMAIL_REDACTED]" },
  { name: "CHAVE_PRIVADA", regex: /sk-[a-zA-Z0-9]{20,}/g, mask: "[API_KEY_REDACTED]" },
];

/**
 * Sanitiza e aplica isolamento de contexto delimitado com Nonce em entradas para modelos de IA.
 * Defesa contra Prompt Injection (OWASP LLM01) e Vazamento de PII (OWASP LLM02).
 */
export function sanitizeAndIsolatePrompt(
  userInput: string,
  config: LLMGuardConfig = {},
): PromptSanitizationResult {
  const maxLen = config.maxInputLength ?? 2000;
  const flagReasons: string[] = [];

  let processed = userInput.slice(0, maxLen);

  // 1. Detecção de Heurísticas de Jailbreak / Injeção
  if (config.blockKnownJailbreaks !== false) {
    for (const pattern of JAILBREAK_PATTERNS) {
      if (pattern.test(processed)) {
        flagReasons.push(`Detectado padrão potencial de Prompt Injection: ${pattern}`);
      }
    }
  }

  // 2. Mascaramento automático de PII
  if (config.maskPII !== false) {
    for (const pii of PII_PATTERNS) {
      processed = processed.replace(pii.regex, pii.mask);
    }
  }

  // 3. Delimitação com Nonce Criptográfico
  const nonce = crypto.randomBytes(8).toString("hex");
  const delimitedPrompt = `<user_untrusted_input_${nonce}>\n${processed}\n</user_untrusted_input_${nonce}>`;

  return {
    safeText: processed,
    isFlagged: flagReasons.length > 0,
    flagReasons,
    nonce,
    delimitedPrompt,
  };
}

/**
 * Validação Zero-Trust de respostas geradas pelo LLM via Zod (OWASP LLM05 - Insecure Output Handling).
 */
export function validateLLMOutput<T>(outputJson: unknown, schema: z.ZodType<T>): { success: true; data: T } | { success: false; error: string } {
  const result = schema.safeParse(outputJson);
  if (result.success) {
    return { success: true, data: result.data };
  }
  return {
    success: false,
    error: `Saída do LLM violou o contrato de schema seguro: ${result.error.message}`,
  };
}
