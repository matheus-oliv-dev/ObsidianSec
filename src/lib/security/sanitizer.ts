/**
 * Módulo de Sanitização e Filtragem de Entradas Maliciosas.
 * Defende contra XSS, Zalgo text, caracteres de controle e bombas de strings.
 */

// Regex para detectar e neutralizar tags perigosas
const HTML_TAG_REGEX = /<[^>]*>?/gm;

// Regex para caracteres de controle invisíveis e Zero-Width chars
const CONTROL_AND_ZERO_WIDTH_REGEX = /[\u0000-\u001F\u007F-\u009F\u200B-\u200D\uFEFF]/g;

// Regex para caracteres combinadores excessivos (Zalgo Text)
const EXCESSIVE_COMBINING_MARKS_REGEX = /[\u0300-\u036F\u1DC0-\u1DFF\u20D0-\u20FF\uFE20-\uFE2F]{3,}/g;

/**
 * Escapa caracteres HTML para exibição segura
 */
export function escapeHtml(str: string): string {
  if (!str || typeof str !== "string") return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Remove tags HTML, scripts e payloads embutidos
 */
export function stripHtml(str: string): string {
  if (!str || typeof str !== "string") return "";
  return str.replace(HTML_TAG_REGEX, "");
}

/**
 * Sanitiza texto profundo: normaliza NFKC, remove tags, filtra caracteres invisíveis
 * e atenua Zalgo text sem quebrar emojis válidos.
 */
export function sanitizeInput(input: string, maxLength = 1000): string {
  if (!input || typeof input !== "string") return "";

  // 1. Limite de tamanho preliminar anti-DoS
  let cleaned = input.slice(0, maxLength);

  // 2. Normalização Unicode NFKC
  cleaned = cleaned.normalize("NFKC");

  // 3. Remoção de tags HTML
  cleaned = stripHtml(cleaned);

  // 4. Atenuação de Zalgo excessivo
  cleaned = cleaned.replace(EXCESSIVE_COMBINING_MARKS_REGEX, (match) => match.slice(0, 2));

  // 5. Remoção de caracteres de controle
  cleaned = cleaned.replace(CONTROL_AND_ZERO_WIDTH_REGEX, "");

  return cleaned.trim();
}
