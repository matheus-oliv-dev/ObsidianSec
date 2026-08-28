import { z } from "zod";

/**
 * Sanitiza apelidos removendo tags HTML, scripts e caracteres de controle perigosos.
 */
function sanitizeNickname(val: string): string {
  // Remove tags HTML
  let cleaned = val.replace(/<[^>]*>?/gm, "");
  // Remove caracteres de controle ASCII perigosos (\x00-\x1F exceto espaço)
  cleaned = cleaned.replace(/[\u0000-\u001F\u007F-\u009F]/g, "");
  // Normaliza Unicode NFKC
  cleaned = cleaned.normalize("NFKC");
  return cleaned.trim();
}

export const nicknameSchema = z
  .string()
  .min(1, { message: "Apelido não pode ser vazio" })
  .max(30, { message: "Apelido muito longo (máximo 30 caracteres)" })
  .transform((val) => sanitizeNickname(val))
  .refine((val) => val.length > 0, {
    message: "Apelido inválido após sanitização",
  })
  .refine((val) => val.length <= 30, {
    message: "Apelido excede tamanho máximo",
  });

export const roomCodeSchema = z
  .string()
  .min(4)
  .max(10)
  .regex(/^[A-Z0-9_-]+$/i, { message: "Código de sala deve ser alfanumérico" })
  .transform((val) => val.toUpperCase());
