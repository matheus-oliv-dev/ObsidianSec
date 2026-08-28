import { verifyAccessToken } from "@/lib/security/token";
import type { AccessTokenClaims } from "@/types";

export type RequireAdminResult =
  | { admin: AccessTokenClaims }
  | { error: { status: number; message: string } };

/**
 * Validador estrito de privilégios de administrador (Zero-Trust Guard).
 * Exige cabeçalho de Autorização Bearer e papel de segurança 'ADMIN'.
 */
export async function requireAdmin(request: Request): Promise<RequireAdminResult> {
  const authHeader = request.headers.get("authorization") || request.headers.get("Authorization");

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return {
      error: {
        status: 401,
        message: "Cabeçalho Authorization Bearer ausente ou inválido.",
      },
    };
  }

  const token = authHeader.substring(7).trim();
  const claims = await verifyAccessToken(token);

  if (!claims) {
    return {
      error: {
        status: 401,
        message: "Token de acesso inválido ou expirado.",
      },
    };
  }

  if (claims.role !== "ADMIN") {
    return {
      error: {
        status: 403,
        message: "Acesso proibido: permissões de administrador requeridas.",
      },
    };
  }

  return { admin: claims };
}
