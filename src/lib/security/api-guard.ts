import { z } from "zod";

/**
 * Filtra e higieniza objetos de resposta da API para prevenir Excessive Data Exposure (OWASP API3).
 */
export function sanitizeApiOutput<T extends Record<string, any>>(data: T, blacklistedKeys = ["password", "password_hash", "token_secret", "mfa_secret", "credit_card"]): Partial<T> {
  if (!data || typeof data !== "object") return data;

  const result: Record<string, any> = {};
  for (const [k, v] of Object.entries(data)) {
    if (!blacklistedKeys.includes(k.toLowerCase())) {
      result[k] = v;
    }
  }
  return result as Partial<T>;
}

/**
 * Coerção segura de parâmetros de paginação para prevenir Unrestricted Resource Consumption (OWASP API4).
 */
export function sanitizePagination(pageInput?: string | number, limitInput?: string | number, maxLimit = 100): { page: number; limit: number; offset: number } {
  const parsedPage = Math.max(1, parseInt(String(pageInput || 1), 10) || 1);
  const rawLimit = parseInt(String(limitInput || 20), 10) || 20;
  const parsedLimit = Math.min(maxLimit, Math.max(1, rawLimit));

  return {
    page: parsedPage,
    limit: parsedLimit,
    offset: (parsedPage - 1) * parsedLimit,
  };
}

/**
 * Simulador de Bloqueio Atômico de Transação contra Race Conditions (TOCTOU).
 */
export class AtomicLockManager {
  private locks = new Set<string>();

  public async executeWithLock<T>(lockKey: string, action: () => Promise<T>): Promise<T> {
    if (this.locks.has(lockKey)) {
      throw new Error(`[ConflictError]: Recurso em uso concorrente (Lock ativo: ${lockKey})`);
    }

    this.locks.add(lockKey);
    try {
      return await action();
    } finally {
      this.locks.delete(lockKey);
    }
  }
}
