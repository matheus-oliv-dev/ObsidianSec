import { type ObsidianConfig, DEFAULT_OBSIDIAN_CONFIG } from "../config/obsidian-config.ts";

export interface ScopeValidationResult {
  allowed: boolean;
  target: string;
  normalizedHost: string;
  matchedRule?: string;
  reason?: string;
  errorCode?: "SCOPE_BLOCKED" | "SCOPE_NOT_IN_ALLOWLIST" | "INVALID_TARGET";
}

/**
 * Normaliza o alvo para extrair o hostname ou domínio base para validação
 */
export function normalizeTargetToHost(target: string): string {
  if (!target || typeof target !== "string") return "";
  let clean = target.trim().toLowerCase();

  // Remove protocolo
  if (clean.startsWith("http://")) clean = clean.slice(7);
  if (clean.startsWith("https://")) clean = clean.slice(8);

  // Remove caminhos, query strings e fragmentos
  clean = clean.split("/")[0].split("?")[0].split("#")[0];

  // Remove porta (ex: localhost:3000 -> localhost)
  clean = clean.split(":")[0];

  return clean;
}

/**
 * Verifica se um host corresponde a um padrão glob simples (ex: *.empresa.com)
 */
export function matchesHostPattern(host: string, pattern: string): boolean {
  if (!host || !pattern) return false;
  const h = host.toLowerCase().trim();
  const p = pattern.toLowerCase().trim();

  // Match exato
  if (h === p) return true;

  // Wildcard de prefixo (ex: *.empresa.com ou *.gov.br)
  if (p.startsWith("*.")) {
    const baseDomain = p.slice(2);
    return h === baseDomain || h.endsWith("." + baseDomain);
  }

  // Wildcard de sufixo ou genérico
  if (p.includes("*")) {
    const regex = new RegExp("^" + p.replace(/\./g, "\\.").replace(/\*/g, ".*") + "$");
    return regex.test(h);
  }

  return false;
}

/**
 * Validador de Perímetro e Escopo Autorizado (Scope Guard)
 * Garante que nenhuma auditoria seja disparada acidentalmente contra alvos proibidos
 * ou fora do perímetro configurado no projeto.
 */
export function validateTargetScope(
  target: string,
  config: ObsidianConfig = DEFAULT_OBSIDIAN_CONFIG
): ScopeValidationResult {
  const host = normalizeTargetToHost(target);

  if (!host) {
    return {
      allowed: false,
      target,
      normalizedHost: "",
      errorCode: "INVALID_TARGET",
      reason: "Alvo inválido ou não foi possível extrair o hostname.",
    };
  }

  // 1. Checa Blocklist (Prioridade Máxima de Segurança)
  const blocklist = config.scope.blocklist || [];
  for (const blockPattern of blocklist) {
    if (matchesHostPattern(host, blockPattern)) {
      return {
        allowed: false,
        target,
        normalizedHost: host,
        matchedRule: blockPattern,
        errorCode: "SCOPE_BLOCKED",
        reason: `Alvo '${host}' bloqueado pela regra de exclusão: '${blockPattern}'.`,
      };
    }
  }

  // 2. Checa Allowlist se o Strict Mode estiver ativo ou se a allowlist não estiver vazia
  const allowlist = config.scope.allowlist || [];
  const strictMode = config.scope.strictMode;

  if (strictMode || allowlist.length > 0) {
    let matchedAllowRule: string | undefined;

    for (const allowPattern of allowlist) {
      if (matchesHostPattern(host, allowPattern)) {
        matchedAllowRule = allowPattern;
        break;
      }
    }

    if (!matchedAllowRule) {
      return {
        allowed: false,
        target,
        normalizedHost: host,
        errorCode: "SCOPE_NOT_IN_ALLOWLIST",
        reason: `Alvo '${host}' não consta na lista de escopos autorizados (allowlist) em obsidiansec.config.json.`,
      };
    }

    return {
      allowed: true,
      target,
      normalizedHost: host,
      matchedRule: matchedAllowRule,
      reason: `Alvo autorizado pela regra de escopo: '${matchedAllowRule}'.`,
    };
  }

  // Se não houver allowlist e strictMode estiver desativado, o alvo é permitido desde que não bloqueado
  return {
    allowed: true,
    target,
    normalizedHost: host,
    reason: "Alvo dentro do escopo geral (permissivo por padrão).",
  };
}
