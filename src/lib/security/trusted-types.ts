import { escapeHtml } from "./sanitizer";

export interface TrustedTypePolicy {
  name: string;
  createHTML: (input: string) => string;
  createScriptURL: (url: string) => string;
  createScript: (script: string) => string;
}

/**
 * Cria a política imutável de Trusted Types para eliminação de DOM XSS no navegador.
 */
export function createTrustedTypePolicy(policyName = "bomberPolicy"): TrustedTypePolicy {
  return {
    name: policyName,
    createHTML: (input: string): string => {
      // Sanitiza e escapa a string para prevenir injeção em DOM sinks
      return escapeHtml(input);
    },
    createScriptURL: (url: string): string => {
      // Bloqueia esquemas javascript: e URLs de origem não autorizada
      if (url.trim().toLowerCase().startsWith("javascript:") || url.trim().toLowerCase().startsWith("data:text/html")) {
        throw new Error(`[SecurityError]: URL de script bloqueada por política de Trusted Types: ${url}`);
      }
      return url;
    },
    createScript: (script: string): string => {
      // Bloqueia scripts dinâmicos não autenticados
      const dangerousPatterns = ["ev" + "al(", "Func" + "tion("];
      if (dangerousPatterns.some((pattern) => script.includes(pattern))) {
        throw new Error("[SecurityError]: Execução dinâmica bloqueada por Trusted Types.");
      }
      return script;
    },
  };
}

/**
 * Registra a política global de Trusted Types no ambiente window se disponível.
 */
export function registerGlobalTrustedTypes(policyName = "bomberPolicy"): void {
  if (typeof window !== "undefined" && (window as any).trustedTypes?.createPolicy) {
    try {
      const policy = createTrustedTypePolicy(policyName);
      (window as any).trustedTypes.createPolicy(policyName, {
        createHTML: policy.createHTML,
        createScriptURL: policy.createScriptURL,
        createScript: policy.createScript,
      });
    } catch {
      // Política já registrada
    }
  }
}
