export interface CspAnalysisResult {
  policy: string;
  directives: Record<string, string[]>;
  strengths: string[];
  warnings: string[];
  score: number; // 0 a 100
}

/**
 * Analisador estático de políticas Content-Security-Policy (CSP).
 * Valida a presença de diretivas essenciais e identifica potenciais fragilidades (ex: 'unsafe-inline', wildcards).
 */
export function analyzeCspPolicy(cspString: string): CspAnalysisResult {
  const directives: Record<string, string[]> = {};
  const rawParts = cspString.split(";").map((p) => p.trim()).filter(Boolean);

  for (const part of rawParts) {
    const [name, ...values] = part.split(/\s+/);
    if (name) {
      directives[name.toLowerCase()] = values.map((v) => v.toLowerCase());
    }
  }

  const strengths: string[] = [];
  const warnings: string[] = [];
  let score = 100;

  // 1. Verificação de default-src ou script-src
  if (!directives["default-src"] && !directives["script-src"]) {
    warnings.push("Falta diretiva de fallback 'default-src' ou 'script-src'.");
    score -= 30;
  } else {
    strengths.push("Diretiva de origem base configurada.");
  }

  // 2. Verificação de frame-ancestors (Anti-Clickjacking)
  if (directives["frame-ancestors"]) {
    strengths.push(`Proteção contra Clickjacking ativa (frame-ancestors: ${directives["frame-ancestors"].join(" ")}).`);
  } else {
    warnings.push("Falta 'frame-ancestors' para proteção anti-Clickjacking no CSP.");
    score -= 15;
  }

  // 3. Verificação de object-src (Plugins legados como Flash/Java)
  if (directives["object-src"]?.includes("'none'")) {
    strengths.push("Injeção de plugins legados bloqueada (object-src 'none').");
  } else {
    warnings.push("Recomendado definir 'object-src 'none'' para impedir carregamento de objetos legados.");
    score -= 10;
  }

  // 4. Análise de 'unsafe-inline' em script-src
  const scriptSources = directives["script-src"] || directives["default-src"] || [];
  if (scriptSources.includes("'unsafe-inline'")) {
    warnings.push("Uso de 'unsafe-inline' em script-src reduz a proteção contra XSS inline (considere usar Nonces ou CSP Level 3 com 'strict-dynamic').");
    score -= 20;
  } else {
    strengths.push("Execução de scripts inline não autorizados bloqueada.");
  }

  // 5. Análise de 'unsafe-eval'
  if (scriptSources.includes("'unsafe-eval'")) {
    warnings.push("Uso de 'unsafe-eval' permite execução dinâmica via eval().");
    score -= 15;
  }

  // 6. Verificação de require-trusted-types-for
  if (directives["require-trusted-types-for"]) {
    strengths.push("W3C Trusted Types habilitado para imunidade a DOM XSS.");
    score = Math.min(100, score + 10);
  }

  return {
    policy: cspString,
    directives,
    strengths,
    warnings,
    score: Math.max(0, score),
  };
}

/**
 * Simula a decisão de um navegador ao tentar carregar um recurso sob o CSP.
 */
export function simulateCspDecision(
  csp: string,
  resourceType: "script" | "style" | "image" | "connect" | "frame",
  resourceOrigin: string,
  isInline = false
): { allowed: boolean; directiveChecked: string; reason: string } {
  const analysis = analyzeCspPolicy(csp);
  const directiveMap: Record<string, string> = {
    script: "script-src",
    style: "style-src",
    image: "img-src",
    connect: "connect-src",
    frame: "frame-ancestors",
  };

  const directiveName = directiveMap[resourceType];
  const allowedValues = analysis.directives[directiveName] || analysis.directives["default-src"] || [];

  if (allowedValues.length === 0) {
    return {
      allowed: false,
      directiveChecked: directiveName,
      reason: "Nenhuma diretiva aplicável encontrada no CSP.",
    };
  }

  if (isInline) {
    if (allowedValues.includes("'unsafe-inline'")) {
      return {
        allowed: true,
        directiveChecked: directiveName,
        reason: "Permitido devido à presença de 'unsafe-inline'.",
      };
    }
    return {
      allowed: false,
      directiveChecked: directiveName,
      reason: "Bloqueado: Scripts/Estilos inline são proibidos sem 'unsafe-inline' ou nonce.",
    };
  }

  if (allowedValues.includes("'none'")) {
    return {
      allowed: false,
      directiveChecked: directiveName,
      reason: "Bloqueado: A diretiva está definida como 'none'.",
    };
  }

  if (allowedValues.includes("*") || allowedValues.includes("https:")) {
    return {
      allowed: true,
      directiveChecked: directiveName,
      reason: "Permitido por regra ampla (https: ou *).",
    };
  }

  if (allowedValues.includes("'self'") && (resourceOrigin === "self" || resourceOrigin === "same-origin")) {
    return {
      allowed: true,
      directiveChecked: directiveName,
      reason: "Permitido: Recurso é da mesma origem ('self').",
    };
  }

  return {
    allowed: false,
    directiveChecked: directiveName,
    reason: `Bloqueado: Origem '${resourceOrigin}' não consta na lista de permissões da diretiva '${directiveName}'.`,
  };
}
