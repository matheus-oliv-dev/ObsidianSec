/**
 * Dynamic Custom Security Rule Loader
 * Permite que equipes de segurança e empresas adicionem seus próprios patterns de
 * credenciais e regras proprietárias via obsidiansec.rules.json ou obsidiansec.config.json.
 */

import fs from "node:fs";
import path from "node:path";
import { type SecretPattern } from "./local-secret-scanner.ts";

export interface CustomSecurityRuleDefinition {
  id: string;
  category?: "API_KEY" | "PRIVATE_KEY" | "SENSITIVE_FILE" | "CREDENTIAL" | "DANGEROUS_CODE";
  description: string;
  pattern: string;
  flags?: string;
  severity?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
}

/**
 * Converte uma lista de definições JSON em objetos RegExp compilados com segurança
 */
export function compileCustomRules(definitions: CustomSecurityRuleDefinition[]): SecretPattern[] {
  const compiled: SecretPattern[] = [];

  for (const def of definitions) {
    if (!def.id || !def.pattern || !def.description) continue;

    try {
      const regex = new RegExp(def.pattern, def.flags || "");
      compiled.push({
        id: def.id,
        category: def.category || "API_KEY",
        description: def.description,
        regex,
        severity: def.severity || "HIGH",
      });
    } catch (err: any) {
      console.warn(`[RULES] Aviso: Padrão regex inválido na regra customizada '${def.id}': ${err.message}`);
    }
  }

  return compiled;
}

/**
 * Carrega regras customizadas a partir de obsidiansec.rules.json ou obsidiansec.config.json
 */
export function loadCustomSecurityRules(targetDir: string = process.cwd()): SecretPattern[] {
  const rulesJsonPath = path.resolve(targetDir, "obsidiansec.rules.json");
  const configJsonPath = path.resolve(targetDir, "obsidiansec.config.json");

  // 1. Tenta ler obsidiansec.rules.json
  try {
    if (fs.existsSync(rulesJsonPath)) {
      const raw = fs.readFileSync(rulesJsonPath, "utf-8");
      const parsed = JSON.parse(raw);
      const list = Array.isArray(parsed) ? parsed : parsed.rules || [];
      return compileCustomRules(list);
    }
  } catch (err: any) {
    console.warn(`[RULES] Aviso: Falha ao ler ${rulesJsonPath}: ${err.message}`);
  }

  // 2. Tenta ler a chave customRules de obsidiansec.config.json
  try {
    if (fs.existsSync(configJsonPath)) {
      const raw = fs.readFileSync(configJsonPath, "utf-8");
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed.customRules)) {
        return compileCustomRules(parsed.customRules);
      }
    }
  } catch {
    // Ignora
  }

  return [];
}

/**
 * Funde os patterns embutidos com patterns customizados (evitando IDs duplicados)
 */
export function mergeSecretPatterns(
  basePatterns: SecretPattern[],
  customPatterns: SecretPattern[]
): SecretPattern[] {
  const customIds = new Set(customPatterns.map((p) => p.id));
  const filteredBase = basePatterns.filter((p) => !customIds.has(p.id));
  return [...filteredBase, ...customPatterns];
}
