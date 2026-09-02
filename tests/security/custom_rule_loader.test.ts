import { describe, it, expect } from "vitest";
import {
  compileCustomRules,
  mergeSecretPatterns,
  type CustomSecurityRuleDefinition,
} from "../../src/lib/security/custom-rule-loader.ts";
import { SECRET_PATTERNS } from "../../src/lib/security/local-secret-scanner.ts";

describe("🧩 Dynamic Custom Security Rule Loader", () => {
  it("compila regras customizadas com flags e regex válidos", () => {
    const definitions: CustomSecurityRuleDefinition[] = [
      {
        id: "corp-token",
        category: "API_KEY",
        description: "Token Corporativo Interno",
        pattern: "CORP_KEY_[0-9A-Z]{20}",
        flags: "i",
        severity: "CRITICAL",
      },
    ];

    const compiled = compileCustomRules(definitions);
    expect(compiled).toHaveLength(1);
    expect(compiled[0].id).toBe("corp-token");
    expect(compiled[0].regex.test("corp_key_12345678901234567890")).toBe(true);
  });

  it("ignora regras com regex malformada sem disparar exceção", () => {
    const definitions: CustomSecurityRuleDefinition[] = [
      {
        id: "broken-regex",
        description: "Regex Inválida",
        pattern: "[a-z(",
      },
      {
        id: "valid-regex",
        description: "Regex Válida",
        pattern: "VALID_TOKEN_[0-9]{4}",
      },
    ];

    const compiled = compileCustomRules(definitions);
    expect(compiled).toHaveLength(1);
    expect(compiled[0].id).toBe("valid-regex");
  });

  it("funde patterns embutidos com patterns customizados sem duplicar IDs", () => {
    const customRules = compileCustomRules([
      {
        id: "aws-access-key", // Sobrescreve a regra embutida
        description: "Custom AWS Rule",
        pattern: "CUSTOM_AWS_KEY_[0-9]{10}",
      },
      {
        id: "custom-token",
        description: "Nova Regra",
        pattern: "NEW_TOKEN_[0-9]{5}",
      },
    ]);

    const merged = mergeSecretPatterns(SECRET_PATTERNS, customRules);
    expect(merged.length).toBe(SECRET_PATTERNS.length + 1);

    const awsRule = merged.find((r) => r.id === "aws-access-key");
    expect(awsRule?.description).toBe("Custom AWS Rule");
  });
});
