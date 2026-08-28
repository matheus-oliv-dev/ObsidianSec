import { describe, expect, it } from "vitest";
import {
  containsPrototypePollution,
  safeDeepClone,
  safeMerge,
} from "@/lib/security/prototype-shield";

describe("🛡️ Prototype Shield: Proteção contra Prototype Pollution (CWE-1321)", () => {
  describe("1. Detecção de Chaves Perigosas", () => {
    it("detecta payloads JSON contendo __proto__ ou constructor", () => {
      const maliciousPayload = JSON.parse('{"name": "test", "__proto__": {"isAdmin": true}}');
      expect(containsPrototypePollution(maliciousPayload)).toBe(true);
    });

    it("detecta tentativas aninhadas de poluição de protótipo", () => {
      const nestedPayload = {
        user: {
          profile: {
            constructor: {
              prototype: { hacked: true },
            },
          },
        },
      };
      expect(containsPrototypePollution(nestedPayload)).toBe(true);
    });
  });

  describe("2. Clonagem e Merge Seguro de Objetos", () => {
    it("descarta propriedades __proto__ durante safeDeepClone sem poluir Object global", () => {
      const payload = JSON.parse('{"validProp": "safe", "__proto__": {"polluted": true}}');
      const cloned = safeDeepClone(payload);

      expect(cloned.validProp).toBe("safe");
      expect((cloned as any).polluted).toBeUndefined();
      expect((({} as any).polluted)).toBeUndefined();
    });

    it("mescla objetos seguramente sem permitir sobrescrita do protótipo base", () => {
      const base = { theme: "dark" };
      const patch = JSON.parse('{"theme": "light", "__proto__": {"isAdmin": true}}');

      const merged = safeMerge(base, patch);
      expect(merged.theme).toBe("light");
      expect((({} as any).isAdmin)).toBeUndefined();
    });
  });
});
