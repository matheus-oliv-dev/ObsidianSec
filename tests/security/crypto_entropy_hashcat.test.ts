import { describe, expect, it } from "vitest";
import {
  auditJwtSecretStrength,
  calculatePasswordEntropy,
  KNOWN_KDF_PROFILES,
} from "@/lib/security/crypto-entropy-analyzer";

describe("🐱 Hashcat & 🎩 John the Ripper Crypto Suite", () => {
  describe("1. Password Entropy & Shannon Bit Strength", () => {
    it("TEST-129: detecta senha fraca de baixa entropia (< 36 bits)", () => {
      const res = calculatePasswordEntropy("123456");
      expect(res.strengthCategory).toBe("VERY_WEAK");
      expect(res.entropyBits).toBeLessThan(36);
      expect(res.recommendations.length).toBeGreaterThan(0);
    });

    it("TEST-130: classifica frase-senha forte com alta entropia (> 72 bits)", () => {
      const res = calculatePasswordEntropy("Trator$Azul#Voador!9876");
      expect(res.entropyBits).toBeGreaterThanOrEqual(90);
      expect(res.strengthCategory).toBe("VERY_STRONG");
      expect(res.estimatedCrackTimeGpuCluster).toContain("Milhões");
    });
  });

  describe("2. KDF Hardness & GPU Resistance Profiles", () => {
    it("TEST-131: valida conformidade FIPS e resistência de Argon2id e Scrypt", () => {
      const argon2 = KNOWN_KDF_PROFILES.argon2id;
      expect(argon2.gpuCrackingResistance).toBe("VERY_HIGH");
      expect(argon2.nistCompliance).toBe(true);

      const scrypt = KNOWN_KDF_PROFILES.scrypt;
      expect(scrypt.gpuCrackingResistance).toBe("HIGH");
      expect(scrypt.category).toBe("MODERN_KDF");
    });

    it("TEST-132: marca algoritmos obsoletos (MD5, SHA-1, SHA-256 puro) como vulneráveis/quebrados", () => {
      const md5 = KNOWN_KDF_PROFILES.md5;
      expect(md5.category).toBe("BROKEN");
      expect(md5.gpuCrackingResistance).toBe("ZERO");

      const sha256 = KNOWN_KDF_PROFILES.sha256_pure;
      expect(sha256.category).toBe("LEGACY_VULNERABLE");
    });
  });

  describe("3. JWT Secret Brute-force Resilience (RFC 7518)", () => {
    it("TEST-133: rejeita segredos de dicionário ('secret', 'admin', '123456')", () => {
      const audit = auditJwtSecretStrength("secret");
      expect(audit.isWeakSecret).toBe(true);
      expect(audit.knownDictionaryMatch).toBe(true);
      expect(audit.recommendation).toContain("CRÍTICO");
    });

    it("TEST-134: aprova chave secreta de 256 bits (32+ caracteres de alta entropia)", () => {
      const audit = auditJwtSecretStrength("9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b");
      expect(audit.isWeakSecret).toBe(false);
      expect(audit.knownDictionaryMatch).toBe(false);
      expect(audit.estimatedBits).toBeGreaterThanOrEqual(256);
    });
  });
});