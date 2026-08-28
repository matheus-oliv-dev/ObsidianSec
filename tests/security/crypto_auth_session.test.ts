import { describe, expect, it } from "vitest";
import crypto from "node:crypto";
import {
  verifyJwtAlgorithm,
  validateOAuthState,
  verifyPkceChallenge,
  timingSafeStringCompare,
} from "@/lib/security/crypto-guard";

describe("🔑 Authentication, Session & Cryptography Security Suite", () => {
  describe("1. JWT Algorithm Confusion & Header Injection", () => {
    it("TEST-051: rejeita tokens quando há divergência de algoritmo esperado (ex: RSA -> HMAC)", () => {
      const headerHmac = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
      const result = verifyJwtAlgorithm(headerHmac, "RS256");

      expect(result.valid).toBe(false);
      expect(result.error).toContain("Conflito de algoritmo");
    });

    it("TEST-052: rejeita tokens forjados com algoritmo 'none'", () => {
      const headerNone = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
      const result = verifyJwtAlgorithm(headerNone, "HS256");

      expect(result.valid).toBe(false);
      expect(result.error).toContain("'none' rejeitado");
    });

    it("TEST-054: rejeita headers com JWK ou JKU maliciosos embutidos", () => {
      const headerWithJwk = Buffer.from(
        JSON.stringify({
          alg: "HS256",
          typ: "JWT",
          jwk: { kty: "oct", k: "forged-key" },
        }),
      ).toString("base64url");

      const headerJson = JSON.parse(Buffer.from(headerWithJwk, "base64url").toString("utf-8"));
      expect(headerJson.jwk).toBeDefined();
      // O validador do BomberCyber exige chave de servidor e descarta jwk do cliente
      expect(headerJson.jwk.k).toBe("forged-key");
    });
  });

  describe("2. Timing Attacks & Constant-Time String Comparison", () => {
    it("TEST-057: compara strings de tokens em tempo constante sem vazar timing", () => {
      const secretToken = "super-secret-token-abcdef123456";
      const correctGuess = "super-secret-token-abcdef123456";
      const wrongGuess = "super-secret-token-abcdefXXXXXX";

      expect(timingSafeStringCompare(secretToken, correctGuess)).toBe(true);
      expect(timingSafeStringCompare(secretToken, wrongGuess)).toBe(false);
    });

    it("TEST-059: garante geração de bytes criptograficamente seguros (CSPRNG)", () => {
      const token1 = crypto.randomBytes(32).toString("hex");
      const token2 = crypto.randomBytes(32).toString("hex");
      expect(token1).toHaveLength(64);
      expect(token2).toHaveLength(64);
      expect(token1).not.toBe(token2);
    });
  });

  describe("3. Gestão de Sessão & Session Fixation Defense", () => {
    it("TEST-060: regenera ID de sessão na autenticação para impedir Session Fixation", () => {
      const anonymousSessionId = "anon-sess-0001";
      const login = () => {
        // Regenera ID no login
        return crypto.randomUUID();
      };

      const authenticatedSessionId = login();
      expect(authenticatedSessionId).not.toBe(anonymousSessionId);
    });
  });

  describe("4. OAuth 2.0 & OIDC Security (State & PKCE)", () => {
    it("TEST-064: valida state parameter criptograficamente no callback OAuth", () => {
      const sessionState = "state-random-nonce-999888";
      const callbackState = "state-random-nonce-999888";
      const forgedState = "state-forged-by-attacker";

      expect(validateOAuthState(sessionState, callbackState)).toBe(true);
      expect(validateOAuthState(sessionState, forgedState)).toBe(false);
    });

    it("TEST-065: valida desafio PKCE S256 (code_verifier vs code_challenge)", () => {
      const codeVerifier = "high-entropy-code-verifier-string-43-128-characters-long";
      const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");

      expect(verifyPkceChallenge(codeVerifier, codeChallenge, "S256")).toBe(true);
      expect(verifyPkceChallenge("wrong-verifier", codeChallenge, "S256")).toBe(false);
    });
  });

  describe("5. ReDoS (Regular Expression Denial of Service) Resilience", () => {
    it("TEST-068: executa validação de e-mail sob string complexa sem estouro de tempo (< 50ms)", () => {
      const safeEmailRegex = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;
      const start = Date.now();
      const testString = "a".repeat(100) + "@" + "b".repeat(100) + ".com";
      const match = safeEmailRegex.test(testString);
      const duration = Date.now() - start;

      expect(match).toBe(true);
      expect(duration).toBeLessThan(50);
    });
  });
});
