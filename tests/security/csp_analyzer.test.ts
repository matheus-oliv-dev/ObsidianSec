import { describe, expect, it } from "vitest";
import { analyzeCspPolicy, simulateCspDecision } from "@/lib/security/csp-analyzer";

describe("🛡️ CSP Analyzer & Browser Decision Simulator", () => {
  const sampleCsp =
    "default-src 'self'; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; font-src 'self' data: https:; connect-src 'self' https: wss:; frame-ancestors 'none'; object-src 'none';";

  describe("1. Análise Estática da Política", () => {
    it("identifica corretamente todas as diretivas declaradas", () => {
      const result = analyzeCspPolicy(sampleCsp);

      expect(result.directives["default-src"]).toEqual(["'self'"]);
      expect(result.directives["frame-ancestors"]).toEqual(["'none'"]);
      expect(result.directives["object-src"]).toEqual(["'none'"]);
      expect(result.strengths.length).toBeGreaterThanOrEqual(3);
    });

    it("sinaliza o uso de 'unsafe-inline' como ponto de atenção", () => {
      const result = analyzeCspPolicy(sampleCsp);
      expect(result.warnings.some((w) => w.includes("unsafe-inline"))).toBe(true);
    });
  });

  describe("2. Simulação de Decisão do Navegador sob o CSP", () => {
    it("BLOQUEIA tentativa de embutir a página em um iframe malicioso (Clickjacking)", () => {
      const decision = simulateCspDecision(sampleCsp, "frame", "https://site-atacante.com");
      expect(decision.allowed).toBe(false);
      expect(decision.directiveChecked).toBe("frame-ancestors");
      expect(decision.reason).toContain("Bloqueado");
    });

    it("PERMITE carregar imagens locais ou via data URIs / https", () => {
      const localImage = simulateCspDecision(sampleCsp, "image", "self");
      expect(localImage.allowed).toBe(true);

      const httpsImage = simulateCspDecision(sampleCsp, "image", "https://cdn.exemplo.com");
      expect(httpsImage.allowed).toBe(true);
    });

    it("BLOQUEIA execução de scripts inline quando 'unsafe-inline' não está presente em CSP estrito", () => {
      const strictCsp = "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';";
      const inlineScriptDecision = simulateCspDecision(strictCsp, "script", "self", true); // true = inline

      expect(inlineScriptDecision.allowed).toBe(false);
      expect(inlineScriptDecision.reason).toContain("Bloqueado: Scripts/Estilos inline");
    });

    it("PERMITE conexões WebSocket (wss:) e HTTPS para APIs", () => {
      const wsDecision = simulateCspDecision(sampleCsp, "connect", "wss://api.stacca.app");
      expect(wsDecision.allowed).toBe(true);
    });
  });
});
