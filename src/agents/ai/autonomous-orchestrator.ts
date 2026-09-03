import { getAutoLLMProvider, type LLMProvider, type LLMMessage } from "./llm-provider.ts";
import { CYBERBRAIN_SYSTEM_PROMPT } from "./prompts.ts";
import { runPolyglotAudit, type PolyglotAuditReport } from "../polyglot/engine.ts";
import { auditUniversalEndpoint, type UniversalAuditReport } from "../../scanner/universal-web-scanner.ts";
import { TokenBudgetGuard } from "./token-budget-guard.ts";
import { loadObsidianConfig as loadChimeraConfig, type ObsidianConfig as ChimeraConfig } from "../../lib/config/obsidian-config.ts";

export interface AICognitiveAnalysis {
  thoughtProcess: string[];
  cognitiveDiagnosis: {
    threatAssessment: string;
    rootCause?: string;
    attackVectors?: string[];
  };
  recommendedExploratoryTests: Array<{
    testName: string;
    targetScope: string;
    rationale: string;
    suggestedPayloadOrLogic?: string;
  }>;
  autoPatches: Array<{
    file: string;
    description: string;
    patchCode: string;
  }>;
  qualityGateAdvice: string;
  verdict: string;
}

export class AutonomousSecurityAIOrchestrator {
  private llm: LLMProvider;
  private budgetGuard: TokenBudgetGuard;
  private isCustomOrSimulated: boolean;

  constructor(customProvider?: LLMProvider, customBudgetGuard?: TokenBudgetGuard) {
    this.llm = customProvider || getAutoLLMProvider();
    this.budgetGuard = customBudgetGuard || new TokenBudgetGuard();
    this.isCustomOrSimulated = customProvider !== undefined || this.llm.name.includes("Simulator") || this.llm.name.includes("Cognitive");
  }

  /**
   * Ciclo Cognitivo Autônomo com Salvaguarda de Tokens:
   * 1. Executa auditoria determinística local (~20ms, Custo R$ 0,00).
   * 2. Gera fingerprint SHA-256 do achado.
   * 3. Consulta TokenBudgetGuard: se já estiver em cache ou se a IA estiver desativada,
   *    retorna instantaneamente com custo zero de tokens.
   * 4. Se a IA estiver habilitada e dentro da cota, executa a inferência e salva no cache.
   */
  public async runCognitiveCycle(
    target: string,
    options: { forceAI?: boolean; config?: ChimeraConfig } = {}
  ): Promise<{
    deterministicReport: PolyglotAuditReport | UniversalAuditReport;
    aiAnalysis: AICognitiveAnalysis;
    providerUsed: string;
    tokenUsageSource: string;
  }> {
    const config = options.config || loadChimeraConfig();

    let rawLogData = "";
    let reportData: any;

    if (target.startsWith("http://") || target.startsWith("https://")) {
      const report = await auditUniversalEndpoint(target);
      reportData = report;
      rawLogData = JSON.stringify(report, null, 2);
    } else {
      const report = runPolyglotAudit(target);
      reportData = report;
      rawLogData = JSON.stringify(report, null, 2);
    }

    // Gera o fingerprint criptográfico para deduplicação
    const fingerprint = this.budgetGuard.generateFingerprint(target, rawLogData);
    const budgetStatus = this.budgetGuard.evaluateBudget(
      fingerprint,
      config,
      options.forceAI || this.isCustomOrSimulated
    );

    // Se já temos no cache, retorna com custo ZERO de tokens
    if (budgetStatus.source === "CACHE" && budgetStatus.cachedData) {
      return {
        deterministicReport: reportData,
        aiAnalysis: budgetStatus.cachedData,
        providerUsed: "Local Cache (Zero-Token)",
        tokenUsageSource: budgetStatus.source,
      };
    }

    // Se a IA estiver desativada ou orçamento estourado, usa o motor determinístico offline
    if (!budgetStatus.canInvoke) {
      const missed = Array.isArray(reportData?.securityHeaders)
        ? Object.entries(reportData.securityHeaders)
            .filter(([_, v]: any) => !v?.present)
            .map(([k]) => k)
        : [];

      const fallback = this.budgetGuard.generateDeterministicFallback(target, missed);
      return {
        deterministicReport: reportData,
        aiAnalysis: fallback,
        providerUsed: "Deterministic Heuristic Engine (Offline)",
        tokenUsageSource: budgetStatus.source,
      };
    }

    // Invocação controlada da IA
    const messages: LLMMessage[] = [
      { role: "system", content: CYBERBRAIN_SYSTEM_PROMPT },
      {
        role: "user",
        content: `Alvo auditado: ${target}
Abaixo estão os logs brutos e achados retornados pelo motor de testes do ChimeraGuard:

\`\`\`json
${rawLogData}
\`\`\`

Execute seu protocolo de 4 etapas: Diagnóstico Profundo, Triagem de Risco, Hipóteses de Novos Testes e Síntese de Auto-Patches. Responda estritamente em JSON.`,
      },
    ];

    let aiAnalysis: AICognitiveAnalysis;
    try {
      const responseText = await this.llm.generateResponse(messages, {
        temperature: 0.2,
        responseFormat: "json",
      });

      const cleaned = responseText.replace(/```json/g, "").replace(/```/g, "").trim();
      aiAnalysis = JSON.parse(cleaned);
      this.budgetGuard.recordAndCache(fingerprint, aiAnalysis, this.llm.name);
    } catch {
      aiAnalysis = this.budgetGuard.generateDeterministicFallback(target, []);
    }

    return {
      deterministicReport: reportData,
      aiAnalysis,
      providerUsed: this.llm.name,
      tokenUsageSource: budgetStatus.source,
    };
  }
}
