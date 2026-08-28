import { describe, expect, it } from "vitest";
import { AutonomousSecurityAIOrchestrator } from "@/agents/ai/autonomous-orchestrator";
import { BuiltinCognitiveSimulator } from "@/agents/ai/llm-provider";

describe("🧠 CyberBrain: Orquestração Cognitiva Autônoma de Segurança", () => {
  it("executa o ciclo cognitivo completo e retorna diagnóstico, novos testes e auto-patches estruturados", async () => {
    const simulator = new BuiltinCognitiveSimulator();
    const orchestrator = new AutonomousSecurityAIOrchestrator(simulator);

    const result = await orchestrator.runCognitiveCycle(".");

    expect(result.providerUsed).toContain("Cognitive");
    expect(result.aiAnalysis).toBeDefined();

    // Validação do Thought Process
    expect(result.aiAnalysis.thoughtProcess.length).toBeGreaterThan(0);

    // Validação do Diagnóstico
    expect(result.aiAnalysis.cognitiveDiagnosis.threatAssessment).toBeDefined();

    // Validação dos Novos Testes Propostos pela IA
    expect(result.aiAnalysis.recommendedExploratoryTests.length).toBeGreaterThan(0);
    expect(result.aiAnalysis.recommendedExploratoryTests[0].testName).toBeDefined();

    // Validação do Auto-Patching
    expect(result.aiAnalysis.autoPatches.length).toBeGreaterThan(0);
    expect(result.aiAnalysis.autoPatches[0].patchCode).toBeDefined();
  });
});
