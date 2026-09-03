#!/usr/bin/env node
import { AutonomousSecurityAIOrchestrator } from "../src/agents/ai/autonomous-orchestrator.ts";

const target = process.argv[2] || ".";

console.log("\n╔══════════════════════════════════════════════════════════════════════╗");
console.log("║    🧠 CHIMERAGUARD CYBERBRAIN · ORQUESTRADOR COGNITIVO COM IA        ║");
console.log("║    Alvo: " + target.padEnd(52) + "║");
console.log("╚══════════════════════════════════════════════════════════════════════╝");

async function main() {
  const orchestrator = new AutonomousSecurityAIOrchestrator();
  const result = await orchestrator.runCognitiveCycle(target);

  console.log("\n======================================================================");
  console.log(`🤖 PROVEDOR DE IA EM USO: [${result.providerUsed}]`);
  console.log("======================================================================");

  console.log("\n🧠 PROCESSO DE RACIOCÍNIO DO CYBERBRAIN (THOUGHT PROCESS):");
  result.aiAnalysis.thoughtProcess.forEach((t) => console.log(`  💭 ${t}`));

  console.log("\n🔬 DIAGNÓSTICO COGNITIVO & CAUSA-RAIZ:");
  console.log(`  🛡️  Avaliação de Risco: ${result.aiAnalysis.cognitiveDiagnosis.threatAssessment}`);
  if (result.aiAnalysis.cognitiveDiagnosis.rootCause) {
    console.log(`  🔍 Causa-Raiz:         ${result.aiAnalysis.cognitiveDiagnosis.rootCause}`);
  }

  if (
    result.aiAnalysis.recommendedExploratoryTests &&
    result.aiAnalysis.recommendedExploratoryTests.length > 0
  ) {
    console.log("\n🧪 NOVOS TESTES EXPLORATÓRIOS PROPOSTOS PELA IA:");
    result.aiAnalysis.recommendedExploratoryTests.forEach((test, idx) => {
      console.log(`\n  👉 [Teste ${idx + 1}] ${test.testName} (Escopo: ${test.targetScope})`);
      console.log(`     ↳ Motivação: ${test.rationale}`);
      if (test.suggestedPayloadOrLogic) {
        console.log(`     ↳ Lógica:    ${test.suggestedPayloadOrLogic}`);
      }
    });
  }

  if (result.aiAnalysis.autoPatches && result.aiAnalysis.autoPatches.length > 0) {
    console.log("\n======================================================================");
    console.log("🔧 AUTO-PATCHES SINTETIZADOS PELA IA (PRONTOS PARA APLICAÇÃO)");
    console.log("======================================================================");
    result.aiAnalysis.autoPatches.forEach((patch, idx) => {
      console.log(`\n📁 Patch #${idx + 1} para: ${patch.file}`);
      console.log(`📝 Descrição: ${patch.description}`);
      console.log("----------------------------------------------------------------------");
      console.log(patch.patchCode);
      console.log("----------------------------------------------------------------------");
    });
  }

  console.log("\n======================================================================");
  console.log(`🏆 PARECER FINAL: ${result.aiAnalysis.verdict}`);
  console.log(`⚖️  CONSELHO QUALITY GATE: ${result.aiAnalysis.qualityGateAdvice}`);
  console.log("======================================================================\n");
}

main().catch(console.error);
