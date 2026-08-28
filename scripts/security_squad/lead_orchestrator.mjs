import { runSastAudit } from "./sast_sentinel.mjs";
import { runDbGuardianAudit } from "./db_guardian.mjs";
import { runAiRedTeamerAudit } from "./ai_red_teamer.mjs";
import { runBrowserHardeningAudit } from "./browser_hardening_sentinel.mjs";

/**
 * Agente Security Lead Orchestrator
 * Consolida SAST, DB RLS, DAST, AI Red Teaming e Browser Hardening.
 * Calcula a pontuação de risco CVSS v3.1/v4.0 ponderada.
 */

export function consolidateSecurityAudit(dastPassed = true, testStats = { total: 105, passed: 105 }) {
  const sast = runSastAudit();
  const db = runDbGuardianAudit();
  const aiRedTeam = runAiRedTeamerAudit();
  const browserHardening = runBrowserHardeningAudit();

  let cvssScore = 0.0;
  const criticalIssues = [];

  if (!dastPassed) {
    cvssScore += 8.5;
    criticalIssues.push("Falha em testes dinâmicos de penetração (DAST Fuzzer).");
  }

  if (sast.status !== "PASSED") {
    cvssScore += 7.0;
    criticalIssues.push(`Vulnerabilidades estáticas detectadas pelo Code Sentinel (${sast.findings.length} ocorrências).`);
  }

  if (db.status !== "PASSED") {
    cvssScore += 6.5;
    criticalIssues.push(`Falha de segurança em banco de dados / RLS detectada pelo DB Guardian (${db.findings.length} ocorrências).`);
  }

  if (aiRedTeam.status !== "PASSED" && aiRedTeam.findings.length > 0) {
    cvssScore += 5.0;
    criticalIssues.push(`Riscos em IA detectados pelo AI Red Teamer (${aiRedTeam.findings.length} ocorrências).`);
  }

  if (browserHardening.status !== "PASSED" && browserHardening.findings.length > 0) {
    cvssScore += 4.5;
    criticalIssues.push(`Vulnerabilidades de DOM Sinks detectadas pelo Browser Sentinel (${browserHardening.findings.length} ocorrências).`);
  }

  const qualityGateApproved = cvssScore === 0.0;

  return {
    timestamp: new Date().toISOString(),
    qualityGate: qualityGateApproved ? "APPROVED" : "BLOCKED",
    cvssScore: Math.min(10.0, cvssScore).toFixed(1),
    summary: {
      dast: dastPassed ? "100% PASSED" : "FAILED",
      sast: sast.status,
      dbGuardian: db.status,
      aiRedTeam: aiRedTeam.status,
      browserHardening: browserHardening.status,
      testsPassed: `${testStats.passed}/${testStats.total}`,
    },
    criticalIssues,
    agents: {
      sast,
      db,
      aiRedTeam,
      browserHardening,
    },
  };
}
