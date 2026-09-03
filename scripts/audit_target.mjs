#!/usr/bin/env node
import fs from "node:fs";
import { runPolyglotAudit } from "../src/agents/polyglot/engine.ts";
import { auditUniversalEndpoint } from "../src/scanner/universal-web-scanner.ts";

const target = process.argv[2] || ".";

console.log("\n╔══════════════════════════════════════════════════════════════════════╗");
console.log("║    🌐 CHIMERAGUARD UNIVERSAL AUDITOR · QUALQUER LINGUAGEM OU SITE     ║");
console.log("║    Alvo: " + target.padEnd(52) + "║");
console.log("╚══════════════════════════════════════════════════════════════════════╝\n");

async function main() {
  if (target.startsWith("http://") || target.startsWith("https://") || target.includes(".")) {
    // Alvo remoto / URL
    if (target.startsWith("http://") || target.startsWith("https://")) {
      console.log("🔍 Detectado alvo Web ao vivo. Disparando auditoria universal de protocolos...\n");
      const report = await auditUniversalEndpoint(target);

      console.log(`📡 Status HTTP: ${report.httpStatus}`);
      console.log(`🖥️  Servidor Detectado: ${report.serverDetected}`);
      if (report.frameworkDetected) {
        console.log(`📦 Framework Detectado: ${report.frameworkDetected}`);
      }

      console.log("\n--- STATUS DOS CABEÇALHOS DE SEGURANÇA ---");
      const headers = report.securityHeaders;
      console.log(`${headers.csp.present ? "✅" : "❌"} Content-Security-Policy (CSP): ${headers.csp.present ? "ATIVO" : "AUSENTE"}`);
      console.log(`${headers.xFrameOptions.present ? "✅" : "❌"} X-Frame-Options (Clickjacking): ${headers.xFrameOptions.present ? "ATIVO" : "AUSENTE"}`);
      console.log(`${headers.xContentTypeOptions.present ? "✅" : "❌"} X-Content-Type-Options: ${headers.xContentTypeOptions.present ? "ATIVO" : "AUSENTE"}`);
      console.log(`${headers.permissionsPolicy.present ? "✅" : "❌"} Permissions-Policy: ${headers.permissionsPolicy.present ? "ATIVO" : "AUSENTE"}`);
      console.log(`${headers.hsts.present ? "✅" : "❌"} Strict-Transport-Security (HSTS): ${headers.hsts.present ? "ATIVO" : "AUSENTE"}`);

      console.log("\n======================================================================");
      console.log("🛠️  SNIPPETS DE CORREÇÃO PRONTOS POR LINGUAGEM / SERVIDOR");
      console.log("======================================================================");
      for (const snippet of report.remediationSnippets) {
        console.log(`\n📌 [${snippet.serverType}]:`);
        console.log(snippet.snippet);
      }
      console.log("\n======================================================================\n");
      return;
    }
  }

  // Alvo local (Pasta de código em qualquer linguagem)
  console.log("📂 Detectada pasta de código local. Disparando SAST Poliglota...\n");
  const polyReport = runPolyglotAudit(target);

  console.log(`📦 Linguagens Detectadas: ${polyReport.techStack.languages.join(", ") || "Nenhuma específica"}`);
  console.log(`🚀 Frameworks Identificados: ${polyReport.techStack.frameworks.join(", ") || "Genérico / Static"}`);
  console.log(`📄 Arquivos Escaneados: ${polyReport.filesScanned}`);
  console.log(`🛡️  Status do Quality Gate: ${polyReport.status === "PASSED" ? "✅ APROVADO (Zero Falhas)" : "❌ REQUER AÇÃO"}`);
  console.log(`📊 Pontuação de Risco CVSS: ${polyReport.cvssScore.toFixed(1)} / 10.0\n`);

  if (polyReport.findings.length > 0) {
    console.log("--- VULNERABILIDADES ENCONTRADAS ---");
    polyReport.findings.forEach((f, idx) => {
      console.log(`\n[${f.severity}] #${idx + 1} ${f.ruleName} (${f.language.toUpperCase()})`);
      console.log(`  📍 Local: ${f.file}:${f.line}`);
      console.log(`  🔍 Trecho: ${f.snippet}`);
      console.log(`  💡 Correção: ${f.remediation}`);
    });
    console.log("");
  } else {
    console.log("🎉 Nenhuma vulnerabilidade encontrada nos arquivos analisados!\n");
  }
}

main().catch(console.error);
