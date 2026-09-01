#!/usr/bin/env node
import { auditUniversalEndpoint } from "../src/scanner/universal-web-scanner.ts";
import { auditDomainDnsSecurity } from "../src/lib/security/dns-security-analyzer.ts";

const args = process.argv.slice(2);
const command = args[0] || "help";

const ANSI = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  red: "\x1b[31m",
  cyan: "\x1b[36m",
  gray: "\x1b[90m",
};

function printBanner() {
  console.log(`
${ANSI.bold}${ANSI.cyan}╔══════════════════════════════════════════════════════════════════════╗
║    🛡️  OBSIDIANSEC CLI // DEVSECOPS & EDGE AUDITING ENGINE 2026        ║
╚══════════════════════════════════════════════════════════════════════╝${ANSI.reset}
`);
}

async function runAudit() {
  const targetUrl = args[1];
  if (!targetUrl) {
    console.error(`${ANSI.red}❌ Erro: URL alvo não especificada.${ANSI.reset}`);
    console.log(`Uso: ${ANSI.bold}npx obsidiansec audit <url> [--min-grade=A] [--json]${ANSI.reset}`);
    process.exit(1);
  }

  const isJson = args.includes("--json");
  const minGradeArg = args.find((a) => a.startsWith("--min-grade="));
  const minGrade = minGradeArg ? minGradeArg.split("=")[1].toUpperCase() : "B";

  if (!isJson) printBanner();
  if (!isJson) console.log(`🔍 [1/2] Disparando sondagem tática de borda em ${ANSI.bold}${targetUrl}${ANSI.reset}...`);

  try {
    const report = await auditUniversalEndpoint(targetUrl);
    
    // Cálculo de Score
    let score = 0;
    const h = report.securityHeaders;
    if (h.csp.present) score += h.csp.isReportOnly ? 15 : 30;
    if (h.xFrameOptions.present) score += 20;
    if (h.hsts.present) score += 20;
    if (h.xContentTypeOptions.present) score += 15;
    if (h.permissionsPolicy.present) score += 15;
    score = Math.min(100, score);

    let grade = "F";
    if (score >= 85) grade = "A+";
    else if (score >= 70) grade = "A";
    else if (score >= 50) grade = "B";
    else if (score >= 30) grade = "C";

    if (isJson) {
      console.log(JSON.stringify({ ...report, score, grade }, null, 2));
      process.exit(0);
    }

    const gradeColor = (grade === "A+" || grade === "A") ? ANSI.green : grade === "B" ? ANSI.yellow : ANSI.red;

    console.log(`\n======================================================================`);
    console.log(`📊 RESULTADO DA AUDITORIA DE SEGURANÇA`);
    console.log(`======================================================================`);
    console.log(`• Alvo Auditado:           ${report.targetUrl}`);
    console.log(`• Servidor / Borda:        ${report.serverDetected}`);
    console.log(`• Score de Blindagem:      ${score} / 100`);
    console.log(`• Nota Final:              ${gradeColor}${ANSI.bold}GRADE ${grade}${ANSI.reset}`);
    console.log(`• Status:                  ${report.overallStatus === "SECURE" ? ANSI.green + "SEGURO" : ANSI.yellow + "AÇÃO REQUERIDA"}${ANSI.reset}`);
    console.log(`• Cadeia de Ataque:        ${report.attackChain.riskSummary}`);
    console.log(`======================================================================\n`);

    console.log(`🛡️  CONTROLES DE BORDA:`);
    console.log(`  [${h.csp.present ? ANSI.green + "✓" : ANSI.red + "✗"}${ANSI.reset}] Content-Security-Policy (CSP)`);
    console.log(`  [${h.xFrameOptions.present ? ANSI.green + "✓" : ANSI.red + "✗"}${ANSI.reset}] X-Frame-Options (Anti-Clickjacking)`);
    console.log(`  [${h.hsts.present ? ANSI.green + "✓" : ANSI.red + "✗"}${ANSI.reset}] Strict-Transport-Security (HSTS)`);
    console.log(`  [${h.xContentTypeOptions.present ? ANSI.green + "✓" : ANSI.red + "✗"}${ANSI.reset}] X-Content-Type-Options (nosniff)`);
    console.log(`  [${h.permissionsPolicy.present ? ANSI.green + "✓" : ANSI.red + "✗"}${ANSI.reset}] Permissions-Policy`);
    console.log(`\n======================================================================\n`);

    // Quality Gate Check para CI/CD
    const gradeRanks = { "A+": 5, "A": 4, "B": 3, "C": 2, "F": 1, "ERR": 0 };
    const currentRank = gradeRanks[grade] || 0;
    const requiredRank = gradeRanks[minGrade] || 3;

    if (currentRank < requiredRank) {
      console.error(`${ANSI.red}❌ [CI/CD Quality Gate]: Reprovado! A nota ${grade} é inferior à nota mínima exigida (${minGrade}).${ANSI.reset}\n`);
      process.exit(1);
    }

    console.log(`${ANSI.green}✅ [CI/CD Quality Gate]: Aprovado com sucesso! O deploy atende aos requisitos de segurança.${ANSI.reset}\n`);
    process.exit(0);
  } catch (err) {
    console.error(`\n${ANSI.red}❌ Falha na auditoria:${ANSI.reset} ${err.message}\n`);
    process.exit(1);
  }
}

async function runDns() {
  const domain = args[1];
  if (!domain) {
    console.error(`${ANSI.red}❌ Erro: Domínio não especificado.${ANSI.reset}`);
    console.log(`Uso: ${ANSI.bold}npx obsidiansec dns <dominio>${ANSI.reset}`);
    process.exit(1);
  }

  printBanner();
  console.log(`🔍 Consultando registros DNS e Anti-Phishing para ${ANSI.bold}${domain}${ANSI.reset}...\n`);

  try {
    const report = await auditDomainDnsSecurity(domain);
    console.log(`• Domínio:             ${report.domain}`);
    console.log(`• Score de Email:      ${report.emailSecurityScore} / 100`);
    console.log(`• Status:              ${report.overallStatus === "SECURE" ? ANSI.green + "SEGURO" : ANSI.yellow + "ALERTA"}${ANSI.reset}`);
    console.log(`• SPF:                 ${report.spf.present ? ANSI.green + "ATIVO (" + report.spf.qualifier + ")" : ANSI.red + "AUSENTE"}${ANSI.reset}`);
    console.log(`• DMARC:               ${report.dmarc.present ? ANSI.green + "ATIVO (p=" + report.dmarc.policy + ")" : ANSI.red + "AUSENTE"}${ANSI.reset}`);
    console.log(`• DNSSEC:              ${report.dnssecActive ? ANSI.green + "ATIVO" : ANSI.gray + "INATIVO"}${ANSI.reset}`);
    console.log(`\n======================================================================\n`);
  } catch (err) {
    console.error(`\n${ANSI.red}❌ Falha na auditoria DNS:${ANSI.reset} ${err.message}\n`);
  }
}

function printHelp() {
  printBanner();
  console.log(`Comandos disponíveis:

  ${ANSI.bold}obsidiansec audit <url>${ANSI.reset}         Audita cabeçalhos de segurança, cookies, CORS e cadeia de ataque
    Opções:
      --min-grade=<A|B|C>      Define a nota mínima para o Quality Gate de CI/CD (padrão: B)
      --json                   Retorna o relatório completo em formato JSON

  ${ANSI.bold}obsidiansec dns <dominio>${ANSI.reset}       Inspeciona registros SPF, DMARC e DNSSEC anti-phishing

  ${ANSI.bold}obsidiansec help${ANSI.reset}                Exibe este menu de ajuda
`);
}

switch (command) {
  case "audit":
    runAudit();
    break;
  case "dns":
    runDns();
    break;
  case "version":
  case "-v":
  case "--version":
    console.log("ObsidianSec CLI v1.0.0");
    break;
  default:
    printHelp();
    break;
}