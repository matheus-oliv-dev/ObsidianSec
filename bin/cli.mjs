#!/usr/bin/env node
import { auditUniversalEndpoint } from "../src/scanner/universal-web-scanner.ts";
import { auditDomainDnsSecurity } from "../src/lib/security/dns-security-analyzer.ts";
import { scanDirectoryForSecrets } from "../src/lib/security/local-secret-scanner.ts";
import { auditJwtToken } from "../src/lib/security/jwt-token-analyzer.ts";
import { discoverSubdomains } from "../src/lib/security/subdomain-recon-analyzer.ts";
import { calculatePasswordEntropy } from "../src/lib/security/crypto-entropy-analyzer.ts";

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
  magenta: "\x1b[35m",
};

function printBanner() {
  console.log(`
${ANSI.bold}${ANSI.cyan}╔══════════════════════════════════════════════════════════════════════╗
║    🛡️  OBSIDIANSEC CLI // DEVSECOPS & EDGE AUDITING ARSENAL 2026      ║
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

async function runScanDir() {
  const dirInput = args[1] || process.cwd();
  const isJson = args.includes("--json");

  if (!isJson) printBanner();
  if (!isJson) console.log(`🔍 Varrendo arquivos e caçando segredos em ${ANSI.bold}${dirInput}${ANSI.reset}...\n`);

  const report = scanDirectoryForSecrets(dirInput);

  if (isJson) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(report.isClean ? 0 : 1);
  }

  console.log(`======================================================================`);
  console.log(`📊 RELATÓRIO DO CAÇADOR DE SEGREDOS & SAST LOCAL`);
  console.log(`======================================================================`);
  console.log(`• Arquivos Analisados:     ${report.totalFilesScanned}`);
  console.log(`• Duração:                 ${report.scanDurationMs}ms`);
  console.log(`• Vulnerabilidades:        ${report.isClean ? ANSI.green + "0 (LIMPO)" : ANSI.red + report.findings.length + " ENCONTRADAS"}${ANSI.reset}`);
  console.log(`• Críticas:                ${report.criticalCount > 0 ? ANSI.red + report.criticalCount : ANSI.green + "0"}${ANSI.reset}`);
  console.log(`• Altas:                   ${report.highCount > 0 ? ANSI.yellow + report.highCount : ANSI.green + "0"}${ANSI.reset}`);
  console.log(`======================================================================\n`);

  if (report.findings.length > 0) {
    console.log(`⚠️  VULNERABILIDADES DETECTADAS:`);
    report.findings.forEach((f, idx) => {
      const color = f.severity === "CRITICAL" ? ANSI.red : ANSI.yellow;
      console.log(`\n  [#${idx + 1}] ${color}${ANSI.bold}[${f.severity}] ${f.description}${ANSI.reset}`);
      console.log(`      📁 Arquivo: ${ANSI.cyan}${f.filePath}:${f.lineNumber}${ANSI.reset}`);
      console.log(`      🔍 Trecho:  ${ANSI.gray}${f.snippet}${ANSI.reset}`);
    });
    console.log(`\n${ANSI.red}❌ [SAST Gate]: Foram encontrados segredos sensíveis no código. Remova-os antes de publicar!${ANSI.reset}\n`);
    process.exit(1);
  } else {
    console.log(`${ANSI.green}✅ [SAST Gate]: Nenhum segredo ou credencial vazada detectada no código!${ANSI.reset}\n`);
    process.exit(0);
  }
}

async function runJwt() {
  const token = args[1];
  if (!token) {
    console.error(`${ANSI.red}❌ Erro: Token JWT não especificado.${ANSI.reset}`);
    console.log(`Uso: ${ANSI.bold}npx obsidiansec jwt <token>${ANSI.reset}`);
    process.exit(1);
  }

  const isJson = args.includes("--json");
  const report = auditJwtToken(token);

  if (isJson) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(report.status === "CRITICAL" ? 1 : 0);
  }

  printBanner();
  console.log(`🎟️ AUDITORIA DE SEGURANÇA DE TOKEN JWT\n`);

  if (!report.isValidStructure) {
    console.error(`${ANSI.red}❌ Formato inválido de JWT.${ANSI.reset}`);
    report.issues.forEach((i) => console.log(`  - ${i.message}`));
    process.exit(1);
  }

  const statusColor = report.status === "SECURE" ? ANSI.green : report.status === "WARNING" ? ANSI.yellow : ANSI.red;

  console.log(`• Algoritmo:           ${ANSI.bold}${report.algorithm}${ANSI.reset}`);
  console.log(`• Score de Segurança:  ${report.securityScore} / 100`);
  console.log(`• Status:              ${statusColor}${ANSI.bold}${report.status}${ANSI.reset}`);
  console.log(`• Assinatura Presente: ${report.signaturePresent ? ANSI.green + "SIM" : ANSI.red + "NÃO (alg: none)"}${ANSI.reset}`);
  console.log(`• Expiração:           ${report.hasExpiration ? (report.isExpired ? ANSI.red + "EXPIRADO" : ANSI.green + "VÁLIDO") : ANSI.yellow + "SEM EXPIRAÇÃO"}${ANSI.reset}`);

  console.log(`\n📜 HEADER DECODIFICADO:`);
  console.log(JSON.stringify(report.header, null, 2));

  console.log(`\n📦 PAYLOAD (CLAIMS):`);
  console.log(JSON.stringify(report.payload, null, 2));

  if (report.issues.length > 0) {
    console.log(`\n⚠️  RISCOS DETECTADOS:`);
    report.issues.forEach((iss) => {
      const color = iss.severity === "CRITICAL" ? ANSI.red : iss.severity === "HIGH" ? ANSI.yellow : ANSI.gray;
      console.log(`  ${color}[${iss.severity}] ${iss.message}${ANSI.reset}`);
    });
  }

  console.log(`\n======================================================================\n`);
  process.exit(report.status === "CRITICAL" ? 1 : 0);
}

async function runSubdomains() {
  const domain = args[1];
  if (!domain) {
    console.error(`${ANSI.red}❌ Erro: Domínio não especificado.${ANSI.reset}`);
    console.log(`Uso: ${ANSI.bold}npx obsidiansec subdomains <dominio>${ANSI.reset}`);
    process.exit(1);
  }

  const isJson = args.includes("--json");
  if (!isJson) printBanner();
  if (!isJson) console.log(`🌐 Buscando subdomínios via Certificate Transparency Logs para ${ANSI.bold}${domain}${ANSI.reset}...\n`);

  const report = await discoverSubdomains(domain);

  if (isJson) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(0);
  }

  console.log(`======================================================================`);
  console.log(`📊 SUPERFÍCIE DE ATAQUE PASSIVA (SUBDOMÍNIOS)`);
  console.log(`======================================================================`);
  console.log(`• Domínio Alvo:        ${report.domain}`);
  console.log(`• Total Descoberto:    ${ANSI.bold}${report.totalFound} subdomínios únicos${ANSI.reset}`);
  console.log(`• Fonte:               ${report.source}`);
  console.log(`• Duração:             ${report.durationMs}ms`);
  console.log(`======================================================================\n`);

  if (report.subdomains.length > 0) {
    report.subdomains.forEach((s) => console.log(`  ${ANSI.cyan}•${ANSI.reset} ${s}`));
  } else {
    console.log(`  Nenhum subdomínio adicional encontrado nos registros públicos.`);
  }

  console.log(`\n======================================================================\n`);
}

async function runEntropy() {
  const password = args[1];
  if (!password) {
    console.error(`${ANSI.red}❌ Erro: Senha não especificada.${ANSI.reset}`);
    console.log(`Uso: ${ANSI.bold}npx obsidiansec entropy <senha>${ANSI.reset}`);
    process.exit(1);
  }

  const isJson = args.includes("--json");
  const entropy = calculatePasswordEntropy(password);

  if (isJson) {
    console.log(JSON.stringify(entropy, null, 2));
    process.exit(0);
  }

  printBanner();
  console.log(`🔑 CALCULADORA DE ENTROPIA SHANNON & HASHCAT\n`);

  const strengthColor = entropy.strengthCategory === "VERY_STRONG" || entropy.strengthCategory === "STRONG" ? ANSI.green : entropy.strengthCategory === "FAIR" ? ANSI.yellow : ANSI.red;

  console.log(`• Tamanho da Senha:    ${entropy.length} caracteres`);
  console.log(`• Bits de Entropia:    ${ANSI.bold}${entropy.entropyBits} bits${ANSI.reset}`);
  console.log(`• Charset Estimado:    ${entropy.charsetSize} símbolos`);
  console.log(`• Nível de Força:      ${strengthColor}${ANSI.bold}${entropy.strengthCategory}${ANSI.reset}`);
  console.log(`• Tempo Estimado GPU:  ${ANSI.bold}${entropy.estimatedCrackTimeGpuCluster}${ANSI.reset} (Cluster RTX 4090 / Hashcat)`);
  console.log(`\n======================================================================\n`);
}

function printHelp() {
  printBanner();
  console.log(`Arsenal de Comandos Disponíveis:

  ${ANSI.bold}obsidiansec audit <url>${ANSI.reset}            Audita cabeçalhos de borda, cookies, CORS e MITRE attack chain
    Opções:
      --min-grade=<A|B|C>         Define a nota mínima para o Quality Gate de CI/CD (padrão: B)
      --json                      Retorna o relatório completo em formato JSON

  ${ANSI.bold}obsidiansec scan-dir [pasta]${ANSI.reset}       Caçador de segredos & SAST local (AWS, OpenAI, Stripe, .env, chaves privadas)
  
  ${ANSI.bold}obsidiansec jwt <token>${ANSI.reset}            Auditor de tokens JWT (detecta alg: none, expiração e decodifica claims)

  ${ANSI.bold}obsidiansec subdomains <dominio>${ANSI.reset}   Descoberta passiva de subdomínios via Certificate Transparency

  ${ANSI.bold}obsidiansec dns <dominio>${ANSI.reset}          Inspeciona registros anti-phishing SPF, DMARC e DNSSEC

  ${ANSI.bold}obsidiansec entropy <senha>${ANSI.reset}        Calcula bits de Shannon e tempo de quebra em GPU cluster

  ${ANSI.bold}obsidiansec help${ANSI.reset}                   Exibe este menu de ajuda
`);
}

switch (command) {
  case "audit":
    runAudit();
    break;
  case "dns":
    runDns();
    break;
  case "scan-dir":
  case "scan":
  case "sast":
    runScanDir();
    break;
  case "jwt":
    runJwt();
    break;
  case "subdomains":
  case "subs":
    runSubdomains();
    break;
  case "entropy":
    runEntropy();
    break;
  case "version":
  case "-v":
  case "--version":
    console.log("ObsidianSec CLI v1.1.0");
    break;
  default:
    printHelp();
    break;
}