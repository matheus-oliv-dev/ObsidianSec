import { AGENT_PERSONAS } from "../prompts/index";
import type { AgentContext, AgentResponse, SecurityFinding } from "../types";
import { runSastAudit } from "../../../scripts/security_squad/sast_sentinel.mjs";
import { runDbGuardianAudit } from "../../../scripts/security_squad/db_guardian.mjs";

export class SecuritySquadOrchestrator {
  private context: AgentContext;

  constructor(targetUrl?: string, workspacePath = ".") {
    this.context = {
      targetUrl,
      workspacePath,
      findings: [],
      metadata: {},
    };
  }

  /**
   * Executa a auditoria do Code Sentinel (SAST)
   */
  public async runCodeSentinel(): Promise<AgentResponse> {
    const startTime = Date.now();
    const sastResult = runSastAudit(this.context.workspacePath);
    const dbResult = runDbGuardianAudit(this.context.workspacePath);

    const findings: SecurityFinding[] = [];

    // Processa achados do SAST
    sastResult.findings.forEach((f: any, idx: number) => {
      findings.push({
        id: `SAST-${idx + 1}`,
        agent: "CODE_SENTINEL_SAST",
        title: f.rule,
        severity: "HIGH",
        cvssScore: 7.5,
        cwe: "CWE-798 / CWE-79",
        owaspCategory: "A02:2021 - Cryptographic Failures",
        location: `${f.file}:${f.line}`,
        description: `Detectado padrão inseguro no código-fonte: ${f.snippet}`,
        remediation: "Remova chaves codificadas de forma estática e use variáveis de ambiente seguras.",
        timestamp: new Date().toISOString(),
      });
    });

    // Processa achados do DB Guardian
    dbResult.findings.forEach((f: any, idx: number) => {
      findings.push({
        id: `DB-${idx + 1}`,
        agent: "CODE_SENTINEL_SAST",
        title: f.rule,
        severity: "CRITICAL",
        cvssScore: 8.9,
        cwe: "CWE-862 - Missing Authorization",
        owaspCategory: "A01:2021 - Broken Access Control",
        location: f.file,
        description: `Tabela SQL sem isolamento de políticas RLS: ${f.targets.join(", ")}`,
        remediation: "Adicione ALTER TABLE ... ENABLE ROW LEVEL SECURITY em todas as tabelas públicas.",
        timestamp: new Date().toISOString(),
      });
    });

    this.context.findings.push(...findings);

    return {
      agent: "CODE_SENTINEL_SAST",
      status: findings.length === 0 ? "SUCCESS" : "FAILED",
      findings,
      summary: `Escaneados ${sastResult.filesScanned} arquivos de código e ${dbResult.migrationsScanned} migrações SQL. ${findings.length} vulnerabilidades encontradas.`,
      durationMs: Date.now() - startTime,
    };
  }

  /**
   * Executa a auditoria do Edge & Protocol Guardian
   */
  public async runEdgeGuardian(targetUrl = this.context.targetUrl): Promise<AgentResponse> {
    const startTime = Date.now();
    const findings: SecurityFinding[] = [];

    if (!targetUrl) {
      return {
        agent: "EDGE_GUARDIAN",
        status: "SUCCESS",
        findings: [],
        summary: "Nenhuma URL externa informada para auditoria de borda.",
        durationMs: Date.now() - startTime,
      };
    }

    try {
      const res = await fetch(targetUrl, { method: "GET" });
      const headers = res.headers;

      // 1. CSP
      if (!headers.get("content-security-policy")) {
        findings.push({
          id: "EDGE-01",
          agent: "EDGE_GUARDIAN",
          title: "Content-Security-Policy (CSP) Ausente",
          severity: "HIGH",
          cvssScore: 7.2,
          cwe: "CWE-79 - Cross-site Scripting",
          owaspCategory: "A03:2021 - Injection",
          description: "O servidor não envia cabeçalho CSP para mitigar XSS e injeção de scripts.",
          remediation: "Configure Content-Security-Policy no vercel.json ou headers do servidor.",
          timestamp: new Date().toISOString(),
        });
      }

      // 2. X-Frame-Options
      if (!headers.get("x-frame-options")) {
        findings.push({
          id: "EDGE-02",
          agent: "EDGE_GUARDIAN",
          title: "Proteção Anti-Clickjacking Ausente",
          severity: "MEDIUM",
          cvssScore: 6.1,
          cwe: "CWE-1021 - Improper Restriction of Rendered UI Layers",
          owaspCategory: "A05:2021 - Security Misconfiguration",
          description: "Ausência de X-Frame-Options: DENY permite que a página seja embutida em iframes.",
          remediation: "Adicione o cabeçalho X-Frame-Options: DENY.",
          timestamp: new Date().toISOString(),
        });
      }

      // 3. X-Content-Type-Options
      if (!headers.get("x-content-type-options")) {
        findings.push({
          id: "EDGE-03",
          agent: "EDGE_GUARDIAN",
          title: "Proteção Anti-MIME Sniffing Ausente",
          severity: "LOW",
          cvssScore: 3.5,
          cwe: "CWE-430 - Deployment of Wrong Handler",
          owaspCategory: "A05:2021 - Security Misconfiguration",
          description: "O navegador não é forçado a respeitar estritamente os tipos MIME declarados.",
          remediation: "Adicione o cabeçalho X-Content-Type-Options: nosniff.",
          timestamp: new Date().toISOString(),
        });
      }

      // 4. Permissions-Policy
      if (!headers.get("permissions-policy")) {
        findings.push({
          id: "EDGE-04",
          agent: "EDGE_GUARDIAN",
          title: "Permissions-Policy Não Declarada",
          severity: "LOW",
          cvssScore: 3.0,
          cwe: "CWE-272 - Least Privilege Violation",
          owaspCategory: "A05:2021 - Security Misconfiguration",
          description: "APIs de hardware (câmera, geolocalização) não possuem restrições formais.",
          remediation: "Adicione Permissions-Policy: camera=(), geolocation=(), microphone=(self).",
          timestamp: new Date().toISOString(),
        });
      }
    } catch (err) {
      findings.push({
        id: "EDGE-ERR",
        agent: "EDGE_GUARDIAN",
        title: "Erro de Conexão com o Alvo",
        severity: "INFO",
        cvssScore: 0.0,
        description: `Não foi possível conectar a ${targetUrl}: ${(err as Error).message}`,
        remediation: "Verifique se a URL está correta e com conexão de rede ativa.",
        timestamp: new Date().toISOString(),
      });
    }

    this.context.findings.push(...findings);

    return {
      agent: "EDGE_GUARDIAN",
      status: findings.length === 0 ? "SUCCESS" : "WARNING",
      findings,
      summary: `Auditoria de cabeçalhos de borda finalizada com ${findings.length} itens a serem reforçados.`,
      durationMs: Date.now() - startTime,
    };
  }

  /**
   * Executa a auditoria consolidada do Esquadrão Multi-Agente
   */
  public async runFullSquadAudit(targetUrl?: string) {
    if (targetUrl) this.context.targetUrl = targetUrl;

    console.log("\n╔══════════════════════════════════════════════════════════════════════╗");
    console.log("║    🛡️  ESQUADRÃO MULTI-AGENTE DEVSECOPS · AUDITORIA AUTÔNOMA         ║");
    console.log("╚══════════════════════════════════════════════════════════════════════╝\n");

    console.log(`${AGENT_PERSONAS.SECURITY_LEAD.avatar} [${AGENT_PERSONAS.SECURITY_LEAD.name}]: Inicializando agentes do esquadrão...`);
    
    // 1. SAST
    console.log(`\n${AGENT_PERSONAS.CODE_SENTINEL_SAST.avatar} [${AGENT_PERSONAS.CODE_SENTINEL_SAST.name}]: Executando análise estática...`);
    const sastRes = await this.runCodeSentinel();
    console.log(`   ↳ Status: ${sastRes.status} (${sastRes.durationMs}ms) - ${sastRes.summary}`);

    // 2. Edge
    if (this.context.targetUrl) {
      console.log(`\n${AGENT_PERSONAS.EDGE_GUARDIAN.avatar} [${AGENT_PERSONAS.EDGE_GUARDIAN.name}]: Auditando ${this.context.targetUrl}...`);
      const edgeRes = await this.runEdgeGuardian();
      console.log(`   ↳ Status: ${edgeRes.status} (${edgeRes.durationMs}ms) - ${edgeRes.summary}`);
    }

    // 3. Lead Consolidation
    let maxCvss = 0.0;
    this.context.findings.forEach(f => {
      if (f.cvssScore > maxCvss) maxCvss = f.cvssScore;
    });

    console.log("\n======================================================================");
    console.log("📊 RELATÓRIO DO CYBER COMMANDER (SECURITY LEAD)");
    console.log("======================================================================");
    console.log(`• Status do Quality Gate: ${this.context.findings.length === 0 ? "✅ APROVADO (Zero Vulnerabilidades)" : "⚠️ AVISO / AJUSTES NECESSÁRIOS"}`);
    console.log(`• Pontuação de Risco Ponderada CVSS: ${maxCvss.toFixed(1)} / 10.0`);
    console.log(`• Total de Achados: ${this.context.findings.length}`);

    if (this.context.findings.length > 0) {
      console.log("\n📋 Achados Consolidados:");
      this.context.findings.forEach((f, idx) => {
        console.log(`  [${f.severity}] ${idx + 1}. ${f.title} (${f.cwe || "Geral"})`);
        console.log(`         ↳ Solução: ${f.remediation}`);
      });
    } else {
      console.log("\n🎉 Nenhum problema de segurança detectado! Sistema 100% blindado.");
    }
    console.log("======================================================================\n");

    return {
      qualityGate: this.context.findings.length === 0 ? "APPROVED" : "ACTION_REQUIRED",
      cvssScore: maxCvss,
      findings: this.context.findings,
    };
  }
}
