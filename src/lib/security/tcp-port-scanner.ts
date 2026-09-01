/**
 * TCP Critical Port & Database Exposure Scanner (Inspirado no Nmap & Shodan)
 * Audita portas de rede em busca de bancos de dados, acesso remoto e serviços
 * expostos publicamente na internet (0.0.0.0/0) usando sockets TCP não-bloqueantes.
 */

import net from "node:net";

export interface PortDefinition {
  port: number;
  service: string;
  category: "DATABASE" | "REMOTE_ACCESS" | "WEB" | "LEGACY_INSECURE";
  riskLevel: "CRITICAL" | "HIGH" | "MEDIUM" | "INFO";
  exposureRisk: string;
  mitigation: string;
}

export interface PortCheckResult {
  port: number;
  service: string;
  category: PortDefinition["category"];
  riskLevel: PortDefinition["riskLevel"];
  status: "OPEN" | "CLOSED" | "FILTERED";
  responseTimeMs: number;
  exposureRisk: string;
  mitigation: string;
}

export interface PortScanReport {
  targetHost: string;
  totalScanned: number;
  openCount: number;
  filteredCount: number;
  closedCount: number;
  criticalExposuresCount: number;
  results: PortCheckResult[];
  overallVerdict: "SECURE" | "WARNING" | "CRITICAL";
  durationMs: number;
}

export const CRITICAL_PORTS: PortDefinition[] = [
  {
    port: 21,
    service: "FTP (File Transfer Protocol)",
    category: "REMOTE_ACCESS",
    riskLevel: "HIGH",
    exposureRisk: "Credenciais e arquivos transmitidos em texto claro sem criptografia.",
    mitigation: "Desativar FTP e utilizar SFTP (porta 22) ou FTPS com TLS.",
  },
  {
    port: 22,
    service: "SSH (Secure Shell)",
    category: "REMOTE_ACCESS",
    riskLevel: "MEDIUM",
    exposureRisk: "Alvo contínuo de botnets de força bruta e varreduras automatizadas.",
    mitigation: "Desabilitar autenticação por senha e restringir a IPs confiáveis ou VPN.",
  },
  {
    port: 23,
    service: "Telnet (Terminal Remoto Legado)",
    category: "LEGACY_INSECURE",
    riskLevel: "CRITICAL",
    exposureRisk: "Protocolo inseguro sem criptografia. Vetor de botnets IoT (Mirai).",
    mitigation: "Desativar imediatamente o serviço Telnet e migrar para SSH.",
  },
  {
    port: 80,
    service: "HTTP (Web Server)",
    category: "WEB",
    riskLevel: "INFO",
    exposureRisk: "Porta web padrão (deve redirecionar para HTTPS).",
    mitigation: "Configurar redirecionamento 301 permanente para HTTPS com HSTS.",
  },
  {
    port: 443,
    service: "HTTPS (Web Seguro)",
    category: "WEB",
    riskLevel: "INFO",
    exposureRisk: "Porta web segura padrão.",
    mitigation: "Manter certificados TLS atualizados e habilitar HTTP/2 e TLS 1.3.",
  },
  {
    port: 3306,
    service: "MySQL / MariaDB Database",
    category: "DATABASE",
    riskLevel: "HIGH",
    exposureRisk: "Banco de dados exposto a ataques de força bruta contra usuário root.",
    mitigation: "Vincular a 127.0.0.1 ou rede privada interna (VPC Security Group).",
  },
  {
    port: 3389,
    service: "RDP (Windows Remote Desktop)",
    category: "REMOTE_ACCESS",
    riskLevel: "CRITICAL",
    exposureRisk: "Vetor #1 de acesso inicial para grupos de ransomware corporativo.",
    mitigation: "Bloquear na borda da nuvem e utilizar VPN com MFA ou Azure Bastion.",
  },
  {
    port: 5432,
    service: "PostgreSQL Database",
    category: "DATABASE",
    riskLevel: "HIGH",
    exposureRisk: "Banco de dados relacional exposto à internet pública.",
    mitigation: "Configurar pg_hba.conf para rejeitar conexões externas e isolar em subnet privada.",
  },
  {
    port: 6379,
    service: "Redis Cache & Database",
    category: "DATABASE",
    riskLevel: "CRITICAL",
    exposureRisk: "RCE e exfiltração total de dados via gravação de chaves SSH ou dump de memória.",
    mitigation: "Nunca expor na internet! Habilitar autenticação forte e isolar em rede local.",
  },
  {
    port: 8080,
    service: "HTTP-Alt / Proxy / Dev Server",
    category: "WEB",
    riskLevel: "MEDIUM",
    exposureRisk: "Porta frequentemente usada para painéis de administração (Tomcat, Jenkins) ou dev.",
    mitigation: "Proteger com autenticação forte e não expor ambientes de desenvolvimento.",
  },
  {
    port: 9200,
    service: "Elasticsearch REST API",
    category: "DATABASE",
    riskLevel: "CRITICAL",
    exposureRisk: "Acesso unauthenticated a logs, dados de clientes e clusters de busca.",
    mitigation: "Ativar X-Pack Security com TLS e restringir o acesso apenas a backends autorizados.",
  },
  {
    port: 27017,
    service: "MongoDB NoSQL Database",
    category: "DATABASE",
    riskLevel: "CRITICAL",
    exposureRisk: "Alvo prioritário de ataques automatizados de ransomware de banco de dados.",
    mitigation: "Ativar autenticação SCRAM-SHA-256 e fechar portas no Security Group da nuvem.",
  },
];

export function checkTcpPort(host: string, portDef: PortDefinition, timeoutMs = 1500): Promise<PortCheckResult> {
  const start = Date.now();
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let isResolved = false;

    const finalize = (status: "OPEN" | "CLOSED" | "FILTERED") => {
      if (isResolved) return;
      isResolved = true;
      socket.removeAllListeners();
      socket.destroy();
      resolve({
        port: portDef.port,
        service: portDef.service,
        category: portDef.category,
        riskLevel: portDef.riskLevel,
        status,
        responseTimeMs: Date.now() - start,
        exposureRisk: portDef.exposureRisk,
        mitigation: portDef.mitigation,
      });
    };

    socket.setTimeout(timeoutMs);

    socket.once("connect", () => finalize("OPEN"));
    socket.once("timeout", () => finalize("FILTERED"));
    socket.once("error", (err: any) => {
      if (err.code === "ECONNREFUSED") finalize("CLOSED");
      else finalize("FILTERED");
    });

    try {
      socket.connect(portDef.port, host);
    } catch {
      finalize("FILTERED");
    }
  });
}

export async function scanHostCriticalPorts(hostInput: string, timeoutMs = 1500): Promise<PortScanReport> {
  const startTime = Date.now();
  const cleanHost = hostInput
    .replace(/^https?:\/\//i, "")
    .split("/")[0]
    .split(":")[0]
    .trim();

  const checks = CRITICAL_PORTS.map((p) => checkTcpPort(cleanHost, p, timeoutMs));
  const results = await Promise.all(checks);

  const openCount = results.filter((r) => r.status === "OPEN").length;
  const filteredCount = results.filter((r) => r.status === "FILTERED").length;
  const closedCount = results.filter((r) => r.status === "CLOSED").length;

  const criticalExposures = results.filter(
    (r) => r.status === "OPEN" && (r.riskLevel === "CRITICAL" || r.riskLevel === "HIGH")
  );

  let overallVerdict: "SECURE" | "WARNING" | "CRITICAL" = "SECURE";
  if (criticalExposures.some((r) => r.riskLevel === "CRITICAL")) {
    overallVerdict = "CRITICAL";
  } else if (criticalExposures.length > 0) {
    overallVerdict = "WARNING";
  }

  return {
    targetHost: cleanHost,
    totalScanned: results.length,
    openCount,
    filteredCount,
    closedCount,
    criticalExposuresCount: criticalExposures.length,
    results,
    overallVerdict,
    durationMs: Date.now() - startTime,
  };
}