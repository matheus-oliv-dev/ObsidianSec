/**
 * TCP Critical Port & Database Exposure Scanner (Inspirado no Nmap & Shodan)
 * Audita 37 portas de rede em busca de bancos de dados, acesso remoto e serviços
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
  // ═══════════════════════════════════════════════════════════════
  // REMOTE ACCESS
  // ═══════════════════════════════════════════════════════════════
  { port: 21, service: "FTP (File Transfer Protocol)", category: "REMOTE_ACCESS", riskLevel: "HIGH", exposureRisk: "Credenciais e arquivos transmitidos em texto claro sem criptografia.", mitigation: "Desativar FTP e utilizar SFTP (porta 22) ou FTPS com TLS." },
  { port: 22, service: "SSH (Secure Shell)", category: "REMOTE_ACCESS", riskLevel: "MEDIUM", exposureRisk: "Alvo contínuo de botnets de força bruta e varreduras automatizadas.", mitigation: "Desabilitar autenticação por senha e restringir a IPs confiáveis ou VPN." },
  { port: 135, service: "MS-RPC / DCOM (Windows)", category: "REMOTE_ACCESS", riskLevel: "HIGH", exposureRisk: "Vetor de ataques WMI e DCOM para movimentação lateral em redes Windows.", mitigation: "Bloquear na borda de rede e restringir a domínios AD internos." },
  { port: 139, service: "NetBIOS Session Service", category: "REMOTE_ACCESS", riskLevel: "CRITICAL", exposureRisk: "Enumeração de compartilhamentos, usuários e vulnerabilidades EternalBlue (MS17-010).", mitigation: "Desativar NetBIOS over TCP/IP e bloquear portas 137-139 na borda." },
  { port: 389, service: "LDAP (Lightweight Directory Access)", category: "REMOTE_ACCESS", riskLevel: "CRITICAL", exposureRisk: "Enumeração de usuários do Active Directory e ataques de credential stuffing.", mitigation: "Utilizar LDAPS (636) com TLS e restringir a rede interna." },
  { port: 445, service: "SMB/CIFS (Server Message Block)", category: "REMOTE_ACCESS", riskLevel: "CRITICAL", exposureRisk: "Vetor de ransomware WannaCry/NotPetya e movimentação lateral.", mitigation: "Bloquear SMB na borda da internet e aplicar patches de segurança." },
  { port: 636, service: "LDAPS (LDAP over TLS)", category: "REMOTE_ACCESS", riskLevel: "MEDIUM", exposureRisk: "Diretório corporativo exposto, mesmo com TLS, permite enumeração.", mitigation: "Restringir a VPN ou rede corporativa interna." },
  { port: 2049, service: "NFS (Network File System)", category: "REMOTE_ACCESS", riskLevel: "CRITICAL", exposureRisk: "Montagem remota de volumes sem autenticação pode expor todo o filesystem.", mitigation: "Restringir exports do NFS a IPs específicos com Kerberos." },
  { port: 3389, service: "RDP (Windows Remote Desktop)", category: "REMOTE_ACCESS", riskLevel: "CRITICAL", exposureRisk: "Vetor #1 de acesso inicial para grupos de ransomware corporativo.", mitigation: "Bloquear na borda da nuvem e utilizar VPN com MFA ou Azure Bastion." },
  { port: 5900, service: "VNC Remote Desktop", category: "REMOTE_ACCESS", riskLevel: "CRITICAL", exposureRisk: "Controle remoto total da máquina, frequentemente sem criptografia.", mitigation: "Desativar VNC ou tunear via SSH/VPN com senha forte." },

  // ═══════════════════════════════════════════════════════════════
  // LEGACY INSECURE
  // ═══════════════════════════════════════════════════════════════
  { port: 23, service: "Telnet (Terminal Remoto Legado)", category: "LEGACY_INSECURE", riskLevel: "CRITICAL", exposureRisk: "Protocolo inseguro sem criptografia. Vetor de botnets IoT (Mirai).", mitigation: "Desativar imediatamente o serviço Telnet e migrar para SSH." },
  { port: 25, service: "SMTP (Simple Mail Transfer Protocol)", category: "LEGACY_INSECURE", riskLevel: "HIGH", exposureRisk: "Open relay pode ser explorado para envio de spam e phishing em massa.", mitigation: "Restringir a redes internas ou utilizar serviço de email gerenciado (SES, SendGrid)." },
  { port: 110, service: "POP3 (Post Office Protocol)", category: "LEGACY_INSECURE", riskLevel: "HIGH", exposureRisk: "Protocolo legado que transmite credenciais em texto claro.", mitigation: "Migrar para POP3S (porta 995) ou IMAPS (porta 993)." },
  { port: 111, service: "RPCBind / SunRPC", category: "LEGACY_INSECURE", riskLevel: "CRITICAL", exposureRisk: "Enumeração de serviços NFS/NIS e execução remota via RPC exploits.", mitigation: "Desativar RPCBind na borda e bloquear no firewall." },
  { port: 143, service: "IMAP (Internet Message Access)", category: "LEGACY_INSECURE", riskLevel: "HIGH", exposureRisk: "Credenciais de email transmitidas sem criptografia.", mitigation: "Migrar para IMAPS (porta 993) com TLS obrigatório." },

  // ═══════════════════════════════════════════════════════════════
  // WEB
  // ═══════════════════════════════════════════════════════════════
  { port: 53, service: "DNS (Domain Name System)", category: "WEB", riskLevel: "MEDIUM", exposureRisk: "Servidor DNS exposto pode sofrer ataques de amplificação DDoS e cache poisoning.", mitigation: "Restringir consultas recursivas e habilitar DNSSEC." },
  { port: 80, service: "HTTP (Web Server)", category: "WEB", riskLevel: "INFO", exposureRisk: "Porta web padrão (deve redirecionar para HTTPS).", mitigation: "Configurar redirecionamento 301 permanente para HTTPS com HSTS." },
  { port: 443, service: "HTTPS (Web Seguro)", category: "WEB", riskLevel: "INFO", exposureRisk: "Porta web segura padrão.", mitigation: "Manter certificados TLS atualizados e habilitar HTTP/2 e TLS 1.3." },
  { port: 993, service: "IMAPS (IMAP Secure)", category: "WEB", riskLevel: "INFO", exposureRisk: "Serviço de email seguro (porta padrão).", mitigation: "Manter certificados TLS atualizados." },
  { port: 995, service: "POP3S (POP3 Secure)", category: "WEB", riskLevel: "INFO", exposureRisk: "Serviço de email seguro (porta padrão).", mitigation: "Manter certificados TLS atualizados." },
  { port: 4443, service: "HTTPS Alternativo", category: "WEB", riskLevel: "MEDIUM", exposureRisk: "Porta alternativa usada por painéis de administração web.", mitigation: "Proteger com autenticação forte e certificado TLS válido." },
  { port: 5000, service: "Docker Registry / Flask Dev", category: "WEB", riskLevel: "HIGH", exposureRisk: "Docker Registry sem auth permite push/pull de imagens maliciosas.", mitigation: "Habilitar autenticação TLS mútua e restringir acesso." },
  { port: 5601, service: "Kibana Dashboard", category: "WEB", riskLevel: "HIGH", exposureRisk: "Dashboard Kibana exposto revela dados indexados no Elasticsearch.", mitigation: "Proteger com X-Pack Security ou proxy reverso com autenticação." },
  { port: 6443, service: "Kubernetes API Server", category: "WEB", riskLevel: "CRITICAL", exposureRisk: "Acesso ao Kubernetes API permite controle total do cluster e containers.", mitigation: "Restringir com RBAC, network policies e API server privado." },
  { port: 8080, service: "HTTP-Alt / Proxy / Dev Server", category: "WEB", riskLevel: "MEDIUM", exposureRisk: "Porta frequentemente usada para painéis de administração (Tomcat, Jenkins) ou dev.", mitigation: "Proteger com autenticação forte e não expor ambientes de desenvolvimento." },
  { port: 8443, service: "HTTPS-Alt / Admin Panel", category: "WEB", riskLevel: "MEDIUM", exposureRisk: "Porta alternativa HTTPS usada por painéis de gerenciamento.", mitigation: "Proteger com autenticação MFA e certificado TLS válido." },
  { port: 9090, service: "Prometheus / Cockpit Admin", category: "WEB", riskLevel: "HIGH", exposureRisk: "Prometheus exposto revela métricas internas e topologia de infraestrutura.", mitigation: "Restringir a rede interna e habilitar autenticação." },
  { port: 15672, service: "RabbitMQ Management Console", category: "WEB", riskLevel: "HIGH", exposureRisk: "Console de gerenciamento de filas exposto com credenciais padrão (guest/guest).", mitigation: "Alterar credenciais padrão e restringir a rede interna." },

  // ═══════════════════════════════════════════════════════════════
  // DATABASES
  // ═══════════════════════════════════════════════════════════════
  { port: 1433, service: "Microsoft SQL Server", category: "DATABASE", riskLevel: "CRITICAL", exposureRisk: "Banco de dados corporativo exposto a ataques de força bruta e SQLi remoto.", mitigation: "Isolar em subnet privada e habilitar Always Encrypted." },
  { port: 1521, service: "Oracle Database TNS Listener", category: "DATABASE", riskLevel: "CRITICAL", exposureRisk: "Banco de dados Oracle exposto permite TNS poisoning e enumeração de SIDs.", mitigation: "Habilitar Oracle Net Encryption e restringir a rede interna." },
  { port: 2181, service: "Apache ZooKeeper", category: "DATABASE", riskLevel: "HIGH", exposureRisk: "Acesso ao cluster ZooKeeper permite manipulação de configurações distribuídas.", mitigation: "Habilitar autenticação SASL e isolar em rede privada." },
  { port: 3306, service: "MySQL / MariaDB Database", category: "DATABASE", riskLevel: "HIGH", exposureRisk: "Banco de dados exposto a ataques de força bruta contra usuário root.", mitigation: "Vincular a 127.0.0.1 ou rede privada interna (VPC Security Group)." },
  { port: 5432, service: "PostgreSQL Database", category: "DATABASE", riskLevel: "HIGH", exposureRisk: "Banco de dados relacional exposto à internet pública.", mitigation: "Configurar pg_hba.conf para rejeitar conexões externas e isolar em subnet privada." },
  { port: 6379, service: "Redis Cache & Database", category: "DATABASE", riskLevel: "CRITICAL", exposureRisk: "RCE e exfiltração total de dados via gravação de chaves SSH ou dump de memória.", mitigation: "Nunca expor na internet! Habilitar autenticação forte e isolar em rede local." },
  { port: 9200, service: "Elasticsearch REST API", category: "DATABASE", riskLevel: "CRITICAL", exposureRisk: "Acesso unauthenticated a logs, dados de clientes e clusters de busca.", mitigation: "Ativar X-Pack Security com TLS e restringir o acesso apenas a backends autorizados." },
  { port: 11211, service: "Memcached", category: "DATABASE", riskLevel: "CRITICAL", exposureRisk: "Amplificação DDoS massiva e exfiltração de dados de cache em memória.", mitigation: "Nunca expor na internet! Vincular a 127.0.0.1 e usar SASL auth." },
  { port: 27017, service: "MongoDB NoSQL Database", category: "DATABASE", riskLevel: "CRITICAL", exposureRisk: "Alvo prioritário de ataques automatizados de ransomware de banco de dados.", mitigation: "Ativar autenticação SCRAM-SHA-256 e fechar portas no Security Group da nuvem." },
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