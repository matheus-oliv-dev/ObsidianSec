/**
 * Attack Chain & Exploit Path Analyzer (Inspirado no BloodHound Graph Engine)
 * Modela grafos de ataque e correlações de causa-e-efeito entre defesas ausentes
 * para demonstrar o caminho crítico que um atacante percorreria.
 */

export interface AttackNode {
  id: string;
  stage: "RECON" | "INITIAL_ACCESS" | "EXECUTION" | "PERSISTENCE" | "PRIV_ESC" | "IMPACT";
  title: string;
  description: string;
  vector: string;
  mitreTechnique: string;
}

export interface AttackEdge {
  fromNodeId: string;
  toNodeId: string;
  condition: string;
  likelihood: "HIGH" | "MEDIUM" | "LOW";
}

export interface AttackChainReport {
  target: string;
  riskSummary: string;
  primaryAttackPath: string[];
  nodes: AttackNode[];
  edges: AttackEdge[];
  maxImpactLevel: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  tacticalDefensePriority: string[];
}

export interface DefenseState {
  hasCsp: boolean;
  hasXFrameOptions: boolean;
  hasHsts: boolean;
  hasNosniff: boolean;
  hasPermissionsPolicy: boolean;
  hasSecureCookies: boolean;
  hasStrictCors: boolean;
  serverVersionExposed: boolean;
}

/**
 * Constrói o grafo de caminho de ataque e correlação de impacto
 */
export function buildAttackChainGraph(targetUrl: string, defenses: DefenseState): AttackChainReport {
  const nodes: AttackNode[] = [];
  const edges: AttackEdge[] = [];
  const primaryPath: string[] = [];
  const priorities: string[] = [];

  // Etapa 1: Reconhecimento
  if (defenses.serverVersionExposed) {
    nodes.push({
      id: "node-recon-server",
      stage: "RECON",
      title: "Identificação de Versão de Servidor Web (Server Fingerprinting)",
      description: "O cabeçalho 'Server' expõe a versão exata do software, permitindo mapeamento de CVEs conhecidas.",
      vector: "Banner Grabbing / Version Header",
      mitreTechnique: "T1592.002 (Gather Victim Host Information: Software)",
    });
    primaryPath.push("Identificação de Versão");
  }

  // Etapa 2: Acesso Inicial & Injeção
  if (!defenses.hasCsp) {
    nodes.push({
      id: "node-xss-injection",
      stage: "INITIAL_ACCESS",
      title: "Injeção de Scripts Maliciosos (Cross-Site Scripting - XSS)",
      description: "A ausência de Content-Security-Policy permite execução irrestrita de scripts no contexto da vítima.",
      vector: "DOM / Reflected / Stored XSS",
      mitreTechnique: "T1189 (Drive-by Compromise / Browser Exploitation)",
    });
    primaryPath.push("Injeção de Script (XSS)");
    priorities.push("Configurar Content-Security-Policy (CSP) com restrição default-src e nonce/hashes.");

    if (nodes.some((n) => n.id === "node-recon-server")) {
      edges.push({
        fromNodeId: "node-recon-server",
        toNodeId: "node-xss-injection",
        condition: "Atacante seleciona payloads compatíveis com a versão do servidor.",
        likelihood: "HIGH",
      });
    }
  }

  // Etapa 3: Execução e Sequestro de Sessão
  if (!defenses.hasCsp && !defenses.hasSecureCookies) {
    nodes.push({
      id: "node-session-hijack",
      stage: "EXECUTION",
      title: "Exfiltração de Cookies e Sequestro de Sessão (Session Hijacking)",
      description: "Cookies de autenticação sem a flag HttpOnly são lidos via document.cookie pelo script XSS e enviados para servidor C2.",
      vector: "Document Cookie Exfiltration",
      mitreTechnique: "T1539 (Steal Web Session Cookie)",
    });
    primaryPath.push("Roubo de Cookie (Session Hijacking)");
    priorities.push("Habilitar flag HttpOnly e prefixos __Host- em todos os cookies de sessão.");

    edges.push({
      fromNodeId: "node-xss-injection",
      toNodeId: "node-session-hijack",
      condition: "Script malicioso executa document.cookie no navegador da vítima.",
      likelihood: "HIGH",
    });
  }

  // Etapa 4: Clickjacking / UI Redressing
  if (!defenses.hasXFrameOptions) {
    nodes.push({
      id: "node-clickjacking",
      stage: "INITIAL_ACCESS",
      title: "Sequestro de Interface e Ações Invisíveis (Clickjacking)",
      description: "Páginas autenticadas podem ser incorporadas em iframes transparentes para induzir cliques involuntários.",
      vector: "Transparent iFrame Overlay",
      mitreTechnique: "T1204.001 (User Execution: Malicious Link / UI Redress)",
    });
    priorities.push("Adicionar 'X-Frame-Options: DENY' e diretiva CSP 'frame-ancestors 'none''.");

    if (primaryPath.length === 0) {
      primaryPath.push("Clickjacking / UI Redressing");
    }
  }

  // Etapa 5: Man-in-the-Middle (MitM) via SSL Strip
  if (!defenses.hasHsts) {
    nodes.push({
      id: "node-hsts-downgrade",
      stage: "INITIAL_ACCESS",
      title: "Interceptação de Tráfego e Downgrade para HTTP (SSL Strip)",
      description: "A falta de HSTS permite que atacantes na mesma rede interceptem a primeira requisição e forcem HTTP plano.",
      vector: "ARP Spoofing / SSL Striping",
      mitreTechnique: "T1557.001 (Man-in-the-Middle: LLMNR/NBT-NS & SSL Strip)",
    });
    priorities.push("Habilitar 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.");
  }

  // Etapa 6: Impacto Final
  let maxImpactLevel: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" = "LOW";

  if (nodes.some((n) => n.id === "node-session-hijack")) {
    nodes.push({
      id: "node-account-takeover",
      stage: "IMPACT",
      title: "Tomada Completa de Conta & Acesso Administrativo (Account Takeover)",
      description: "Atacante utiliza a sessão roubada para assumir identidade legítima e acessar dados internos.",
      vector: "Authenticated Impersonation",
      mitreTechnique: "T1078 (Valid Accounts)",
    });
    primaryPath.push("Comprometimento de Conta (Account Takeover)");
    maxImpactLevel = "CRITICAL";

    edges.push({
      fromNodeId: "node-session-hijack",
      toNodeId: "node-account-takeover",
      condition: "Atacante replica token em cabeçalho Authorization/Cookie.",
      likelihood: "HIGH",
    });
  } else if (nodes.some((n) => n.id === "node-xss-injection") || nodes.some((n) => n.id === "node-clickjacking")) {
    maxImpactLevel = "HIGH";
  } else if (nodes.length > 0) {
    maxImpactLevel = "MEDIUM";
  }

  const riskSummary =
    primaryPath.length > 1
      ? `Cadeia de Ataque Detectada: ${primaryPath.join(" ➔ ")}`
      : nodes.length > 0
        ? `Superfície de Risco Identificada com ${nodes.length} vetores potenciais de invasão.`
        : "Nenhum vetor crítico de encadeamento de ataque detectado nas camadas de borda.";

  return {
    target: targetUrl,
    riskSummary,
    primaryAttackPath: primaryPath,
    nodes,
    edges,
    maxImpactLevel,
    tacticalDefensePriority: priorities,
  };
}