/**
 * DNS & Email Security Analyzer (Anti-Phishing / SPF / DMARC / DNSSEC)
 * Inspeciona registros DNS via DNS-over-HTTPS (DoH) para validação de políticas
 * anti-spoofing e integridade de domínio conforme RFC 7208, RFC 7489 e NIST SP 800-81B.
 */

export interface SpfAnalysis {
  present: boolean;
  rawRecord?: string;
  qualifier?: "-all" | "~all" | "?all" | "+all";
  hasWildcardPass: boolean;
  lookupCountEstimate: number;
  isCompliant: boolean;
  verdict: string;
  issues: string[];
}

export interface DmarcAnalysis {
  present: boolean;
  rawRecord?: string;
  policy?: "reject" | "quarantine" | "none";
  subdomainPolicy?: "reject" | "quarantine" | "none";
  percentage: number;
  aggregateReportUri?: string;
  forensicReportUri?: string;
  isEnforcing: boolean;
  verdict: string;
  issues: string[];
}

export interface DnsSecurityReport {
  domain: string;
  hasMxRecords: boolean;
  mxServers: string[];
  spf: SpfAnalysis;
  dmarc: DmarcAnalysis;
  dnssecActive: boolean;
  emailSecurityScore: number;
  overallStatus: "SECURE" | "WARNING" | "CRITICAL";
  recommendations: string[];
}

/**
 * Analisa registros TXT para extração e auditoria de SPF
 */
export function parseSpfRecord(txtRecords: string[]): SpfAnalysis {
  const spfRaw = txtRecords.find((r) => r.toLowerCase().startsWith("v=spf1"));
  if (!spfRaw) {
    return {
      present: false,
      hasWildcardPass: false,
      lookupCountEstimate: 0,
      isCompliant: false,
      verdict: "Ausência de SPF: Qualquer servidor no mundo pode forjar emails em nome do domínio.",
      issues: ["Crie uma entrada TXT com 'v=spf1 ... -all' autorizando apenas seus servidores de email legítimos."],
    };
  }

  const parts = spfRaw.split(/\s+/);
  let qualifier: "-all" | "~all" | "?all" | "+all" = "~all";
  const issues: string[] = [];
  let lookupCount = 0;

  for (const part of parts) {
    const pLower = part.toLowerCase();
    if (pLower.startsWith("include:") || pLower.startsWith("a") || pLower.startsWith("mx") || pLower.startsWith("ptr:") || pLower.startsWith("exists:")) {
      lookupCount++;
    }
    if (pLower === "-all") qualifier = "-all";
    else if (pLower === "~all") qualifier = "~all";
    else if (pLower === "?all") qualifier = "?all";
    else if (pLower === "+all" || pLower === "all") qualifier = "+all";
  }

  const hasWildcardPass = qualifier === "+all";
  if (hasWildcardPass) {
    issues.push("VULNERABILIDADE CRÍTICA: '+all' autoriza qualquer IP na internet a enviar emails em seu nome.");
  }
  if (qualifier === "?all") {
    issues.push("Qualificador neutro '?all' não instrui servidores a rejeitarem mensagens não autorizadas.");
  }
  if (lookupCount > 10) {
    issues.push(`Excesso de Lookups DNS (${lookupCount} > 10). Excede o limite da RFC 7208 e pode invalidar o SPF (PermError).`);
  }

  const isCompliant = (qualifier === "-all" || qualifier === "~all") && !hasWildcardPass && lookupCount <= 10;
  let verdict = "SPF configurado corretamente com restrição de remetentes.";
  if (hasWildcardPass) verdict = "SPF Perigoso (+all): Permite spoofing irrestrito de email.";
  else if (qualifier === "-all") verdict = "SPF Blindado (HardFail -all): Rejeição estrita de remetentes não autorizados.";
  else if (qualifier === "~all") verdict = "SPF Moderado (SoftFail ~all): Mensagens não autorizadas são marcadas como spam.";

  return {
    present: true,
    rawRecord: spfRaw,
    qualifier,
    hasWildcardPass,
    lookupCountEstimate: lookupCount,
    isCompliant,
    verdict,
    issues,
  };
}

/**
 * Analisa registros TXT para extração e auditoria de DMARC
 */
export function parseDmarcRecord(txtRecords: string[]): DmarcAnalysis {
  const dmarcRaw = txtRecords.find((r) => r.toLowerCase().startsWith("v=dmarc1"));
  if (!dmarcRaw) {
    return {
      present: false,
      percentage: 0,
      isEnforcing: false,
      verdict: "Ausência de DMARC: Domínio desprotegido contra ataques de Business Email Compromise (BEC) e Phishing.",
      issues: ["Configure uma entrada TXT em '_dmarc.seudominio.com' com política 'v=DMARC1; p=reject; rua=mailto:dmarc@seudominio.com'."],
    };
  }

  const tags = dmarcRaw.split(";").map((t) => t.trim());
  let policy: "reject" | "quarantine" | "none" = "none";
  let subdomainPolicy: "reject" | "quarantine" | "none" | undefined;
  let percentage = 100;
  let aggregateReportUri: string | undefined;
  let forensicReportUri: string | undefined;
  const issues: string[] = [];

  for (const tag of tags) {
    const [key, val] = tag.split("=").map((s) => s?.trim());
    if (!key || !val) continue;
    const kLower = key.toLowerCase();
    const vLower = val.toLowerCase();

    if (kLower === "p") {
      if (vLower === "reject") policy = "reject";
      else if (vLower === "quarantine") policy = "quarantine";
      else policy = "none";
    }
    if (kLower === "sp") {
      if (vLower === "reject") subdomainPolicy = "reject";
      else if (vLower === "quarantine") subdomainPolicy = "quarantine";
      else subdomainPolicy = "none";
    }
    if (kLower === "pct") {
      percentage = parseInt(val, 10) || 100;
    }
    if (kLower === "rua") aggregateReportUri = val;
    if (kLower === "ruf") forensicReportUri = val;
  }

  if (policy === "none") {
    issues.push("Política DMARC 'p=none' atua apenas como telemetria e NÃO bloqueia emails falsificados.");
  }
  if (percentage < 100) {
    issues.push(`Apenas ${percentage}% das mensagens sofrem aplicação da regra DMARC.`);
  }
  if (!aggregateReportUri) {
    issues.push("Nenhum endereço 'rua' configurado para receber relatórios agregados de tentativas de spoofing.");
  }

  const isEnforcing = policy === "reject" || policy === "quarantine";
  let verdict = "DMARC Ativo em Modo de Bloqueio.";
  if (policy === "reject") verdict = "DMARC Máximo (p=reject): Emails falsificados são terminantemente descartados.";
  else if (policy === "quarantine") verdict = "DMARC Médio (p=quarantine): Emails falsificados são isolados em quarentena/spam.";
  else verdict = "DMARC Apenas Monitoramento (p=none): Não impede envio de emails falsos.";

  return {
    present: true,
    rawRecord: dmarcRaw,
    policy,
    subdomainPolicy,
    percentage,
    aggregateReportUri,
    forensicReportUri,
    isEnforcing,
    verdict,
    issues,
  };
}

/**
 * Consulta registros DNS via DNS-over-HTTPS (Cloudflare DoH)
 */
export async function queryDohRecords(domain: string, type: "TXT" | "MX" | "DS"): Promise<string[]> {
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`;
  try {
    const res = await fetch(url, {
      headers: { Accept: "application/dns-json" },
      signal: AbortSignal.timeout(3500),
    });
    if (!res.ok) return [];
    const data = await res.json();
    if (!data.Answer || !Array.isArray(data.Answer)) return [];

    return data.Answer.map((a: any) => {
      let dataStr = String(a.data || "");
      if (dataStr.startsWith('"') && dataStr.endsWith('"')) {
        dataStr = dataStr.slice(1, -1);
      }
      return dataStr;
    });
  } catch {
    return [];
  }
}

/**
 * Auditoria completa de segurança DNS e Email para um domínio
 */
export async function auditDomainDnsSecurity(domainInput: string): Promise<DnsSecurityReport> {
  const cleanDomain = domainInput
    .replace(/^https?:\/\//i, "")
    .split("/")[0]
    .split(":")[0]
    .trim()
    .toLowerCase();

  const [domainTxt, dmarcTxt, mxRecords, dsRecords] = await Promise.all([
    queryDohRecords(cleanDomain, "TXT"),
    queryDohRecords(`_dmarc.${cleanDomain}`, "TXT"),
    queryDohRecords(cleanDomain, "MX"),
    queryDohRecords(cleanDomain, "DS"),
  ]);

  const spf = parseSpfRecord(domainTxt);
  const dmarc = parseDmarcRecord(dmarcTxt);
  const dnssecActive = dsRecords.length > 0;
  const hasMxRecords = mxRecords.length > 0;

  let score = 0;
  const recommendations: string[] = [];

  // Cálculo de pontuação
  if (spf.present && spf.isCompliant) {
    score += spf.qualifier === "-all" ? 40 : 30;
  } else if (spf.present) {
    score += 15;
  } else {
    recommendations.push("Publicar registro SPF (TXT) com '-all' para autenticar provedores de envio.");
  }

  if (dmarc.present && dmarc.isEnforcing) {
    score += dmarc.policy === "reject" ? 45 : 35;
  } else if (dmarc.present) {
    score += 15;
    recommendations.push("Evoluir a política DMARC de 'p=none' para 'p=quarantine' ou 'p=reject'.");
  } else {
    recommendations.push("Configurar registro DMARC (_dmarc) para proteção ativa contra Phishing e BEC.");
  }

  if (dnssecActive) {
    score += 15;
  } else {
    recommendations.push("Ativar DNSSEC no registrador do domínio para proteção contra envenenamento de cache DNS.");
  }

  score = Math.min(100, score);

  let overallStatus: "SECURE" | "WARNING" | "CRITICAL" = "CRITICAL";
  if (score >= 80) overallStatus = "SECURE";
  else if (score >= 50) overallStatus = "WARNING";

  return {
    domain: cleanDomain,
    hasMxRecords,
    mxServers: mxRecords,
    spf,
    dmarc,
    dnssecActive,
    emailSecurityScore: score,
    overallStatus,
    recommendations,
  };
}