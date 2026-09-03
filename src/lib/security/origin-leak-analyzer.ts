/**
 * Origin Bypass & Real IP Leak Detector
 * Detecta vazamentos de IP de servidores de origem por trás de CDNs/WAFs (Cloudflare, CloudFront)
 * analisando múltiplos vetores (SPF, MX, subdomínios em nuvem cinza, e validação de Virtual Host).
 */

import { URL } from "node:url";

export const CLOUDFLARE_IPV4_CIDRS = [
  "173.245.48.0/20",
  "103.21.244.0/22",
  "103.22.200.0/22",
  "103.31.4.0/22",
  "141.101.64.0/18",
  "108.162.192.0/18",
  "190.93.240.0/20",
  "188.114.96.0/20",
  "197.234.240.0/22",
  "198.41.128.0/17",
  "162.158.0.0/15",
  "104.16.0.0/13",
  "104.24.0.0/14",
  "172.64.0.0/13",
  "131.0.72.0/22",
  "1.0.0.0/24",
  "1.1.1.0/24",
];

export const HIGH_RISK_ORIGIN_SUBDOMAINS = [
  "direct",
  "origin",
  "origin-api",
  "direct-connect",
  "cpanel",
  "whm",
  "webmail",
  "mail",
  "smtp",
  "ftp",
  "ssh",
  "vpn",
  "dev",
  "staging",
  "test",
  "internal",
  "portal",
  "backup",
  "admin",
];

export interface CandidateOriginIp {
  ip: string;
  sourceVector: "SPF_RECORD" | "MX_HOST" | "GRAY_CLOUD_SUBDOMAIN" | "CERTIFICATE_LOG";
  discoveredHost?: string;
  isCloudflare: boolean;
  virtualHostMatch?: boolean;
  statusCode?: number;
  serverBanner?: string;
}

export interface OriginLeakReport {
  targetDomain: string;
  isBehindProxyOrCdn: boolean;
  proxyProvider?: "Cloudflare" | "Fastly" | "CloudFront" | "Generic CDN" | "Direct Origin";
  primaryIps: string[];
  candidateOriginIps: CandidateOriginIp[];
  confirmedBypassIps: string[];
  testedVectors: {
    spfInspected: boolean;
    spfIpsFound: string[];
    mxInspected: boolean;
    mxHostsFound: string[];
    subdomainsProbed: number;
    subdomainsExposed: string[];
  };
  overallStatus: "SECURE" | "WARNING" | "CRITICAL_BYPASS";
  riskScore: number; // 0 (impenetrable) a 100 (vazamento crítico de IP)
  summary: string;
  firewallPatches: {
    ufwScript: string;
    nginxSnippet: string;
  };
  durationMs: number;
}

/**
 * Converte IP IPv4 para número inteiro de 32 bits
 */
export function ipToInt(ip: string): number {
  return ip
    .split(".")
    .reduce((acc, octet) => ((acc << 8) + parseInt(octet, 10)) >>> 0, 0);
}

/**
 * Verifica se um endereço IPv4 pertence a uma sub-rede CIDR
 */
export function ipInCidr(ip: string, cidr: string): boolean {
  try {
    const [range, bitsStr] = cidr.split("/");
    const bits = parseInt(bitsStr, 10);
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    const ipVal = ipToInt(ip);
    const rangeVal = ipToInt(range);
    return (ipVal & mask) === (rangeVal & mask);
  } catch {
    return false;
  }
}

/**
 * Checa se um IP pertence aos ranges oficiais da Cloudflare
 */
export function isCloudflareIp(ip: string): boolean {
  if (!ip || !ip.includes(".")) return false;
  return CLOUDFLARE_IPV4_CIDRS.some((cidr) => ipInCidr(ip, cidr));
}

/**
 * Extrai IPs IPv4 de registros SPF/TXT
 */
export function extractSpfIps(spfRecord: string): string[] {
  if (!spfRecord) return [];
  const matches = spfRecord.match(/ip4:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(?:\/[0-9]+)?)/gi) || [];
  const ips: string[] = [];

  for (const m of matches) {
    const raw = m.replace(/^ip4:/i, "").split("/")[0].trim();
    if (
      !raw.startsWith("127.") &&
      !raw.startsWith("10.") &&
      !raw.startsWith("192.168.") &&
      !raw.startsWith("0.") &&
      !ips.includes(raw)
    ) {
      ips.push(raw);
    }
  }

  return ips;
}

/**
 * Consulta registros DNS via DoH (DNS-over-HTTPS)
 */
async function queryDohRecords(name: string, type: "A" | "TXT" | "MX", timeoutMs = 2500): Promise<string[]> {
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    const res = await fetch(url, {
      signal: controller.signal,
      headers: { Accept: "application/dns-json" },
    });
    clearTimeout(timer);

    if (!res.ok) return [];
    const data: any = await res.json();
    if (!data.Answer || !Array.isArray(data.Answer)) return [];

    return data.Answer.map((a: any) => {
      let str = String(a.data || "");
      if (str.startsWith('"') && str.endsWith('"')) {
        str = str.slice(1, -1);
      }
      return str;
    });
  } catch {
    return [];
  }
}

/**
 * Gera regras de Firewall prontas para fechar conexões diretas
 */
export function generateOriginFirewallPatches(candidateIps: string[] = []): { ufwScript: string; nginxSnippet: string } {
  const ufwScript = `# ====================================================================
# CHIMERAGUARD DEFENSE PATCH: BLOCK DIRECT ORIGIN ACCESS (UFW)
# Permite tráfego HTTPS apenas das faixas oficiais da Cloudflare
# ====================================================================
sudo ufw default deny incoming
${CLOUDFLARE_IPV4_CIDRS.map((cidr) => `sudo ufw allow from ${cidr} to any port 443 proto tcp comment "Cloudflare Edge"`).join("\n")}
sudo ufw deny 443/tcp comment "Block direct HTTP/HTTPS bypass"
sudo ufw reload`;

  const nginxSnippet = `# ====================================================================
# CHIMERAGUARD DEFENSE PATCH: NGINX RESTRICTED ORIGIN ACCESS
# Rejeita requisições diretas que não vierem do proxy da Cloudflare
# ====================================================================
# Adicione dentro do bloco server { ... } em /etc/nginx/sites-available/
${CLOUDFLARE_IPV4_CIDRS.map((cidr) => `set_real_ip_from ${cidr};`).join("\n")}
real_ip_header CF-Connecting-IP;

# Negar qualquer acesso direto fora da Cloudflare
allow 127.0.0.1;
${CLOUDFLARE_IPV4_CIDRS.map((cidr) => `allow ${cidr};`).join("\n")}
deny all;`;

  return { ufwScript, nginxSnippet };
}

/**
 * Motor Principal: Analisa vetores de vazamento de IP e valida bypass de CDN
 */
export async function analyzeOriginLeak(
  targetUrl: string,
  options?: {
    timeoutMs?: number;
    probeVirtualHost?: boolean;
  }
): Promise<OriginLeakReport> {
  const startTime = Date.now();
  const probeVhost = options?.probeVirtualHost !== false;

  // Normaliza domínio
  let rawHost = targetUrl.replace(/^https?:\/\//i, "").split("/")[0].split(":")[0].trim().toLowerCase();
  const cleanDomain = rawHost;

  // 1. Resolve IPs primários do domínio
  const primaryA = await queryDohRecords(cleanDomain, "A");
  const primaryIps = primaryA.filter((ip) => /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(ip));

  const isCloudflare = primaryIps.length > 0 && primaryIps.every(isCloudflareIp);
  const isBehindProxyOrCdn = isCloudflare || primaryIps.some(isCloudflareIp);

  let proxyProvider: OriginLeakReport["proxyProvider"] = "Direct Origin";
  if (isCloudflare) proxyProvider = "Cloudflare";
  else if (isBehindProxyOrCdn) proxyProvider = "Generic CDN";

  const candidateOriginIps: CandidateOriginIp[] = [];
  const spfIpsFound: string[] = [];
  const mxHostsFound: string[] = [];
  const subdomainsExposed: string[] = [];

  // Vetor 1: Inspeciona registros SPF/TXT
  const txtRecords = await queryDohRecords(cleanDomain, "TXT");
  for (const txt of txtRecords) {
    if (txt.toLowerCase().startsWith("v=spf1")) {
      const ips = extractSpfIps(txt);
      for (const ip of ips) {
        if (!spfIpsFound.includes(ip)) spfIpsFound.push(ip);
        if (!isCloudflareIp(ip) && !primaryIps.includes(ip)) {
          candidateOriginIps.push({
            ip,
            sourceVector: "SPF_RECORD",
            isCloudflare: false,
          });
        }
      }
    }
  }

  // Vetor 2: Inspeciona servidores de e-mail (MX)
  const mxRecords = await queryDohRecords(cleanDomain, "MX");
  for (const mx of mxRecords) {
    // Formato MX: "10 mail.dominio.com."
    const parts = mx.split(/\s+/);
    const host = (parts.length > 1 ? parts[1] : parts[0]).replace(/\.$/, "");
    if (host && !mxHostsFound.includes(host)) {
      mxHostsFound.push(host);
      // Se o MX for um subdomínio do próprio alvo (ex: mail.alvo.com)
      if (host.endsWith(cleanDomain)) {
        const mxA = await queryDohRecords(host, "A");
        for (const ip of mxA) {
          if (!isCloudflareIp(ip) && !primaryIps.includes(ip)) {
            candidateOriginIps.push({
              ip,
              sourceVector: "MX_HOST",
              discoveredHost: host,
              isCloudflare: false,
            });
          }
        }
      }
    }
  }

  // Vetor 3: Sondagem de subdomínios de alto risco em nuvem cinza
  await Promise.all(
    HIGH_RISK_ORIGIN_SUBDOMAINS.map(async (sub) => {
      const subHost = `${sub}.${cleanDomain}`;
      const subA = await queryDohRecords(subHost, "A");
      for (const ip of subA) {
        if (/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(ip)) {
          if (!isCloudflareIp(ip)) {
            subdomainsExposed.push(`${subHost} -> ${ip}`);
            if (!candidateOriginIps.some((c) => c.ip === ip)) {
              candidateOriginIps.push({
                ip,
                sourceVector: "GRAY_CLOUD_SUBDOMAIN",
                discoveredHost: subHost,
                isCloudflare: false,
              });
            }
          }
        }
      }
    })
  );

  // Vetor 5: Confirmação Ativa via Host Header Match Probe
  const confirmedBypassIps: string[] = [];

  if (probeVhost && candidateOriginIps.length > 0) {
    // Deduplica IPs para testar
    const uniqueIps = Array.from(new Set(candidateOriginIps.map((c) => c.ip)));

    await Promise.all(
      uniqueIps.slice(0, 5).map(async (ip) => {
        try {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), 3000);

          // Tenta conexão direta via HTTP/HTTPS no IP passando o Host Header
          const res = await fetch(`http://${ip}/`, {
            signal: controller.signal,
            headers: {
              Host: cleanDomain,
              "User-Agent": "ChimeraGuard-Origin-Probe/1.4",
            },
          });
          clearTimeout(timer);

          const candidate = candidateOriginIps.find((c) => c.ip === ip);
          if (candidate) {
            candidate.statusCode = res.status;
            candidate.serverBanner = res.headers.get("server") || undefined;
            // Se o servidor responde com código de sucesso ou redirecionamento de aplicação
            if (res.status < 500 && res.status !== 404 && res.status !== 403) {
              candidate.virtualHostMatch = true;
              if (!confirmedBypassIps.includes(ip)) {
                confirmedBypassIps.push(ip);
              }
            }
          }
        } catch {
          // Timeout ou conexão recusada
        }
      })
    );
  }

  // Avaliação de Risco e Score
  let riskScore = 0;
  let overallStatus: OriginLeakReport["overallStatus"] = "SECURE";
  let summary = "Nenhum vazamento de IP real de origem foi detectado. Borda e proxies protegidos.";

  if (confirmedBypassIps.length > 0) {
    overallStatus = "CRITICAL_BYPASS";
    riskScore = 95;
    summary = `CRÍTICO: Vazamento confirmado! O servidor de origem responde diretamente em ${confirmedBypassIps.join(", ")}, ignorando 100% da proteção da CDN/WAF.`;
  } else if (candidateOriginIps.length > 0) {
    overallStatus = "WARNING";
    riskScore = 65;
    summary = `ALERTA: Foram descobertos ${candidateOriginIps.length} IPs candidatos fora da CDN via registros SPF/MX/Subdomínios. Recomenda-se bloquear acesso direto no firewall.`;
  } else if (!isBehindProxyOrCdn) {
    overallStatus = "WARNING";
    riskScore = 50;
    summary = `O domínio não utiliza serviço de proxy ou CDN de borda (como Cloudflare). O tráfego bate diretamente no IP público ${primaryIps.join(", ") || "desconhecido"}.`;
  }

  const durationMs = Date.now() - startTime;
  const firewallPatches = generateOriginFirewallPatches(confirmedBypassIps.length > 0 ? confirmedBypassIps : candidateOriginIps.map((c) => c.ip));

  return {
    targetDomain: cleanDomain,
    isBehindProxyOrCdn,
    proxyProvider,
    primaryIps,
    candidateOriginIps,
    confirmedBypassIps,
    testedVectors: {
      spfInspected: true,
      spfIpsFound,
      mxInspected: true,
      mxHostsFound,
      subdomainsProbed: HIGH_RISK_ORIGIN_SUBDOMAINS.length,
      subdomainsExposed,
    },
    overallStatus,
    riskScore,
    summary,
    firewallPatches,
    durationMs,
  };
}
