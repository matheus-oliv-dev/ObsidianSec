/**
 * Passive Subdomain Reconnaissance (Certificate Transparency Log Analyzer)
 * Realiza descoberta passiva e inofensiva de subdomínios expostos via logs públicos
 * de certificados TLS (crt.sh) sem enviar pacotes intrusivos ao alvo.
 */

export interface SubdomainReconReport {
  domain: string;
  totalFound: number;
  subdomains: string[];
  durationMs: number;
  source: string;
  status: "SUCCESS" | "EMPTY" | "ERROR";
  error?: string;
}

export async function discoverSubdomains(domainInput: string): Promise<SubdomainReconReport> {
  const startTime = Date.now();
  const cleanDomain = domainInput
    .replace(/^https?:\/\//i, "")
    .split("/")[0]
    .split(":")[0]
    .trim()
    .toLowerCase();

  if (!cleanDomain) {
    return {
      domain: "",
      totalFound: 0,
      subdomains: [],
      durationMs: 0,
      source: "crt.sh",
      status: "ERROR",
      error: "Domínio inválido fornecido.",
    };
  }

  const url = `https://crt.sh/?q=%.${encodeURIComponent(cleanDomain)}&output=json`;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);

    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        "User-Agent": "ObsidianSec-PassiveRecon/1.1 (+https://obsidiansec.dev)",
        Accept: "application/json",
      },
    });

    clearTimeout(timeout);

    if (!res.ok) {
      return {
        domain: cleanDomain,
        totalFound: 0,
        subdomains: [],
        durationMs: Date.now() - startTime,
        source: "crt.sh",
        status: "ERROR",
        error: `Serviço de Certificate Transparency retornou HTTP ${res.status}.`,
      };
    }

    const data = await res.json();
    if (!Array.isArray(data)) {
      return {
        domain: cleanDomain,
        totalFound: 0,
        subdomains: [],
        durationMs: Date.now() - startTime,
        source: "crt.sh",
        status: "EMPTY",
      };
    }

    const uniqueSubs = new Set<string>();

    for (const entry of data) {
      const nameValue = String(entry.name_value || "");
      const lines = nameValue.split("\n");
      for (const line of lines) {
        const sub = line.trim().toLowerCase();
        if (sub && sub.endsWith(cleanDomain) && !sub.includes("@")) {
          // Remove wildcard inicial *.
          const normalized = sub.startsWith("*.") ? sub.slice(2) : sub;
          if (normalized) uniqueSubs.add(normalized);
        }
      }
    }

    const sortedSubs = Array.from(uniqueSubs).sort((a, b) => a.localeCompare(b));

    return {
      domain: cleanDomain,
      totalFound: sortedSubs.length,
      subdomains: sortedSubs,
      durationMs: Date.now() - startTime,
      source: "Certificate Transparency Logs (crt.sh)",
      status: sortedSubs.length > 0 ? "SUCCESS" : "EMPTY",
    };
  } catch (err: any) {
    return {
      domain: cleanDomain,
      totalFound: 0,
      subdomains: [],
      durationMs: Date.now() - startTime,
      source: "crt.sh",
      status: "ERROR",
      error: err.message?.includes("abort")
        ? "Tempo limite esgotado ao consultar logs públicos de certificados."
        : `Erro na consulta de subdomínios: ${err.message || "Falha de rede"}`,
    };
  }
}