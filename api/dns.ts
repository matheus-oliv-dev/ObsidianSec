import type { VercelRequest, VercelResponse } from "../src/types/index.ts";

export const config = {
  maxDuration: 15,
};

async function queryDoh(domain: string, type: "TXT" | "MX" | "DS"): Promise<string[]> {
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`;
  try {
    const res = await fetch(url, {
      headers: { Accept: "application/dns-json" },
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) return [];
    const data = await res.json();
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

export default async function handler(req: VercelRequest, res: VercelResponse) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");

  const domainQuery = (req.query?.domain as string) || (req.body?.domain as string) || "";
  const cleanDomain = domainQuery
    .replace(/^https?:\/\//i, "")
    .split("/")[0]
    .split(":")[0]
    .trim()
    .toLowerCase();

  if (!cleanDomain) {
    res.status(400).json({ error: "Parâmetro 'domain' é obrigatório. Ex: gov.br ou redubla.com.br" });
    return;
  }

  try {
    const [domainTxt, dmarcTxt, mxRecords, dsRecords] = await Promise.all([
      queryDoh(cleanDomain, "TXT"),
      queryDoh(`_dmarc.${cleanDomain}`, "TXT"),
      queryDoh(cleanDomain, "MX"),
      queryDoh(cleanDomain, "DS"),
    ]);

    // SPF Analysis
    const spfRaw = domainTxt.find((r) => r.toLowerCase().startsWith("v=spf1"));
    let spfPresent = !!spfRaw;
    let spfQualifier = "~all";
    const spfIssues: string[] = [];

    if (spfRaw) {
      if (spfRaw.includes("-all")) spfQualifier = "-all";
      else if (spfRaw.includes("~all")) spfQualifier = "~all";
      else if (spfRaw.includes("?all")) spfQualifier = "?all";
      else if (spfRaw.includes("+all")) {
        spfQualifier = "+all";
        spfIssues.push("SPF Perigoso (+all): Autoriza qualquer servidor no mundo a enviar emails.");
      }
    } else {
      spfIssues.push("Ausência de registro SPF: Domínio desprotegido contra falsificação de remetente.");
    }

    // DMARC Analysis
    const dmarcRaw = dmarcTxt.find((r) => r.toLowerCase().startsWith("v=dmarc1"));
    let dmarcPresent = !!dmarcRaw;
    let dmarcPolicy = "none";
    const dmarcIssues: string[] = [];

    if (dmarcRaw) {
      const pMatch = dmarcRaw.match(/p=([a-zA-Z]+)/i);
      if (pMatch) dmarcPolicy = pMatch[1].toLowerCase();
      if (dmarcPolicy === "none") {
        dmarcIssues.push("DMARC em modo apenas monitoramento (p=none). Não bloqueia envio de emails forjados.");
      }
    } else {
      dmarcIssues.push("Ausência de registro DMARC (_dmarc): Domínio vulnerável a ataques de Business Email Compromise (BEC).");
    }

    const dnssecActive = dsRecords.length > 0;
    const hasMx = mxRecords.length > 0;

    let emailScore = 0;
    if (spfPresent && spfQualifier !== "+all") emailScore += spfQualifier === "-all" ? 40 : 30;
    if (dmarcPresent && dmarcPolicy !== "none") emailScore += dmarcPolicy === "reject" ? 45 : 35;
    else if (dmarcPresent) emailScore += 15;
    if (dnssecActive) emailScore += 15;

    emailScore = Math.min(100, emailScore);

    let status: "SECURE" | "WARNING" | "CRITICAL" = "CRITICAL";
    if (emailScore >= 80) status = "SECURE";
    else if (emailScore >= 50) status = "WARNING";

    res.status(200).json({
      domain: cleanDomain,
      hasMx,
      mxRecords,
      spf: {
        present: spfPresent,
        rawRecord: spfRaw,
        qualifier: spfQualifier,
        issues: spfIssues,
        isCompliant: spfPresent && spfQualifier !== "+all",
      },
      dmarc: {
        present: dmarcPresent,
        rawRecord: dmarcRaw,
        policy: dmarcPolicy,
        issues: dmarcIssues,
        isEnforcing: dmarcPresent && (dmarcPolicy === "reject" || dmarcPolicy === "quarantine"),
      },
      dnssecActive,
      emailScore,
      status,
    });
  } catch (err: any) {
    res.status(500).json({ error: `Erro ao auditar DNS: ${err.message || "Erro desconhecido"}` });
  }
}