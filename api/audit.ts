import type { VercelRequest, VercelResponse } from "@vercel/node";

// ============================================================================
// VALIDAÇÃO DE SEGURANÇA & SSRF SHIELD
// ============================================================================
function validateTargetUrlSafety(targetUrl: string): { safe: boolean; reason?: string } {
  try {
    const parsed = new URL(targetUrl);

    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return { safe: false, reason: "Protocolo não suportado. Utilize HTTP ou HTTPS." };
    }

    const hostname = parsed.hostname.toLowerCase();

    // 1. Bloqueio de IP de Metadados de Nuvem (AWS/GCP/Azure/Oracle/Vercel)
    if (
      hostname === "169.254.169.254" ||
      hostname === "metadata.google.internal" ||
      hostname === "instance-data"
    ) {
      return {
        safe: false,
        reason: "SSRF Shield: Tentativa de acesso a serviços de metadados de nuvem bloqueada.",
      };
    }

    // 2. Bloqueio de Redes Locais e Loopback (RFC 1918 & RFC 6890)
    if (
      hostname === "localhost" ||
      hostname === "127.0.0.1" ||
      hostname === "0.0.0.0" ||
      hostname === "::1" ||
      hostname.startsWith("10.") ||
      hostname.startsWith("192.168.") ||
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(hostname)
    ) {
      return {
        safe: false,
        reason: "SSRF Shield: Acesso a redes internas e loopback bloqueado por segurança.",
      };
    }

    return { safe: true };
  } catch (err: any) {
    return { safe: false, reason: `URL malformada: ${err.message}` };
  }
}

// ============================================================================
// AUDITORIA UNIVERSAL DE CABEÇALHOS E BORDAS
// ============================================================================
async function auditUniversalEndpoint(targetUrl: string) {
  const safety = validateTargetUrlSafety(targetUrl);
  if (!safety.safe) {
    throw new Error(safety.reason);
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 12000);

  try {
    const res = await fetch(targetUrl, {
      method: "GET",
      signal: controller.signal,
      redirect: "follow",
      headers: {
        "User-Agent": "ObsidianSec-DevSecOps-Auditor/1.0 (+https://obsidiansec.dev)",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
    });

    clearTimeout(timeoutId);

    const headers = res.headers;
    const serverHeader = headers.get("server") || "";
    const xPoweredBy = headers.get("x-powered-by") || "";

    const cspVal = headers.get("content-security-policy");
    const cspReportOnly = headers.get("content-security-policy-report-only");
    const xfoVal = headers.get("x-frame-options");
    const xctoVal = headers.get("x-content-type-options");
    const permVal = headers.get("permissions-policy");
    const hstsVal = headers.get("strict-transport-security");
    const refVal = headers.get("referrer-policy");
    const coopVal = headers.get("cross-origin-opener-policy");

    // Detectar Servidor / CDN
    let serverDetected = "Desconhecido / Proxy Oculto";
    const sLower = serverHeader.toLowerCase();
    if (sLower.includes("cloudflare")) serverDetected = "Cloudflare Edge";
    else if (sLower.includes("nginx")) serverDetected = "Nginx Web Server";
    else if (sLower.includes("apache")) serverDetected = "Apache HTTP Server";
    else if (sLower.includes("caddy")) serverDetected = "Caddy Web Server";
    else if (sLower.includes("vercel")) serverDetected = "Vercel Edge Network";
    else if (sLower.includes("netlify")) serverDetected = "Netlify Edge";
    else if (sLower.includes("iis") || sLower.includes("microsoft")) serverDetected = "Microsoft IIS";
    else if (serverHeader) serverDetected = serverHeader;

    // Detectar Framework
    let frameworkDetected: string | undefined;
    const pLower = xPoweredBy.toLowerCase();
    if (pLower.includes("express")) frameworkDetected = "Node.js / Express";
    else if (pLower.includes("next")) frameworkDetected = "Next.js";
    else if (pLower.includes("php")) frameworkDetected = `PHP Runtime (${xPoweredBy})`;
    else if (xPoweredBy) frameworkDetected = xPoweredBy;

    // Snippets de Remediação
    const remediationSnippets = [
      {
        serverType: "Nginx (nginx.conf)",
        snippet: `# =========================================================
# OBSIDIANSEC DEFENSE PATCH // NGINX HARDENING
# =========================================================
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'strict-dynamic'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
server_tokens off;`,
      },
      {
        serverType: "Apache (.htaccess)",
        snippet: `# =========================================================
# OBSIDIANSEC DEFENSE PATCH // APACHE HTTP HARDENING
# =========================================================
<IfModule mod_headers.c>
  Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';"
  Header always set X-Frame-Options "DENY"
  Header always set X-Content-Type-Options "nosniff"
  Header always set Referrer-Policy "strict-origin-when-cross-origin"
  Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"
  Header always set Cross-Origin-Opener-Policy "same-origin"
  Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
  Header unset X-Powered-By
</IfModule>
ServerSignature Off`,
      },
      {
        serverType: "Node.js (Helmet / Express)",
        snippet: `// =========================================================
// OBSIDIANSEC DEFENSE PATCH // NODE.JS & EXPRESS HELMET
// =========================================================
import express from 'express';
import helmet from 'helmet';

const app = express();

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: [],
    }
  },
  crossOriginOpenerPolicy: { policy: "same-origin" },
  referrerPolicy: { policy: "strict-origin-when-cross-origin" },
  hsts: { maxAge: 63072000, includeSubDomains: true, preload: true }
}));`,
      },
      {
        serverType: "Cloudflare (Transform Rules)",
        snippet: `# =========================================================
# OBSIDIANSEC DEFENSE PATCH // CLOUDFLARE EDGE HEADERS
# HTTP Response Header Modification Rules
# =========================================================
Set Dynamic Header:
- Content-Security-Policy: "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';"
- X-Frame-Options: "DENY"
- X-Content-Type-Options: "nosniff"
- Referrer-Policy: "strict-origin-when-cross-origin"
- Permissions-Policy: "camera=(), microphone=(), geolocation=()"
- Cross-Origin-Opener-Policy: "same-origin"`,
      },
      {
        serverType: "Vercel (vercel.json)",
        snippet: `{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        { "key": "X-Content-Type-Options", "value": "nosniff" },
        { "key": "X-Frame-Options", "value": "DENY" },
        { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" },
        { "key": "Permissions-Policy", "value": "camera=(), microphone=(), geolocation=()" },
        { "key": "Cross-Origin-Opener-Policy", "value": "same-origin" },
        { "key": "Content-Security-Policy", "value": "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';" }
      ]
    }
  ]
}`,
      },
    ];

    return {
      targetUrl,
      httpStatus: res.status,
      serverDetected,
      frameworkDetected,
      securityHeaders: {
        csp: {
          present: !!cspVal || !!cspReportOnly,
          value: cspVal || cspReportOnly || undefined,
          isReportOnly: !cspVal && !!cspReportOnly,
        },
        xFrameOptions: { present: !!xfoVal, value: xfoVal || undefined },
        xContentTypeOptions: { present: !!xctoVal, value: xctoVal || undefined },
        permissionsPolicy: { present: !!permVal, value: permVal || undefined },
        hsts: { present: !!hstsVal, value: hstsVal || undefined },
        referrerPolicy: { present: !!refVal, value: refVal || undefined },
        coop: { present: !!coopVal, value: coopVal || undefined },
      },
      remediationSnippets,
    };
  } catch (err: any) {
    clearTimeout(timeoutId);
    throw new Error(err.message || "Falha na conexão com o alvo.");
  }
}

// ============================================================================
// GEMINI 3.7 FLASH & FALLBACK COGNITIVO
// ============================================================================
async function generateAiDiagnosis(auditReport: any, score: number, grade: string, apiKey?: string) {
  const finalApiKey = apiKey || process.env.GEMINI_API_KEY || "";
  const models = ["gemini-3.7-flash", "gemini-3-flash-preview", "gemini-3.6-flash", "gemini-3.5-flash"];

  const prompt = `Você é o CyberBrain da plataforma ObsidianSec. Analise o relatório de segurança do site: ${auditReport.targetUrl}
- Score: ${score}/100 (Grade ${grade})
- Servidor: ${auditReport.serverDetected}
- CSP: ${auditReport.securityHeaders.csp.present ? "Presente" : "AUSENTE"}
- X-Frame-Options: ${auditReport.securityHeaders.xFrameOptions.present ? "Presente" : "AUSENTE"}
- X-Content-Type-Options: ${auditReport.securityHeaders.xContentTypeOptions.present ? "Presente" : "AUSENTE"}
- Permissions-Policy: ${auditReport.securityHeaders.permissionsPolicy.present ? "Presente" : "AUSENTE"}
- HSTS: ${auditReport.securityHeaders.hsts.present ? "Presente" : "AUSENTE"}
- COOP: ${auditReport.securityHeaders.coop.present ? "Presente" : "AUSENTE"}

Gere uma análise pedagógica, tática e defensiva curta (3 a 4 parágrafos) em português, destacando os riscos reais e como aplicar as correções.`;

  if (finalApiKey) {
    const maestroSystemPrompt = `Você é o OBSIDIANSEC MASTER ORCHESTRATOR (CyberBrain Maestro), o cérebro supremo de IA do Esquadrão DevSecOps ObsidianSec.
Sua missão: fornecer diagnósticos táticos, pedagógicos, investigativos e de alta autoridade técnica sobre a segurança de borda, cabeçalhos HTTP, arquitetura Zero Trust (NIST SP 800-207), OWASP Top 10 e conformidade LGPD.
Tom de voz: Tático, analítico, imponente, preciso e orientador.`;

    for (const model of models) {
      try {
        const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${finalApiKey}`;
        const resp = await fetch(url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            system_instruction: { parts: [{ text: maestroSystemPrompt }] },
            contents: [{ parts: [{ text: prompt }] }],
            generationConfig: { maxOutputTokens: 1000, temperature: 0.2 },
          }),
        });

        if (resp.ok) {
          const data = await resp.json();
          const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
          if (text) return { provider: "Google Gemini 3.7 Flash", analysis: text };
        }
      } catch {
        // Tenta o próximo modelo
      }
    }
  }

  // Motor Cognitivo Embutido (Offline Fallback Instantâneo)
  let fallbackText = `### 🧠 PARECER COGNITIVO // OBSIDIANSEC DEFENSE CORE\n\n`;
  fallbackText += `O alvo **${auditReport.targetUrl}** obteve pontuação **${score}/100 (Grade ${grade})** com infraestrutura identificada como **${auditReport.serverDetected}**.\n\n`;

  if (score >= 90) {
    fallbackText += `**Veredito:** O ambiente apresenta **Excelente Postura de Segurança**, implementando cabeçalhos de isolamento rigorosos contra ataques de Cross-Site Scripting (XSS), Clickjacking e MIME Sniffing.\n\n`;
  } else if (score >= 60) {
    fallbackText += `**Veredito:** O ambiente possui **Postura Moderada de Segurança**, mas deixa brechas importantes abertas que facilitam ataques de Clickjacking ou execução de scripts maliciosos injetados.\n\n`;
  } else {
    fallbackText += `**Veredito:** O ambiente encontra-se em **Estado Crítico de Vulnerabilidade**, sem políticas de isolamento de borda, permitindo iframe embeeding malicioso e bypass de políticas do navegador.\n\n`;
  }

  fallbackText += `**Recomendação Imediata:** Aplique os patches de cabeçalhos de resposta fornecidos abaixo na sua camada de proxy/CDN para elevar a nota para **A+ (100/100)** imediatamente.`;

  return { provider: "ObsidianSec Cognitive Core", analysis: fallbackText };
}

// ============================================================================
// HANDLER PRINCIPAL DA SERVERLESS FUNCTION
// ============================================================================
export default async function handler(req: VercelRequest, res: VercelResponse) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");

  if (req.method !== "POST") {
    res.status(405).json({ error: "Método não permitido. Use POST." });
    return;
  }

  try {
    const rawBody = req.body;
    const body = typeof rawBody === "string" ? JSON.parse(rawBody || "{}") : rawBody || {};
    const { url, acceptedTerms, apiKey } = body;

    if (!acceptedTerms) {
      res.status(403).json({
        error: "É obrigatório aceitar os Termos de Uso e Isenção de Responsabilidade (LGPD) para prosseguir.",
      });
      return;
    }

    if (!url || typeof url !== "string" || !url.startsWith("http")) {
      res.status(400).json({
        error: "URL inválida. Informe uma URL válida iniciando com http:// ou https://",
      });
      return;
    }

    // 1. Auditoria de Rede e Cabeçalhos
    const auditReport = await auditUniversalEndpoint(url);

    // 2. Cálculo Pedagógico da Pontuação
    const earnedItems: Array<{ control: string; points: number; explanation: string; lesson: string }> = [];
    const missedItems: Array<{ control: string; lostPoints: number; risk: string; lesson: string }> = [];

    const h = auditReport.securityHeaders;

    if (h.csp.present) {
      earnedItems.push({
        control: "Content-Security-Policy (CSP)",
        points: 30,
        explanation: "Diretiva ativa restringindo as origens permitidas de scripts e recursos.",
        lesson: "Mitiga ataques devastadores de XSS e injeção maliciosa de dados.",
      });
    } else {
      missedItems.push({
        control: "Content-Security-Policy (CSP)",
        lostPoints: 30,
        risk: "Vulnerabilidade aberta a injeção de scripts (XSS) e carregamento de iframes não autorizados.",
        lesson: "Defina o cabeçalho 'Content-Security-Policy: default-src 'self'' para bloquear scripts externos não auditados.",
      });
    }

    if (h.xFrameOptions.present) {
      earnedItems.push({
        control: "X-Frame-Options",
        points: 20,
        explanation: `Proteção ativa configurada com valor '${h.xFrameOptions.value}'.`,
        lesson: "Impede que páginas de phishing incorporem seu site em iframes transparentes.",
      });
    } else {
      missedItems.push({
        control: "X-Frame-Options",
        lostPoints: 20,
        risk: "Risco severo de Clickjacking / UI Redressing.",
        lesson: "Configure 'X-Frame-Options: DENY' ou use CSP 'frame-ancestors 'none''.",
      });
    }

    if (h.xContentTypeOptions.present) {
      earnedItems.push({
        control: "X-Content-Type-Options",
        points: 15,
        explanation: "Proteção 'nosniff' ativa contra interpretação incorreta de tipos MIME.",
        lesson: "Evita que navegadores executem arquivos de imagem ou texto como scripts JavaScript.",
      });
    } else {
      missedItems.push({
        control: "X-Content-Type-Options",
        lostPoints: 15,
        risk: "Vulnerável a MIME-Sniffing e execução de payloads camuflados em uploads.",
        lesson: "Adicione 'X-Content-Type-Options: nosniff' nas respostas do servidor.",
      });
    }

    if (h.hsts.present) {
      earnedItems.push({
        control: "Strict-Transport-Security (HSTS)",
        points: 15,
        explanation: "Forçamento criptográfico de conexões HTTPS ativado.",
        lesson: "Impede ataques de downgrade SSL Strip e interceptação em redes Wi-Fi públicas.",
      });
    } else {
      missedItems.push({
        control: "Strict-Transport-Security (HSTS)",
        lostPoints: 15,
        risk: "Possibilidade de ataques Man-in-the-Middle (MitM) com downgrade para HTTP plano.",
        lesson: "Habilite 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload'.",
      });
    }

    if (h.permissionsPolicy.present) {
      earnedItems.push({
        control: "Permissions-Policy",
        points: 10,
        explanation: "Restrição de APIs de hardware ativada.",
        lesson: "Bloqueia acesso a microfone, câmera e geolocalização por scripts de terceiros.",
      });
    } else {
      missedItems.push({
        control: "Permissions-Policy",
        lostPoints: 10,
        risk: "Scripts maliciosos podem tentar invocar APIs de sensores, câmera ou pagamentos.",
        lesson: "Configure 'Permissions-Policy: camera=(), microphone=(), geolocation=()'.",
      });
    }

    if (h.coop.present) {
      earnedItems.push({
        control: "Cross-Origin-Opener-Policy (COOP)",
        points: 5,
        explanation: "Isolamento de contexto de janela ('same-origin') ativo.",
        lesson: "Protege o processo do navegador contra ataques de canal lateral como Spectre.",
      });
    } else {
      missedItems.push({
        control: "Cross-Origin-Opener-Policy (COOP)",
        lostPoints: 5,
        risk: "Janelas abertas podem manter referências de contexto acessíveis a janelas maliciosas.",
        lesson: "Adicione 'Cross-Origin-Opener-Policy: same-origin'.",
      });
    }

    if (h.referrerPolicy.present) {
      earnedItems.push({
        control: "Referrer-Policy",
        points: 5,
        explanation: "Isolamento de metadados em navegação externa ativo.",
        lesson: "Evita o vazamento de caminhos de URLs internas para domínios de terceiros.",
      });
    } else {
      missedItems.push({
        control: "Referrer-Policy",
        lostPoints: 5,
        risk: "URLs com dados sensíveis podem ser expostas no cabeçalho Referer em cliques externos.",
        lesson: "Adicione 'Referrer-Policy: strict-origin-when-cross-origin'.",
      });
    }

    const totalScore = earnedItems.reduce((acc, curr) => acc + curr.points, 0);

    let grade = "F";
    let gradeVerdict = "Postura Crítica de Segurança: Múltiplas defesas essenciais ausentes.";
    if (totalScore >= 95) {
      grade = "A+";
      gradeVerdict = "Excelente! Fortaleza de Borda: Controles de isolamento e cabeçalhos em nível máximo.";
    } else if (totalScore >= 80) {
      grade = "A";
      gradeVerdict = "Ótima Blindagem: A maioria dos controles defensivos está ativa e protegendo o usuário.";
    } else if (totalScore >= 60) {
      grade = "B";
      gradeVerdict = "Postura Regular: Controles parciais. Recomenda-se aplicar os patches fornecidos.";
    } else if (totalScore >= 40) {
      grade = "C";
      gradeVerdict = "Postura Fraca: Falhas graves de cabeçalhos facilitam exploração por atacantes.";
    }

    // 3. Síntese com Inteligência Artificial
    const aiDiagnosis = await generateAiDiagnosis(auditReport, totalScore, grade, apiKey);

    // Retornar JSON completo
    res.status(200).json({
      url: auditReport.targetUrl,
      httpStatus: auditReport.httpStatus,
      serverDetected: auditReport.serverDetected,
      frameworkDetected: auditReport.frameworkDetected,
      score: totalScore,
      grade,
      gradeVerdict,
      scoreBreakdown: {
        earned: earnedItems,
        missed: missedItems,
        earnedItems,
        missedItems,
        totalEarned: totalScore,
      },
      securityHeaders: auditReport.securityHeaders,
      aiDiagnosis,
      aiAnalysis: {
        providerUsed: aiDiagnosis.provider,
        customAnalysis: aiDiagnosis.analysis,
      },
      remediationSnippets: auditReport.remediationSnippets,
    });
  } catch (err: any) {
    res.status(500).json({
      error: `Erro ao processar auditoria: ${err.message || "Erro desconhecido."}`,
    });
  }
}
