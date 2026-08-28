import type { VercelRequest, VercelResponse } from "@vercel/node";
import { auditUniversalEndpoint } from "../src/scanner/universal-web-scanner";
import { analyzeCspPolicy } from "../src/lib/security/csp-analyzer";
import { GeminiProvider, BuiltinCognitiveSimulator } from "../src/agents/ai/llm-provider";
import { CYBERBRAIN_SYSTEM_PROMPT } from "../src/agents/ai/prompts";

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
    const body = typeof rawBody === "string" ? JSON.parse(rawBody || "{}") : (rawBody || {});
    const { url, acceptedTerms, apiKey, aiProvider } = body;

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

    // 1. Auditoria Universal de Protocolos e Cabeçalhos
    let auditReport;
    try {
      auditReport = await auditUniversalEndpoint(url);
    } catch (scanErr: any) {
      res.status(502).json({
        error: `Não foi possível conectar ao alvo: ${scanErr?.message || "Conexão recusada ou timeout."}`,
      });
      return;
    }

    // 2. Análise detalhada de CSP
    let cspAnalysis = null;
    if (auditReport.securityHeaders.csp.value) {
      try {
        cspAnalysis = analyzeCspPolicy(auditReport.securityHeaders.csp.value);
      } catch (e) {
        console.warn("Aviso na análise de CSP:", e);
      }
    }

    // 3. Cálculo Pedagógico da Pontuação
    const earnedItems: Array<{ control: string; points: number; explanation: string; lesson: string }> = [];
    const missedItems: Array<{ control: string; lostPoints: number; risk: string; lesson: string }> = [];

    let score = 0;

    // HSTS
    if (auditReport.securityHeaders.hsts.present) {
      score += 20;
      earnedItems.push({
        control: "Strict-Transport-Security (HSTS)",
        points: 20,
        explanation: "Força conexões criptografadas via HTTPS e impede downgrade para HTTP inseguro.",
        lesson: "Garante que dados em trânsito e cookies de sessão não sejam interceptados em redes públicas.",
      });
    } else {
      missedItems.push({
        control: "Strict-Transport-Security (HSTS)",
        lostPoints: 20,
        risk: "Ataques de Man-in-the-Middle (MitM) e SSL Stripping.",
        lesson: "Adicione 'Strict-Transport-Security: max-age=31536000; includeSubDomains' no servidor.",
      });
    }

    // X-Frame-Options
    if (auditReport.securityHeaders.xFrameOptions.present) {
      score += 20;
      earnedItems.push({
        control: "X-Frame-Options",
        points: 20,
        explanation: "Impede que o site seja renderizado dentro de <iframe> não autorizados.",
        lesson: "Elimina ataques de Clickjacking onde o usuário clica em botões invisíveis.",
      });
    } else {
      missedItems.push({
        control: "X-Frame-Options",
        lostPoints: 20,
        risk: "Clickjacking e sequestro de cliques de usuários autenticados.",
        lesson: "Configure 'X-Frame-Options: DENY' ou a diretiva CSP 'frame-ancestors 'none''.",
      });
    }

    // Content-Security-Policy
    if (auditReport.securityHeaders.csp.present) {
      const pts = auditReport.securityHeaders.csp.isReportOnly ? 15 : 25;
      score += pts;
      earnedItems.push({
        control: auditReport.securityHeaders.csp.isReportOnly ? "Content-Security-Policy (Report-Only)" : "Content-Security-Policy (Bloqueante)",
        points: pts,
        explanation: auditReport.securityHeaders.csp.isReportOnly
          ? "CSP ativo em modo de telemetria e observação."
          : "CSP ativo bloqueando ativamente carregamento de scripts não autorizados.",
        lesson: "É a barreira mais importante contra injeção de scripts (XSS) e vazamento de dados.",
      });
    } else {
      missedItems.push({
        control: "Content-Security-Policy (CSP)",
        lostPoints: 25,
        risk: "Cross-Site Scripting (XSS) e execução de scripts de terceiros maliciosos.",
        lesson: "Defina um CSP restringindo 'script-src' e 'default-src' para origens confiáveis.",
      });
    }

    // X-Content-Type-Options
    if (auditReport.securityHeaders.xContentTypeOptions.present) {
      score += 15;
      earnedItems.push({
        control: "X-Content-Type-Options: nosniff",
        points: 15,
        explanation: "Obriga o navegador a respeitar o MIME Type enviado pelo servidor.",
        lesson: "Impede que arquivos de imagem ou texto sejam executados como código JavaScript.",
      });
    } else {
      missedItems.push({
        control: "X-Content-Type-Options",
        lostPoints: 15,
        risk: "MIME-type Confusion e execução de arquivos não executáveis.",
        lesson: "Adicione 'X-Content-Type-Options: nosniff' nas respostas do servidor.",
      });
    }

    // Permissions-Policy
    if (auditReport.securityHeaders.permissionsPolicy.present) {
      score += 10;
      earnedItems.push({
        control: "Permissions-Policy",
        points: 10,
        explanation: "Restringe explicitamente recursos de hardware (câmera, microfone, GPS).",
        lesson: "Garante privacidade e impede que scripts de terceiros acessem hardware sem permissão.",
      });
    } else {
      missedItems.push({
        control: "Permissions-Policy",
        lostPoints: 10,
        risk: "Acesso inadvertido a hardware e APIs do navegador por scripts de terceiros.",
        lesson: "Configure 'Permissions-Policy: camera=(), microphone=(), geolocation=()'.",
      });
    }

    // Referrer-Policy
    if (auditReport.securityHeaders.referrerPolicy.present) {
      score += 5;
      earnedItems.push({
        control: "Referrer-Policy",
        points: 5,
        explanation: "Controla quanto da URL atual é vazada ao clicar em links externos.",
        lesson: "Evita o vazamento de tokens de sessão ou dados sensíveis presentes na URL.",
      });
    }

    // COOP
    if (auditReport.securityHeaders.coop.present) {
      score += 5;
      earnedItems.push({
        control: "Cross-Origin-Opener-Policy (COOP)",
        points: 5,
        explanation: "Isola o contexto de navegação e memória contra ataques Spectre e XS-Leaks.",
        lesson: "Garante que outras abas não possam interagir com o DOM da sua aplicação.",
      });
    }

    score = Math.min(100, score);

    let grade = "F";
    let gradeVerdict = "Crítico: Múltiplas vulnerabilidades de borda abertas. Requer atenção imediata.";
    if (score >= 85) {
      grade = "A+";
      gradeVerdict = "Excelente: Configuração de segurança de nível corporativo e DevSecOps moderno.";
    } else if (score >= 70) {
      grade = "A";
      gradeVerdict = "Bom: A maioria das defesas está ativa, restando apenas ajustes finos.";
    } else if (score >= 50) {
      grade = "B";
      gradeVerdict = "Médio / Regular: Protegido na camada de rede (HTTPS), mas vulnerável no navegador.";
    } else if (score >= 30) {
      grade = "C";
      gradeVerdict = "Fraco: Faltam cabeçalhos essenciais contra XSS e Clickjacking.";
    }

    // 4. Execução da IA com Chave da Vercel ou Fallback Cognitivo Seguro
    let aiProviderName = "Google Gemini 3 Flash";
    let customAiText: string | null = null;
    const effectiveGeminiKey = apiKey || process.env.GEMINI_API_KEY;

    try {
      if ((aiProvider === "gemini" || !aiProvider) && effectiveGeminiKey) {
        aiProviderName = "Google Gemini 3 Flash";
        const gemini = new GeminiProvider(effectiveGeminiKey);
        const aiPrompt = `Analise a segurança de ${url}. Score: ${score}/100 (${grade}). Controles Ausentes: ${missedItems.map((m) => m.control).join(", ")}. Controles Ativos: ${earnedItems.map((e) => e.control).join(", ")}. Forneça um parecer didático em 3 parágrafos curtos explicando o que o desenvolvedor deve aprender e como corrigir.`;
        customAiText = await gemini.generateResponse([
          { role: "system", content: CYBERBRAIN_SYSTEM_PROMPT },
          { role: "user", content: aiPrompt },
        ]);
      }
    } catch (aiErr: any) {
      console.warn("⚠️ [CYBERBRAIN VERCEL]: Ativando Motor Cognitivo Embutido...");
      aiProviderName = "Motor Cognitivo Embutido (Fallback Seguro)";
      const simulator = new BuiltinCognitiveSimulator();
      const simResponse = await simulator.generateResponse([
        { role: "user", content: `Auditoria de ${url}` },
      ]);
      try {
        const parsed = JSON.parse(simResponse);
        customAiText = `📌 Diagnóstico Cognitivo: ${parsed.cognitiveDiagnosis.threatAssessment}\n\n💡 Análise Técnica: ${parsed.cognitiveDiagnosis.deepAnalysis}`;
      } catch {
        customAiText = null;
      }
    }

    res.status(200).json({
      url: auditReport.targetUrl,
      httpStatus: auditReport.httpStatus,
      serverDetected: auditReport.serverDetected,
      frameworkDetected: auditReport.frameworkDetected,
      score,
      grade,
      gradeVerdict,
      scoreBreakdown: {
        earnedItems,
        missedItems,
        totalEarned: score,
      },
      securityHeaders: auditReport.securityHeaders,
      cspAnalysis,
      aiAnalysis: {
        providerUsed: aiProviderName,
        customAnalysis: customAiText,
      },
      remediationSnippets: auditReport.remediationSnippets,
      timestamp: new Date().toISOString(),
    });
  } catch (err: any) {
    res.status(500).json({ error: err?.message || "Erro interno ao processar a auditoria." });
  }
}
