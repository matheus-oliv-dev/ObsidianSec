import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { auditUniversalEndpoint } from "../scanner/universal-web-scanner.ts";
import { analyzeCspPolicy } from "../lib/security/csp-analyzer.ts";
import { GeminiProvider, BuiltinCognitiveSimulator, OpenAIProvider, OllamaLocalProvider } from "../agents/ai/llm-provider.ts";
import { CYBERBRAIN_SYSTEM_PROMPT } from "../agents/ai/prompts.ts";
import { KNOWLEDGE_BASE } from "../data/knowledge.ts";

// Proteção global contra encerramento inesperado do processo por sockets remotos
process.on("uncaughtException", (err) => {
  console.warn("⚠️ [SHIELD] Exceção não tratada interceptada com segurança:", err?.message || err);
});
process.on("unhandledRejection", (reason) => {
  console.warn("⚠️ [SHIELD] Rejeição de Promise interceptada com segurança:", reason);
});

// Carregamento automático de .env nativo no Node.js
if (fs.existsSync(".env")) {
  try {
    if (typeof (process as any).loadEnvFile === "function") {
      (process as any).loadEnvFile(".env");
    } else {
      const envContent = fs.readFileSync(".env", "utf-8");
      for (const line of envContent.split("\n")) {
        const match = line.match(/^\s*([\w_]+)\s*=\s*(.*)?\s*$/);
        if (match && !match[1].startsWith("#")) {
          const key = match[1];
          const val = (match[2] || "").trim().replace(/^['"]|['"]$/g, "");
          if (!process.env[key]) process.env[key] = val;
        }
      }
    }
  } catch (e) {
    console.warn("Aviso ao carregar .env:", e);
  }
}

const PORT = process.env.PORT || 3333;
const PUBLIC_DIR = path.resolve(process.cwd(), "public");

// ====================================================================
// SLIDING WINDOW RATE LIMITER & ANTI-BOT SHIELD POR IP
// ====================================================================
interface ClientRequestLog {
  timestamps: number[];
  blockedUntil?: number;
}

const rateLimitStore = new Map<string, ClientRequestLog>();

// Limpeza automática de IPs inativos a cada 5 minutos para evitar vazamento de memória
setInterval(() => {
  const now = Date.now();
  for (const [ip, log] of rateLimitStore.entries()) {
    log.timestamps = log.timestamps.filter((t) => now - t < 60000);
    if (log.timestamps.length === 0 && (!log.blockedUntil || log.blockedUntil < now)) {
      rateLimitStore.delete(ip);
    }
  }
}, 300000);

/**
 * Valida o limite de requisições por IP (Sliding Window Algorithm)
 */
function checkRateLimit(ip: string, maxRequests = 10, windowMs = 60000): { allowed: boolean; remaining: number; resetTime: number; retryAfterSeconds?: number } {
  const now = Date.now();
  let log = rateLimitStore.get(ip);

  if (!log) {
    log = { timestamps: [] };
    rateLimitStore.set(ip, log);
  }

  // Se o IP estiver em cooldown de bloqueio
  if (log.blockedUntil && log.blockedUntil > now) {
    const retryAfterSeconds = Math.ceil((log.blockedUntil - now) / 1000);
    return { allowed: false, remaining: 0, resetTime: log.blockedUntil, retryAfterSeconds };
  }

  // Filtrar apenas timestamps dentro da janela deslizante (últimos 60s)
  log.timestamps = log.timestamps.filter((t) => now - t < windowMs);

  if (log.timestamps.length >= maxRequests) {
    // Bloqueia o IP por 30 segundos por excesso de requisições
    log.blockedUntil = now + 30000;
    const retryAfterSeconds = 30;
    return { allowed: false, remaining: 0, resetTime: log.blockedUntil, retryAfterSeconds };
  }

  log.timestamps.push(now);
  const remaining = Math.max(0, maxRequests - log.timestamps.length);
  const resetTime = log.timestamps[0] + windowMs;

  return { allowed: true, remaining, resetTime };
}

/**
 * Servidor Web Nativo BomberCyber Dashboard (Resiliente, Rate-Limited e Blindado)
 */
export function createWebServer() {
  const server = http.createServer(async (req, res) => {
    try {
      const parsedUrl = new URL(req.url || "/", `http://${req.headers.host}`);
      const pathname = parsedUrl.pathname;
      const clientIp = (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim() || req.socket.remoteAddress || "127.0.0.1";

      res.setHeader("X-Content-Type-Options", "nosniff");
      res.setHeader("X-Frame-Options", "DENY");
      res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
      res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
      res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
      res.setHeader(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; connect-src 'self' https://generativelanguage.googleapis.com; img-src 'self' data:; frame-ancestors 'none';",
      );

      // ==========================================
      // API: /api/knowledge (Enciclopédia & Wiki de Segurança)
      // ==========================================
      if (pathname === "/api/knowledge" && req.method === "GET") {
        const rateCheck = checkRateLimit(clientIp, 60, 60000); // 60 req/min para leitura
        res.setHeader("X-RateLimit-Limit", "60");
        res.setHeader("X-RateLimit-Remaining", String(rateCheck.remaining));
        res.setHeader("X-RateLimit-Reset", String(Math.floor(rateCheck.resetTime / 1000)));

        if (!rateCheck.allowed) {
          res.setHeader("Retry-After", String(rateCheck.retryAfterSeconds || 30));
          res.writeHead(429, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Limite de requisições excedido. Aguarde antes de tentar novamente." }));
          return;
        }

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ total: KNOWLEDGE_BASE.length, items: KNOWLEDGE_BASE }));
        return;
      }

      // ==========================================
      // API: /api/audit (Auditoria de Borda - Limite Rígido Anti-Bot)
      // ==========================================
      if (pathname === "/api/audit" && req.method === "POST") {
        // Limite de 10 auditorias por minuto por IP para evitar spam de bots e exaustão
        const rateCheck = checkRateLimit(clientIp, 10, 60000);
        res.setHeader("X-RateLimit-Limit", "10");
        res.setHeader("X-RateLimit-Remaining", String(rateCheck.remaining));
        res.setHeader("X-RateLimit-Reset", String(Math.floor(rateCheck.resetTime / 1000)));

        if (!rateCheck.allowed) {
          res.setHeader("Retry-After", String(rateCheck.retryAfterSeconds || 30));
          res.writeHead(429, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              error: `🛡️ Limite de requisições excedido (${rateCheck.retryAfterSeconds}s de cooldown). Para mitigar ataques de bots e abusos, aguarde alguns segundos antes de disparar outra auditoria.`,
            }),
          );
          return;
        }

        let body = "";
        req.on("data", (chunk) => {
          body += chunk;
          if (body.length > 50000) req.destroy();
        });

        req.on("end", async () => {
          try {
            const { url, acceptedTerms, apiKey, aiProvider } = JSON.parse(body || "{}");

            if (!acceptedTerms) {
              res.writeHead(403, { "Content-Type": "application/json" });
              res.end(
                JSON.stringify({
                  error: "É obrigatório aceitar os Termos de Uso e Isenção de Responsabilidade para prosseguir.",
                }),
              );
              return;
            }

            if (!url || typeof url !== "string" || !url.startsWith("http")) {
              res.writeHead(400, { "Content-Type": "application/json" });
              res.end(
                JSON.stringify({
                  error: "URL inválida. Informe uma URL válida iniciando com http:// ou https://",
                }),
              );
              return;
            }

            // 1. Auditoria Universal de Protocolos e Cabeçalhos com Proteção de Socket
            let auditReport;
            try {
              auditReport = await auditUniversalEndpoint(url);
            } catch (scanErr: any) {
              res.writeHead(502, { "Content-Type": "application/json" });
              res.end(JSON.stringify({ error: `Não foi possível conectar ao alvo: ${scanErr?.message || "Conexão recusada ou timeout."}` }));
              return;
            }

            // 2. Análise detalhada do CSP se presente
            let cspAnalysis = null;
            if (auditReport.securityHeaders.csp.value) {
              try {
                cspAnalysis = analyzeCspPolicy(auditReport.securityHeaders.csp.value);
              } catch (e) {
                console.warn("Aviso na análise de CSP:", e);
              }
            }

            // 3. Cálculo Detalhado e Pedagógico da Pontuação
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
                lesson: "Garante que dados em trânsito e cookies de sessão não sejam interceptados em redes Wi-Fi públicas.",
              });
            } else {
              missedItems.push({
                control: "Strict-Transport-Security (HSTS)",
                lostPoints: 20,
                risk: "Ataques de Man-in-the-Middle (MitM) e SSL Stripping.",
                lesson: "Adicione 'Strict-Transport-Security: max-age=31536000; includeSubDomains' no seu servidor.",
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
                risk: "Acesso inadvertido a hardware e APIs do navegador por scripts de anúncios/terceiros.",
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

            // 4. Execução do CyberBrain com IA Selecionada pelo Usuário ou Fallback Cognitivo Seguro
            let aiProviderName = "Google Gemini 3 Flash";
            let customAiText: string | null = null;
            const effectiveGeminiKey = apiKey || process.env.GEMINI_API_KEY;

            try {
              if ((aiProvider === "gemini" || (!aiProvider && process.env.GEMINI_API_KEY)) && effectiveGeminiKey) {
                aiProviderName = "Google Gemini 3 Flash";
                const gemini = new GeminiProvider(effectiveGeminiKey);
                const aiPrompt = `Analise a segurança de ${url}. Score: ${score}/100 (${grade}). Controles Ausentes: ${missedItems.map((m) => m.control).join(", ")}. Controles Ativos: ${earnedItems.map((e) => e.control).join(", ")}. Forneça um parecer didático em 3 parágrafos curtos explicando o que o desenvolvedor deve aprender e como corrigir.`;
                customAiText = await gemini.generateResponse([
                  { role: "system", content: CYBERBRAIN_SYSTEM_PROMPT },
                  { role: "user", content: aiPrompt },
                ]);
              } else if (aiProvider === "ollama") {
                aiProviderName = "Ollama Local (DeepSeek/Llama)";
                const ollama = new OllamaLocalProvider();
                customAiText = await ollama.generateResponse([
                  { role: "system", content: CYBERBRAIN_SYSTEM_PROMPT },
                  { role: "user", content: `Analise a segurança de ${url}. Score: ${score}/100.` },
                ]);
              }
            } catch (aiErr: any) {
              console.warn("⚠️ [CYBERBRAIN]: IA externa indisponível ou com pico de demanda. Ativando Motor Cognitivo Embutido...");
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

            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(
              JSON.stringify({
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
              }),
            );
          } catch (err: any) {
            res.writeHead(500, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: err?.message || "Erro interno ao processar a auditoria." }));
          }
        });
        return;
      }

      // ==========================================
      // Servir Arquivos Estáticos da Pasta /public
      // ==========================================
      let filePath = path.join(PUBLIC_DIR, pathname === "/" ? "index.html" : pathname);

      if (!filePath.startsWith(PUBLIC_DIR)) {
        res.writeHead(403);
        res.end("Acesso proibido.");
        return;
      }

      if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
        filePath = path.join(PUBLIC_DIR, "index.html");
      }

      const ext = path.extname(filePath).toLowerCase();
      const mimeTypes: Record<string, string> = {
        ".html": "text/html; charset=utf-8",
        ".css": "text/css; charset=utf-8",
        ".js": "application/javascript; charset=utf-8",
        ".json": "application/json",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".svg": "image/svg+xml",
      };

      const contentType = mimeTypes[ext] || "application/octet-stream";
      fs.readFile(filePath, (err, content) => {
        if (err) {
          res.writeHead(404);
          res.end("Arquivo não encontrado.");
        } else {
          res.writeHead(200, { "Content-Type": contentType });
          res.end(content);
        }
      });
    } catch (criticalErr: any) {
      console.warn("⚠️ [CRITICAL SERVER SHIELD]:", criticalErr);
      try {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Erro interno no servidor." }));
      } catch {}
    }
  });

  return { server, port: PORT };
}
