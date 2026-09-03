import https from "node:https";
import http from "node:http";

const TARGET_URL = "https://bot.matheusdev.com.br";

console.log("\n╔══════════════════════════════════════════════════════════════════════╗");
console.log("║    🌐 AUDITORIA DE DIAGNÓSTICO EXTERNO · CHIMERAGUARD SECURITY        ║");
console.log("║    Alvo: " + TARGET_URL.padEnd(52) + "║");
console.log("╚══════════════════════════════════════════════════════════════════════╝\n");

async function checkUrl(url, options = {}) {
  const res = await fetch(url, {
    method: options.method || "GET",
    headers: options.headers || {},
    redirect: "manual",
  });
  return res;
}

async function runLiveDiagnostics() {
  const findings = [];
  const passed = [];

  // 1. Teste de Redirecionamento HTTP -> HTTPS
  console.log("👉 [1/6] Testando redirecionamento seguro (HTTP -> HTTPS)...");
  try {
    const httpRes = await checkUrl("http://bot.matheusdev.com.br/");
    const location = httpRes.headers.get("location");
    if (httpRes.status === 301 || httpRes.status === 308 || httpRes.status === 307) {
      if (location && location.startsWith("https://")) {
        passed.push("Redirecionamento HTTP para HTTPS ativo e seguro.");
      } else {
        findings.push({ severity: "MÉDIA", title: "Redirecionamento HTTP aponta para destino não-HTTPS.", detail: location });
      }
    } else {
      findings.push({ severity: "ALTA", title: "Porta HTTP (80) não força redirecionamento para HTTPS.", detail: `Status: ${httpRes.status}` });
    }
  } catch (e) {
    passed.push("Porta HTTP insegura recusada ou fechada pelo servidor.");
  }

  // 2. Auditoria dos Cabeçalhos de Resposta Principal (GET /)
  console.log("👉 [2/6] Analisando Cabeçalhos de Segurança (Security Headers)...");
  const mainRes = await checkUrl(TARGET_URL + "/");
  const headers = mainRes.headers;

  // HSTS
  const hsts = headers.get("strict-transport-security");
  if (hsts) {
    passed.push(`HSTS Ativo: ${hsts}`);
  } else {
    findings.push({ severity: "ALTA", title: "HSTS ausente", detail: "Sem garantia de transporte estrito HTTPS." });
  }

  // CSP
  const csp = headers.get("content-security-policy");
  if (csp) {
    passed.push("Content-Security-Policy (CSP) presente.");
  } else {
    findings.push({ severity: "ALTA", title: "Content-Security-Policy (CSP) ausente", detail: "O navegador não restringe as origens de scripts, imagens ou conexões WebSocket." });
  }

  // X-Frame-Options
  const xFrame = headers.get("x-frame-options");
  if (xFrame) {
    passed.push(`X-Frame-Options ativo: ${xFrame}`);
  } else {
    findings.push({ severity: "MÉDIA", title: "X-Frame-Options ausente", detail: "O site pode ser embutido em páginas de terceiros via <iframe> (vulnerável a Clickjacking)." });
  }

  // X-Content-Type-Options
  const nosniff = headers.get("x-content-type-options");
  if (nosniff && nosniff.toLowerCase() === "nosniff") {
    passed.push("X-Content-Type-Options: nosniff ativo.");
  } else {
    findings.push({ severity: "BAIXA", title: "X-Content-Type-Options ausente", detail: "O navegador pode tentar inferir tipos de arquivo (*MIME sniffing*)." });
  }

  // Permissions-Policy
  const permPolicy = headers.get("permissions-policy");
  if (permPolicy) {
    passed.push(`Permissions-Policy ativo: ${permPolicy}`);
  } else {
    findings.push({ severity: "BAIXA", title: "Permissions-Policy ausente", detail: "APIs de hardware (câmera, geolocalização) não possuem restrição declarativa." });
  }

  // 3. Teste de Política CORS (Cross-Origin Resource Sharing)
  console.log("👉 [3/6] Testando comportamento de Origem Cruzada (CORS)...");
  const corsRes = await checkUrl(TARGET_URL + "/", {
    headers: {
      "Origin": "https://attacker-origin.com",
    },
  });
  const allowOrigin = corsRes.headers.get("access-control-allow-origin");
  if (allowOrigin === "*") {
    findings.push({
      severity: "MÉDIA",
      title: "CORS Wildcard (Access-Control-Allow-Origin: *) no HTML principal",
      detail: "Qualquer página externa pode solicitar e ler o HTML da aplicação.",
    });
  } else if (allowOrigin) {
    passed.push(`CORS restrito a: ${allowOrigin}`);
  } else {
    passed.push("Sem cabeçalhos CORS abertos no HTML principal.");
  }

  // 4. Teste de Métodos HTTP (Preflight OPTIONS)
  console.log("👉 [4/6] Testando métodos HTTP e Preflight (OPTIONS)...");
  const optionsRes = await checkUrl(TARGET_URL + "/", { method: "OPTIONS" });
  const allowMethods = optionsRes.headers.get("allow") || optionsRes.headers.get("access-control-allow-methods");
  if (allowMethods) {
    passed.push(`Métodos suportados declarados: ${allowMethods}`);
  } else {
    passed.push(`Resposta OPTIONS retornou status HTTP ${optionsRes.status}`);
  }

  // 5. Verificação de Informações de Servidor e Tecnologia
  console.log("👉 [5/6] Analisando vazamento de cabeçalhos de infraestrutura...");
  const server = headers.get("server");
  const vercelId = headers.get("x-vercel-id");
  if (server) {
    passed.push(`Servidor de Borda identificado: ${server}`);
  }
  if (vercelId) {
    passed.push(`Instância Edge Vercel identificada: ${vercelId}`);
  }

  // 6. Resumo e Pontuação Ponderada
  console.log("\n======================================================================");
  console.log("📊 RESULTADO DO DIAGNÓSTICO DE SEGURANÇA");
  console.log("======================================================================");
  
  console.log("\n✅ PONTOS FORTES / APROVADOS:");
  passed.forEach(p => console.log(`  ✓ ${p}`));

  console.log("\n⚠️ PONTOS DE ATENÇÃO / VULNERABILIDADES IDENTIFICADAS:");
  if (findings.length === 0) {
    console.log("  Nenhuma vulnerabilidade identificada!");
  } else {
    findings.forEach(f => {
      console.log(`  [${f.severity}] ${f.title}`);
      console.log(`         ↳ Detalhe: ${f.detail}`);
    });
  }
  console.log("======================================================================\n");
}

runLiveDiagnostics().catch(console.error);
