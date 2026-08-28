import https from "node:https";

const TARGET_URL = "https://bot.matheusdev.com.br";

console.log("======================================================================");
console.log("🛡️  BOMBERCYBER LIVE SECURITY AUDIT · TESTES DE DEFESA AO VIVO");
console.log("🎯  Alvo: " + TARGET_URL);
console.log("📅  Data/Hora: " + new Date().toISOString());
console.log("======================================================================\n");

async function fetchHeaders(url, customHeaders = {}) {
  const res = await fetch(url, {
    method: "GET",
    headers: customHeaders,
    redirect: "manual",
  });
  return {
    status: res.status,
    headers: res.headers,
  };
}

async function runLiveTests() {
  const results = [];

  // ==========================================
  // TESTE 1: Content-Security-Policy (CSP)
  // ==========================================
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log("🧪 TESTE 1: Content-Security-Policy (Defesa contra XSS & Injeção de Scripts)");
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  const mainRes = await fetchHeaders(TARGET_URL + "/");
  const csp = mainRes.headers.get("content-security-policy");
  
  console.log(`📡 Requisição enviada: GET ${TARGET_URL}/`);
  console.log(`📥 Status HTTP recebido: ${mainRes.status}`);
  console.log(`🔍 Valor do cabeçalho 'Content-Security-Policy': ${csp ? `"${csp}"` : "❌ NÃO ENCONTRADO (null)"}`);

  if (csp) {
    console.log("✅ RESULTADO: APROVADO - O navegador aplicará restrições de carregamento de scripts.");
    results.push({ test: "Content-Security-Policy (CSP)", status: "APROVADO", risk: "Nenhum" });
  } else {
    console.log("❌ RESULTADO: VULNERÁVEL (ALTA) - O navegador não possui regras para barrar scripts externos.");
    results.push({ test: "Content-Security-Policy (CSP)", status: "FALHA / AUSENTE", risk: "Alto (Risco de XSS e conexões não autorizadas)" });
  }
  console.log("");

  // ==========================================
  // TESTE 2: X-Frame-Options (Clickjacking)
  // ==========================================
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log("🧪 TESTE 2: Proteção Anti-Clickjacking (X-Frame-Options & frame-ancestors)");
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  const xFrame = mainRes.headers.get("x-frame-options");
  
  console.log(`📡 Verificando permissão de incorporação em <iframe>...`);
  console.log(`🔍 Valor do cabeçalho 'X-Frame-Options': ${xFrame ? `"${xFrame}"` : "❌ NÃO ENCONTRADO (null)"}`);

  if (xFrame && (xFrame.toUpperCase() === "DENY" || xFrame.toUpperCase() === "SAMEORIGIN")) {
    console.log(`✅ RESULTADO: APROVADO - Bloqueio de frames ativo (${xFrame}).`);
    results.push({ test: "X-Frame-Options (Clickjacking)", status: "APROVADO", risk: "Nenhum" });
  } else {
    console.log("❌ RESULTADO: VULNERÁVEL (MÉDIA) - Páginas externas podem embutir seu site em <iframe>.");
    results.push({ test: "X-Frame-Options (Clickjacking)", status: "FALHA / AUSENTE", risk: "Médio (Vulnerável a Clickjacking / Iframe Spoofing)" });
  }
  console.log("");

  // ==========================================
  // TESTE 3: X-Content-Type-Options (MIME Sniffing)
  // ==========================================
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log("🧪 TESTE 3: Proteção contra MIME Sniffing (X-Content-Type-Options)");
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  const contentTypeOptions = mainRes.headers.get("x-content-type-options");
  
  console.log(`📡 Verificando se o navegador é forçado a respeitar os tipos MIME declarados...`);
  console.log(`🔍 Valor do cabeçalho 'X-Content-Type-Options': ${contentTypeOptions ? `"${contentTypeOptions}"` : "❌ NÃO ENCONTRADO (null)"}`);

  if (contentTypeOptions && contentTypeOptions.toLowerCase() === "nosniff") {
    console.log("✅ RESULTADO: APROVADO - Proteção 'nosniff' ativa.");
    results.push({ test: "X-Content-Type-Options", status: "APROVADO", risk: "Nenhum" });
  } else {
    console.log("❌ RESULTADO: VULNERÁVEL (BAIXA) - Ausência da flag 'nosniff'.");
    results.push({ test: "X-Content-Type-Options", status: "FALHA / AUSENTE", risk: "Baixo (Possível confusão de tipo MIME)" });
  }
  console.log("");

  // ==========================================
  // TESTE 4: Permissions-Policy (Hardware APIs)
  // ==========================================
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log("🧪 TESTE 4: Política de Permissões de Hardware (Permissions-Policy)");
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  const permissionsPolicy = mainRes.headers.get("permissions-policy");
  
  console.log(`📡 Verificando restrições explícitas para Câmera, Geolocalização e USB...`);
  console.log(`🔍 Valor do cabeçalho 'Permissions-Policy': ${permissionsPolicy ? `"${permissionsPolicy}"` : "❌ NÃO ENCONTRADO (null)"}`);

  if (permissionsPolicy) {
    console.log("✅ RESULTADO: APROVADO - Permissões restritas declaradas.");
    results.push({ test: "Permissions-Policy", status: "APROVADO", risk: "Nenhum" });
  } else {
    console.log("❌ RESULTADO: VULNERÁVEL (BAIXA) - Não há bloqueio declarativo de APIs do navegador.");
    results.push({ test: "Permissions-Policy", status: "FALHA / AUSENTE", risk: "Baixo (APIs de hardware não restringidas formalmente)" });
  }
  console.log("");

  // ==========================================
  // RESUMO GERAL AO VIVO
  // ==========================================
  console.log("======================================================================");
  console.log("📊 PLACAR CONSOLIDADO DA AUDITORIA AO VIVO");
  console.log("======================================================================");
  results.forEach((r, idx) => {
    const icon = r.status.includes("APROVADO") ? "✅" : "⚠️";
    console.log(`${icon} [${idx + 1}/4] ${r.test.padEnd(35)} : ${r.status}`);
    if (r.risk !== "Nenhum") {
      console.log(`      ↳ Impacto: ${r.risk}`);
    }
  });
  console.log("======================================================================\n");
}

runLiveTests().catch(console.error);
