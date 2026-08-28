import https from "node:https";
import http from "node:http";

async function fetchDetails(urlStr) {
  return new Promise((resolve) => {
    const url = new URL(urlStr);
    const client = url.protocol === "https:" ? https : http;
    const req = client.request(
      url,
      {
        method: "GET",
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
          "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
      },
      (res) => {
        let body = "";
        res.on("data", (chunk) => {
          if (body.length < 10000) body += chunk;
        });
        res.on("end", () => {
          resolve({
            url: urlStr,
            statusCode: res.statusCode,
            headers: res.headers,
            bodySnippet: body.slice(0, 1000),
          });
        });
      }
    );
    req.on("error", (e) => resolve({ url: urlStr, error: e.message }));
    req.end();
  });
}

async function inspectSite() {
  console.log("🔍 Iniciando Inspeção Passiva Detalhada de https://stacca.app/ ...\n");

  // 1. Teste de Redirecionamento HTTP -> HTTPS
  const httpRes = await fetchDetails("http://stacca.app/");
  console.log("1️⃣ [Redirecionamento HTTP -> HTTPS]");
  console.log(`   Status: ${httpRes.statusCode}`);
  console.log(`   Location: ${httpRes.headers?.location || "Nenhum"}`);

  // 2. Análise da Raiz HTTPS
  const httpsRes = await fetchDetails("https://stacca.app/");
  console.log("\n2️⃣ [Análise do Endpoint Principal HTTPS]");
  console.log(`   Status HTTP: ${httpsRes.statusCode}`);
  console.log("   Cabeçalhos Recebidos:");
  for (const [k, v] of Object.entries(httpsRes.headers || {})) {
    console.log(`     - ${k}: ${v}`);
  }

  // 3. Verificação de Meta Tags de Segurança no HTML
  console.log("\n3️⃣ [Inspeção de Meta Tags no HTML]");
  const body = httpsRes.bodySnippet || "";
  const hasMetaCsp = /http-equiv=["']Content-Security-Policy["']/i.test(body);
  const hasMetaReferrer = /name=["']referrer["']/i.test(body);
  console.log(`   - Meta CSP no HTML: ${hasMetaCsp ? "Encontrado" : "Não encontrado"}`);
  console.log(`   - Meta Referrer no HTML: ${hasMetaReferrer ? "Encontrado" : "Não encontrado"}`);

  // 4. Verificação de Cookies
  console.log("\n4️⃣ [Análise de Cookies de Sessão]");
  const setCookie = httpsRes.headers?.["set-cookie"];
  if (setCookie) {
    console.log(`   - Set-Cookie presente: ${JSON.stringify(setCookie)}`);
  } else {
    console.log("   - Nenhum cookie de sessão foi emitido na resposta inicial.");
  }

  // 5. Teste de Rotas Comuns (robots.txt, sitemap)
  const robotsRes = await fetchDetails("https://stacca.app/robots.txt");
  console.log("\n5️⃣ [Inspeção de Arquivos Públicos]");
  console.log(`   - /robots.txt status: ${robotsRes.statusCode}`);
}

inspectSite();
