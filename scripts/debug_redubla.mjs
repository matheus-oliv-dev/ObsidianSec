import { auditUniversalEndpoint } from "../src/scanner/universal-web-scanner.ts";

async function testRedubla() {
  console.log("=== TESTANDO REDUBLA.COM.BR COM O SCANNER ATUAL ===");
  try {
    const report1 = await auditUniversalEndpoint("https://redubla.com.br");
    console.log("Resultado https://redubla.com.br:", JSON.stringify(report1, null, 2));
  } catch (e) {
    console.error("Erro 1:", e);
  }

  console.log("\n=== TESTANDO COM FETCH SEGUINDO REDIRECIONAMENTOS ===");
  try {
    const res = await fetch("https://redubla.com.br", {
      method: "GET",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
      }
    });
    console.log("Status final:", res.status);
    console.log("URL final:", res.url);
    console.log("Headers finais:");
    for (const [k, v] of res.headers.entries()) {
      console.log(`  ${k}: ${v}`);
    }
  } catch (e) {
    console.error("Erro 2:", e);
  }
}

testRedubla();
