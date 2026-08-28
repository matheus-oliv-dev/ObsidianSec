import fs from "node:fs";

let apiKey = "";
if (fs.existsSync(".env")) {
  const env = fs.readFileSync(".env", "utf-8");
  for (const line of env.split("\n")) {
    const match = line.match(/^\s*([\w_]+)\s*=\s*(.*)?\s*$/);
    if (match && !match[1].startsWith("#")) {
      if (match[1] === "GEMINI_API_KEY") apiKey = (match[2] || "").trim();
    }
  }
}

const models = ["gemini-2.5-flash", "gemini-2.5-pro", "gemini-flash-latest", "gemini-3-flash-preview", "gemini-3.5-flash", "gemini-3.7-flash"];

async function testAll() {
  for (const m of models) {
    console.log(`\nTestando modelo: ${m}...`);
    try {
      const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${m}:generateContent?key=${apiKey}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: [{ parts: [{ text: "Diga apenas: 'BOMBERCYBER_ONLINE'" }] }]
        }),
        signal: AbortSignal.timeout(6000)
      });
      console.log(`Status: ${res.status} ${res.statusText}`);
      const text = await res.text();
      console.log(`Resposta: ${text.slice(0, 300)}`);
      if (res.ok) {
        console.log(`✅ SUCESSO NO MODELO ${m}!`);
        break;
      }
    } catch (e) {
      console.log(`Erro no modelo ${m}: ${e.message}`);
    }
  }
}

testAll();
