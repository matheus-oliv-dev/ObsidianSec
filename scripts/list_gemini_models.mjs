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

async function listModels() {
  console.log("Consultando lista de modelos disponíveis para esta chave...");
  const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models?key=${apiKey}`);
  console.log("Status:", res.status);
  const data = await res.json();
  if (data.models) {
    console.log("Modelos encontrados:");
    for (const m of data.models) {
      if (m.supportedGenerationMethods?.includes("generateContent")) {
        console.log(` - ${m.name} (${m.displayName})`);
      }
    }
  } else {
    console.log("Resposta:", JSON.stringify(data, null, 2));
  }
}

listModels();
