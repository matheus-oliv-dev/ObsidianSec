import { GeminiProvider } from "../src/agents/ai/llm-provider.ts";
import fs from "node:fs";

if (fs.existsSync(".env")) {
  const env = fs.readFileSync(".env", "utf-8");
  for (const line of env.split("\n")) {
    const match = line.match(/^\s*([\w_]+)\s*=\s*(.*)?\s*$/);
    if (match && !match[1].startsWith("#")) {
      process.env[match[1]] = (match[2] || "").trim();
    }
  }
}

async function benchmark() {
  console.log("⏱️ Medindo tempo de resposta da IA com gemini-3-flash-preview...");
  const t0 = performance.now();
  const gemini = new GeminiProvider();
  const res = await gemini.generateResponse([
    { role: "user", content: "Diga 'OK'." }
  ]);
  const t1 = performance.now();
  console.log(`✅ Resposta recebida em: ${((t1 - t0) / 1000).toFixed(2)} segundos!`);
  console.log(`💬 Resposta: ${res.trim()}`);
}

benchmark();
