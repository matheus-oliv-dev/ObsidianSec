import { GeminiProvider } from "../src/agents/ai/llm-provider.ts";
import fs from "node:fs";

// Load .env
if (fs.existsSync(".env")) {
  const env = fs.readFileSync(".env", "utf-8");
  for (const line of env.split("\n")) {
    const match = line.match(/^\s*([\w_]+)\s*=\s*(.*)?\s*$/);
    if (match && !match[1].startsWith("#")) {
      process.env[match[1]] = (match[2] || "").trim();
    }
  }
}

async function test() {
  console.log("=== TESTANDO CONEXÃO DIRETA COM GOOGLE GEMINI API ===");
  try {
    const gemini = new GeminiProvider();
    const response = await gemini.generateResponse([
      { role: "system", content: "Você é o núcleo de inteligência de segurança cibernética CyberBrain." },
      { role: "user", content: "Responda em uma frase curta: O sistema BomberCyber com IA está ativo?" }
    ]);
    console.log("✅ RESPOSTA DA IA GEMINI RECEBIDA COM SUCESSO:");
    console.log(response);
  } catch (e) {
    console.error("❌ ERRO NA CHAMADA GEMINI:", e.message);
  }
}

test();
