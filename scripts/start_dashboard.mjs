#!/usr/bin/env node
import { createWebServer } from "../src/server/web-server.ts";

function startOnAvailablePort(initialPort = 3333) {
  let port = initialPort;
  const { server } = createWebServer();

  server.on("error", (err) => {
    if (err.code === "EADDRINUSE") {
      console.log(`⚠️ Porta ${port} ocupada. Tentando porta ${port + 1}...`);
      startOnAvailablePort(port + 1);
    } else {
      console.error("Erro no servidor:", err);
    }
  });

  server.listen(port, () => {
    console.log("\n╔══════════════════════════════════════════════════════════════════════╗");
    console.log("║    🟢 CHIMERAGUARD // DEVSECOPS DEFENSE PLATFORM ONLINE!              ║");
    console.log("╠══════════════════════════════════════════════════════════════════════╣");
    console.log(`║    👉 Acesse no seu navegador: http://localhost:${port}               ║`);
    console.log("║    🎓 Diagnóstico Pedagógico & Por que da Pontuação Ativo            ║");
    console.log("║    🧠 Suporte a Google Gemini 3.7 Flash & Fallback Cognitivo Ativo  ║");
    console.log("╚══════════════════════════════════════════════════════════════════════╝\n");
  });
}

startOnAvailablePort(Number(process.env.PORT || 3333));
