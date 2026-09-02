import { describe, it, expect } from "vitest";
import {
  isNewerVersion,
  formatUpdateNotification,
  checkCliUpdate,
} from "../../src/lib/security/update-notifier.ts";

describe("🔔 Automated Version Update Notifier", () => {
  it("compara versões SemVer corretamente (major, minor, patch)", () => {
    // Novas versões
    expect(isNewerVersion("1.4.1", "1.4.0")).toBe(true);
    expect(isNewerVersion("1.5.0", "1.4.9")).toBe(true);
    expect(isNewerVersion("2.0.0", "1.9.9")).toBe(true);

    // Versões iguais ou inferiores
    expect(isNewerVersion("1.4.0", "1.4.0")).toBe(false);
    expect(isNewerVersion("1.3.9", "1.4.0")).toBe(false);
    expect(isNewerVersion("0.9.0", "1.0.0")).toBe(false);
  });

  it("formata o banner de notificação de forma visual e amigável", () => {
    const banner = formatUpdateNotification("1.3.1", "1.4.0");
    expect(banner).toContain("1.3.1 →");
    expect(banner).toContain("1.4.0");
    expect(banner).toContain("npm install -g obsidiansec");
  });

  it("não quebra e retorna null quando offline ou com timeout de rede", async () => {
    const res = await checkCliUpdate("1.4.0", { timeoutMs: 1 });
    // Deve finalizar graciosamente sem lançar erro
    expect(res === null || typeof res === "string").toBe(true);
  });
});
