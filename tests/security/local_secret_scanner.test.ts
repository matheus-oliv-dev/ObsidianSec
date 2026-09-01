import { describe, expect, it } from "vitest";
import { scanDirectoryForSecrets } from "@/lib/security/local-secret-scanner";
import path from "node:path";
import fs from "node:fs";

describe("🔍 Local Secret & SAST Scanner Suite", () => {
  it("TEST-143: detecta chaves de API da AWS, OpenAI e Stripe", () => {
    const tmpDir = path.join(process.cwd(), "tests", "fixtures", "secrets_test");
    if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir, { recursive: true });

    const fakeFile = path.join(tmpDir, "leaked_config.js");
    fs.writeFileSync(
      fakeFile,
      `
      const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
      const OPENAI = "sk-abcdefghijklmnopqrstuvwxyz1234567890";
      const STRIPE = "sk_live_51ABCDefghIJKLMnopqrstuv1234567890";
      `,
      "utf-8"
    );

    const report = scanDirectoryForSecrets(tmpDir);

    // Limpa fixture após teste
    fs.rmSync(tmpDir, { recursive: true, force: true });

    expect(report.findings.length).toBeGreaterThanOrEqual(3);
    expect(report.findings.some((f) => f.ruleId === "aws-access-key")).toBe(true);
    expect(report.findings.some((f) => f.ruleId === "openai-api-key")).toBe(true);
    expect(report.findings.some((f) => f.ruleId === "stripe-secret-key")).toBe(true);
    expect(report.criticalCount).toBeGreaterThanOrEqual(3);
    expect(report.isClean).toBe(false);
  });

  it("TEST-144: identifica exposição de arquivos sensíveis (.env, id_rsa)", () => {
    const tmpDir = path.join(process.cwd(), "tests", "fixtures", "files_test");
    if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir, { recursive: true });

    fs.writeFileSync(path.join(tmpDir, ".env.production"), "DB_PASS=123", "utf-8");
    fs.writeFileSync(path.join(tmpDir, "id_rsa"), "-----BEGIN RSA PRIVATE KEY-----", "utf-8");

    const report = scanDirectoryForSecrets(tmpDir);

    fs.rmSync(tmpDir, { recursive: true, force: true });

    expect(report.findings.some((f) => f.filePath.includes(".env.production"))).toBe(true);
    expect(report.findings.some((f) => f.filePath.includes("id_rsa"))).toBe(true);
  });
});