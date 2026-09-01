import { describe, expect, it } from "vitest";
import { auditJwtToken } from "@/lib/security/jwt-token-analyzer";

describe("🎟️ JWT Token Security Auditor Suite", () => {
  it("TEST-145: detecta token com alg: none e ausência de assinatura", () => {
    const rawNoneToken = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.";
    const report = auditJwtToken(rawNoneToken);

    expect(report.isValidStructure).toBe(true);
    expect(report.algorithm).toBe("NONE");
    expect(report.signaturePresent).toBe(false);
    expect(report.status).toBe("CRITICAL");
    expect(report.issues.some((i) => i.severity === "CRITICAL")).toBe(true);
  });

  it("TEST-146: detecta expiração de token e claims com PII", () => {
    // Token com senha no payload e expiração no passado
    const payload = Buffer.from(
      JSON.stringify({ sub: "user-123", password: "plain-secret-password", exp: 1600000000 })
    ).toString("base64url");
    const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
    const testToken = `${header}.${payload}.fakeSignature`;

    const report = auditJwtToken(testToken);

    expect(report.algorithm).toBe("HS256");
    expect(report.isExpired).toBe(true);
    expect(report.issues.some((i) => i.message.includes("Vazamento de PII"))).toBe(true);
  });
});