import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  isPrivateOrMetadataIp,
  normalizeIp,
  resolveSafePath,
  validateSafeUrl,
} from "@/lib/security/cloud-guard";

describe("☁️ Cloud, Metadata Security & Path Traversal Suite", () => {
  describe("1. Cloud Metadata SSRF Shield (AWS, GCP, Azure, K8s)", () => {
    it("TEST-088: bloqueia requisições contra o IP de metadados Cloud (169.254.169.254)", () => {
      expect(isPrivateOrMetadataIp("169.254.169.254")).toBe(true);
      expect(isPrivateOrMetadataIp("169.254.10.20")).toBe(true);
    });

    it("TEST-089: bloqueia faixas privadas RFC 1918 e loopback (127.0.0.1, 10.x, 192.168.x)", () => {
      expect(isPrivateOrMetadataIp("127.0.0.1")).toBe(true);
      expect(isPrivateOrMetadataIp("localhost")).toBe(true);
      expect(isPrivateOrMetadataIp("10.0.0.1")).toBe(true);
      expect(isPrivateOrMetadataIp("192.168.1.254")).toBe(true);
      expect(isPrivateOrMetadataIp("172.20.0.1")).toBe(true);
    });

    it("TEST-090: bloqueia domínios internos de metadados GCP (metadata.google.internal)", () => {
      expect(isPrivateOrMetadataIp("metadata.google.internal")).toBe(true);
    });

    it("TEST-093: normaliza e neutraliza evasões com IPs em formato Hexadecimal e Decimal", () => {
      // 0x7f000001 = 127.0.0.1
      expect(normalizeIp("0x7f000001")).toBe("127.0.0.1");
      expect(isPrivateOrMetadataIp("0x7f000001")).toBe(true);

      // 2130706433 = 127.0.0.1
      expect(normalizeIp("2130706433")).toBe("127.0.0.1");
      expect(isPrivateOrMetadataIp("2130706433")).toBe(true);
    });

    it("TEST-095: rejeita URLs com esquemas não-HTTP (file://, gopher://, ftp://)", () => {
      expect(validateSafeUrl("file:///etc/passwd").isAllowed).toBe(false);
      expect(validateSafeUrl("gopher://127.0.0.1:6379").isAllowed).toBe(false);
      expect(validateSafeUrl("http://169.254.169.254/latest/meta-data").isAllowed).toBe(false);
      expect(validateSafeUrl("https://bombercyber.io/webhook").isAllowed).toBe(true);
    });
  });

  describe("2. Path Traversal & LFI Shield", () => {
    const baseDir = path.resolve("app", "storage", "uploads");

    it("TEST-096: bloqueia travessia de diretório com ../ e resolve canônico", () => {
      expect(() => resolveSafePath(baseDir, "../../../../etc/passwd")).toThrow(
        /Path traversal/i,
      );
      expect(() => resolveSafePath(baseDir, "..\\..\\windows\\win.ini")).toThrow(
        /Path traversal/i,
      );
    });

    it("TEST-098: neutraliza travessias com percent-encoding duplo", () => {
      expect(() =>
        resolveSafePath(baseDir, "%252e%252e%252f%252e%252e%252fetc/passwd"),
      ).toThrow(/Path traversal/i);
    });

    it("TEST-099: rejeita injeções com Null Bytes (%00 e \\0)", () => {
      expect(() => resolveSafePath(baseDir, "relatorio.pdf\0.png")).toThrow(
        /Null Byte/i,
      );
    });

    it("TEST-101: permite arquivos legítimos contidos dentro do diretório base", () => {
      const safe = resolveSafePath(baseDir, "avatar-usuario.png");
      expect(safe).toContain("avatar-usuario.png");
    });

    it("TEST-103: bloqueia vulnerabilidade Zip Slip em nomes de arquivos descompactados", () => {
      const maliciousZipEntryName = "../../cron.d/malicious-task";
      expect(() => resolveSafePath(baseDir, maliciousZipEntryName)).toThrow(
        /Path traversal/i,
      );
    });
  });
});
