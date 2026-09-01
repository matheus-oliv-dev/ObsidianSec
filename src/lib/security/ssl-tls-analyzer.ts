/**
 * SSL/TLS Certificate & Protocol Analyzer (Inspirado no SSL Labs)
 * Inspeciona certificados TLS, validade, emissor, algoritmos e gera nota de segurança.
 */

import tls from "node:tls";
import net from "node:net";
import { URL } from "node:url";

export interface SslTlsReport {
  targetUrl: string;
  valid: boolean;
  issuer: string;
  subject: string;
  subjectAltNames: string[];
  validFrom: string;
  validTo: string;
  daysUntilExpiry: number;
  isExpired: boolean;
  isExpiringSoon: boolean;
  serialNumber: string;
  fingerprint256: string;
  protocol: string;
  signatureAlgorithm: string;
  isSelfSigned: boolean;
  grade: string;
  issues: Array<{ severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"; message: string }>;
  durationMs: number;
}

export async function analyzeSslTls(targetUrl: string): Promise<SslTlsReport> {
  const startTime = Date.now();
  let url = targetUrl.trim();
  if (!url.startsWith("http://") && !url.startsWith("https://")) url = `https://${url}`;

  const parsed = new URL(url);
  const hostname = parsed.hostname;
  const port = parseInt(parsed.port) || 443;
  const issues: SslTlsReport["issues"] = [];

  return new Promise((resolve) => {
    let resolved = false;
    const finalize = (report: SslTlsReport) => {
      if (resolved) return;
      resolved = true;
      clearTimeout(timeout);
      resolve(report);
    };

    const timeout = setTimeout(() => {
      if (socket) socket.destroy();
      finalize({
        targetUrl: url, valid: false, issuer: "N/A", subject: "N/A", subjectAltNames: [],
        validFrom: "N/A", validTo: "N/A", daysUntilExpiry: -1, isExpired: true, isExpiringSoon: true,
        serialNumber: "N/A", fingerprint256: "N/A", protocol: "N/A", signatureAlgorithm: "N/A",
        isSelfSigned: false, grade: "F",
        issues: [{ severity: "CRITICAL", message: "Connection timed out — unable to establish TLS handshake." }],
        durationMs: Date.now() - startTime,
      });
    }, 5000);

    const isIp = net.isIP(hostname) !== 0;
    const connectOptions: tls.ConnectionOptions = {
      host: hostname,
      port,
      rejectUnauthorized: false,
      ...(isIp ? {} : { servername: hostname }),
    };

    let socket: tls.TLSSocket;
    try {
      socket = tls.connect(connectOptions, () => {
        const cert = socket.getPeerCertificate(true);
        const protocol = socket.getProtocol() || "unknown";
        const authorized = socket.authorized;

        const validFrom = cert.valid_from || "N/A";
        const validTo = cert.valid_to || "N/A";
        const validToDate = new Date(validTo);
        const now = new Date();
        const daysUntilExpiry = Math.floor((validToDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
        const isExpired = daysUntilExpiry < 0;
        const isExpiringSoon = daysUntilExpiry >= 0 && daysUntilExpiry <= 30;

        const issuerCN = cert.issuer?.CN || cert.issuer?.O || "Unknown";
        const subjectCN = cert.subject?.CN || "Unknown";
        const isSelfSigned = issuerCN === subjectCN && (!cert.issuer?.O || cert.issuer?.O === cert.subject?.O);

        const san = cert.subjectaltname ? cert.subjectaltname.split(", ").map((s: string) => s.replace("DNS:", "")) : [];
        const sigAlg = (cert as any).sigalg || "unknown";
        const serial = cert.serialNumber || "N/A";
        const fp256 = cert.fingerprint256 || "N/A";

        // Issue detection
        if (isExpired) issues.push({ severity: "CRITICAL", message: `Certificate expired ${Math.abs(daysUntilExpiry)} days ago.` });
        else if (isExpiringSoon) issues.push({ severity: "HIGH", message: `Certificate expires in ${daysUntilExpiry} days — renewal required.` });

        if (isSelfSigned) issues.push({ severity: "HIGH", message: "Self-signed certificate detected — not trusted by browsers." });
        if (!authorized && !isSelfSigned && !isExpired) issues.push({ severity: "MEDIUM", message: "Certificate chain validation failed." });

        if (protocol === "TLSv1" || protocol === "TLSv1.1") {
          issues.push({ severity: "CRITICAL", message: `Deprecated protocol ${protocol} in use — vulnerable to POODLE/BEAST.` });
        }
        if (sigAlg && (sigAlg.includes("sha1") || sigAlg.includes("md5"))) {
          issues.push({ severity: "HIGH", message: `Weak signature algorithm: ${sigAlg}. Migrate to SHA-256+.` });
        }
        if (san.length === 0) issues.push({ severity: "LOW", message: "No Subject Alternative Names (SAN) found." });

        // Grading
        let grade = "A+";
        if (isExpired) grade = "F";
        else if (isSelfSigned) grade = "F";
        else if (protocol === "TLSv1" || protocol === "TLSv1.1") grade = "C";
        else if (isExpiringSoon) grade = "C";
        else if (daysUntilExpiry < 90) grade = "A";
        else if (issues.some(i => i.severity === "HIGH")) grade = "B";

        socket.destroy();
        finalize({
          targetUrl: url, valid: !isExpired && authorized, issuer: issuerCN, subject: subjectCN,
          subjectAltNames: san, validFrom, validTo, daysUntilExpiry, isExpired, isExpiringSoon,
          serialNumber: serial, fingerprint256: fp256, protocol, signatureAlgorithm: sigAlg,
          isSelfSigned, grade, issues, durationMs: Date.now() - startTime,
        });
      });

      socket.on("error", (err) => {
        finalize({
          targetUrl: url, valid: false, issuer: "N/A", subject: "N/A", subjectAltNames: [],
          validFrom: "N/A", validTo: "N/A", daysUntilExpiry: -1, isExpired: true, isExpiringSoon: true,
          serialNumber: "N/A", fingerprint256: "N/A", protocol: "N/A", signatureAlgorithm: "N/A",
          isSelfSigned: false, grade: "F",
          issues: [{ severity: "CRITICAL", message: `TLS connection failed: ${err.message}` }],
          durationMs: Date.now() - startTime,
        });
      });
    } catch (err: any) {
      finalize({
        targetUrl: url, valid: false, issuer: "N/A", subject: "N/A", subjectAltNames: [],
        validFrom: "N/A", validTo: "N/A", daysUntilExpiry: -1, isExpired: true, isExpiringSoon: true,
        serialNumber: "N/A", fingerprint256: "N/A", protocol: "N/A", signatureAlgorithm: "N/A",
        isSelfSigned: false, grade: "F",
        issues: [{ severity: "CRITICAL", message: `TLS initialization failed: ${err.message}` }],
        durationMs: Date.now() - startTime,
      });
    }
  });
}
