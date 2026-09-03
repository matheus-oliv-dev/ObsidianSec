/**
 * Standalone HTML Security Report Generator
 * Transforma qualquer auditoria de segurança em um relatório executivo HTML autocontido,
 * moderno e interativo para desenvolvedores, equipes de segurança e clientes.
 */

import { type UniversalAuditReport } from "../../scanner/universal-web-scanner.ts";

export function generateHtmlSecurityReport(
  report: UniversalAuditReport,
  score: number,
  grade: string
): string {
  const gradeColor =
    grade === "A+" || grade === "A"
      ? "#10b981"
      : grade === "B"
      ? "#eab308"
      : grade === "C"
      ? "#f97316"
      : "#ef4444";

  const dateStr = new Date().toLocaleString("en-US", {
    dateStyle: "full",
    timeStyle: "medium",
  });

  const headers = [
    {
      name: "Content-Security-Policy (CSP)",
      present: report.securityHeaders.csp.present,
      value: report.securityHeaders.csp.value,
      desc: "XSS & code injection defense",
    },
    {
      name: "Strict-Transport-Security (HSTS)",
      present: report.securityHeaders.hsts.present,
      value: report.securityHeaders.hsts.value,
      desc: "Forces HTTPS encryption (RFC 6797)",
    },
    {
      name: "X-Frame-Options",
      present: report.securityHeaders.xFrameOptions.present,
      value: report.securityHeaders.xFrameOptions.value,
      desc: "Zero-clickjacking defense",
    },
    {
      name: "X-Content-Type-Options",
      present: report.securityHeaders.xContentTypeOptions.present,
      value: report.securityHeaders.xContentTypeOptions.value,
      desc: "MIME sniffing protection (nosniff)",
    },
    {
      name: "Permissions-Policy",
      present: report.securityHeaders.permissionsPolicy.present,
      value: report.securityHeaders.permissionsPolicy.value,
      desc: "Camera, microphone & geolocation lockdown",
    },
    {
      name: "Referrer-Policy",
      present: report.securityHeaders.referrerPolicy.present,
      value: report.securityHeaders.referrerPolicy.value,
      desc: "URL credential leakage prevention",
    },
  ];

  const headerRows = headers
    .map((h) => {
      const statusBadge = h.present
        ? `<span style="background: rgba(16, 185, 129, 0.2); color: #10b981; padding: 3px 8px; border-radius: 6px; font-weight: bold; font-size: 11px;">ACTIVE</span>`
        : `<span style="background: rgba(239, 68, 68, 0.2); color: #ef4444; padding: 3px 8px; border-radius: 6px; font-weight: bold; font-size: 11px;">MISSING</span>`;
      return `
        <tr style="border-bottom: 1px solid #27272a;">
          <td style="padding: 12px; font-weight: 600;">${h.name}</td>
          <td style="padding: 12px; color: #a1a1aa; font-size: 12px;">${h.desc}</td>
          <td style="padding: 12px;">${statusBadge}</td>
          <td style="padding: 12px; font-family: monospace; font-size: 11px; color: #d4d4d8; max-width: 300px; word-break: break-all;">
            ${h.value ? h.value.slice(0, 100) + (h.value.length > 100 ? "..." : "") : "—"}
          </td>
        </tr>
      `;
    })
    .join("");

  const remediationCards = report.remediationSnippets
    .map(
      (snip) => `
      <div style="background: #18181b; border: 1px solid #27272a; border-radius: 8px; padding: 14px; margin-bottom: 12px;">
        <div style="font-weight: 600; color: #38bdf8; font-size: 13px; margin-bottom: 6px;">🔧 ${snip.serverType}</div>
        <pre style="background: #09090b; padding: 10px; border-radius: 6px; color: #a1a1aa; font-family: monospace; font-size: 11px; overflow-x: auto; margin: 0;"><code>${snip.snippet}</code></pre>
      </div>
    `
    )
    .join("");

  const attackNodes = report.attackChain.nodes
    .map(
      (node) => `
      <div style="background: #18181b; border-left: 3px solid ${node.type === "ENTRY_POINT" ? "#ef4444" : node.type === "IMPACT" ? "#dc2626" : "#f97316"}; padding: 10px 14px; border-radius: 0 8px 8px 0; margin-bottom: 8px;">
        <div style="font-weight: 600; font-size: 12px; color: #fafafa;">${node.label}</div>
        <div style="font-size: 11px; color: #a1a1aa;">${node.description}</div>
        ${node.mitreTechnique ? `<span style="display: inline-block; margin-top: 4px; background: #27272a; color: #38bdf8; font-size: 10px; font-family: monospace; padding: 2px 6px; border-radius: 4px;">MITRE ${node.mitreTechnique}</span>` : ""}
      </div>
    `
    )
    .join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ChimeraGuard Security Audit Report - ${report.targetUrl}</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: #09090b;
      color: #fafafa;
      margin: 0;
      padding: 24px;
      line-height: 1.5;
    }
    .container {
      max-width: 1000px;
      margin: 0 auto;
    }
    .header-card {
      background: #18181b;
      border: 1px solid #27272a;
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 16px;
    }
    .score-badge {
      background: #09090b;
      border: 2px solid ${gradeColor};
      border-radius: 12px;
      padding: 12px 24px;
      text-align: center;
    }
    .grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
      margin-bottom: 20px;
    }
    @media (max-width: 768px) {
      .grid { grid-template-columns: 1fr; }
    }
    .card {
      background: #18181b;
      border: 1px solid #27272a;
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 20px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    .footer {
      text-align: center;
      color: #71717a;
      font-size: 12px;
      margin-top: 40px;
    }
  </style>
</head>
<body>
  <div class="container">
    
    <!-- Top Header Card -->
    <div class="header-card">
      <div>
        <div style="font-size: 12px; color: #a1a1aa; letter-spacing: 1px; text-transform: uppercase;">🛡️ ChimeraGuard DevSecOps Arsenal</div>
        <h1 style="margin: 4px 0 6px 0; font-size: 22px;">Security Audit: <span style="color: #38bdf8;">${report.targetUrl}</span></h1>
        <div style="font-size: 12px; color: #71717a;">Generated on ${dateStr} • Status HTTP ${report.httpStatus}</div>
      </div>
      <div class="score-badge">
        <div style="font-size: 11px; color: #a1a1aa; text-transform: uppercase;">Security Grade</div>
        <div style="font-size: 38px; font-weight: 800; color: ${gradeColor}; line-height: 1.1;">${grade}</div>
        <div style="font-size: 11px; color: #a1a1aa;">Score: ${score}/100</div>
      </div>
    </div>

    <!-- Infrastructure Overview -->
    <div class="grid">
      <div class="card">
        <h2 style="font-size: 15px; margin: 0 0 12px 0; color: #38bdf8;">🌐 Edge & Infrastructure</h2>
        <div style="font-size: 13px; display: grid; gap: 8px;">
          <div><strong>Web Server:</strong> <span style="color: #a1a1aa;">${report.serverDetected}</span></div>
          <div><strong>Framework:</strong> <span style="color: #a1a1aa;">${report.frameworkDetected || "Not Disclosed (Hardened)"}</span></div>
          <div><strong>CDN / Edge Shield:</strong> <span style="color: #a1a1aa;">${report.cdnOrProxy || "Direct Server Exposure"}</span></div>
          <div><strong>Version Leakage:</strong> <span style="color: ${report.versionExposed ? "#ef4444" : "#10b981"};">${report.versionExposed ? "⚠️ Version Exposed" : "✅ Hidden"}</span></div>
        </div>
      </div>

      <div class="card">
        <h2 style="font-size: 15px; margin: 0 0 12px 0; color: #eab308;">🍪 Session & Cookie Audit</h2>
        <div style="font-size: 13px; display: grid; gap: 8px;">
          <div><strong>Cookies Analyzed:</strong> <span style="color: #a1a1aa;">${report.burpInspection.cookies.length}</span></div>
          <div><strong>CORS Policy:</strong> <span style="color: ${report.burpInspection.cors.severity === "HIGH" ? "#ef4444" : "#10b981"};">${report.burpInspection.cors.severity === "HIGH" ? "⚠️ Insecure / Permissive" : "✅ Protected"}</span></div>
          <div><strong>Wildcard with Credentials:</strong> <span style="color: ${report.burpInspection.cors.hasWildcardWithCredentials ? "#ef4444" : "#10b981"};">${report.burpInspection.cors.hasWildcardWithCredentials ? "CRITICAL RISK" : "None"}</span></div>
        </div>
      </div>
    </div>

    <!-- Security Headers Table -->
    <div class="card">
      <h2 style="font-size: 16px; margin: 0 0 16px 0;">🛡️ Tactical Security Headers Inspection</h2>
      <table>
        <thead>
          <tr style="border-bottom: 2px solid #27272a; text-align: left; color: #71717a; font-size: 11px; text-transform: uppercase;">
            <th style="padding: 8px 12px;">Header</th>
            <th style="padding: 8px 12px;">Defense Purpose</th>
            <th style="padding: 8px 12px;">Status</th>
            <th style="padding: 8px 12px;">Value Detected</th>
          </tr>
        </thead>
        <tbody>
          ${headerRows}
        </tbody>
      </table>
    </div>

    <!-- MITRE ATT&CK Chain -->
    <div class="card">
      <h2 style="font-size: 16px; margin: 0 0 8px 0; color: #f43f5e;">🕸️ BloodHound MITRE ATT&CK Exploitation Graph</h2>
      <p style="font-size: 12px; color: #a1a1aa; margin: 0 0 16px 0;">How an adversary can pivot missing defensive headers into active session hijacking and account takeover.</p>
      ${attackNodes}
    </div>

    <!-- Remediation Patches -->
    <div class="card">
      <h2 style="font-size: 16px; margin: 0 0 14px 0; color: #10b981;">🚀 Automated Virtual Patches (Ready to Deploy)</h2>
      <p style="font-size: 12px; color: #a1a1aa; margin: 0 0 16px 0;">Copy and paste these hardened configuration blocks into your web server or edge proxy to immediately achieve Grade A+.</p>
      ${remediationCards}
    </div>

    <!-- Footer -->
    <div class="footer">
      Generated automatically by <strong>ChimeraGuard v1.3.1</strong> // The Autonomous DevSecOps & Edge Security Arsenal.<br>
      <a href="https://github.com/matheus-oliv-dev/ChimeraGuard" style="color: #38bdf8; text-decoration: none;">GitHub Repository</a> • <a href="https://www.npmjs.com/package/chimeraguard" style="color: #38bdf8; text-decoration: none;">NPM Package</a>
    </div>

  </div>
</body>
</html>`;
}
