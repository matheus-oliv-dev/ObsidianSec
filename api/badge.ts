import type { VercelRequest, VercelResponse } from "../src/types/index.ts";

export const config = {
  maxDuration: 10,
};

function generateSvgBadge(label: string, value: string, colorHex: string): string {
  const labelWidth = Math.max(80, label.length * 7.5 + 20);
  const valueWidth = Math.max(50, value.length * 8 + 20);
  const totalWidth = labelWidth + valueWidth;

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="24" viewBox="0 0 ${totalWidth} 24" role="img" aria-label="${label}: ${value}">
  <title>${label}: ${value}</title>
  <clipPath id="r">
    <rect width="${totalWidth}" height="24" rx="0" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="${labelWidth}" height="24" fill="#000000" stroke="#333333" stroke-width="1"/>
    <rect x="${labelWidth}" width="${valueWidth}" height="24" fill="${colorHex}" stroke="#222222" stroke-width="1"/>
  </g>
  <g fill="#ffffff" text-anchor="middle" font-family="'JetBrains Mono', 'Chakra Petch', 'Segoe UI', monospace" font-size="11" font-weight="700">
    <text x="${labelWidth / 2}" y="16" fill="#e5e5e5" letter-spacing="0.5">${label}</text>
    <text x="${labelWidth + valueWidth / 2}" y="16" fill="#000000" font-weight="900" letter-spacing="0.5">${value}</text>
  </g>
</svg>`;
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  res.setHeader("Content-Type", "image/svg+xml; charset=utf-8");
  res.setHeader("Cache-Control", "public, s-maxage=300, stale-while-revalidate=600");
  res.setHeader("X-Content-Type-Options", "nosniff");

  const query = req.query || {};
  let gradeParam = String(query.grade || "").toUpperCase();
  let scoreParam = String(query.score || "");
  const urlParam = String(query.url || "").trim();

  // Se o usuário passou url diretamente na query e não passou grade fixa
  if (urlParam && !gradeParam) {
    let target = urlParam;
    if (!target.startsWith("http://") && !target.startsWith("https://")) {
      target = `https://${target}`;
    }

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 4000);
      const probeRes = await fetch(target, {
        method: "GET",
        signal: controller.signal,
        headers: { "User-Agent": "ObsidianSec-Badge-Bot/1.0" },
      });
      clearTimeout(timeout);

      const h = probeRes.headers;
      const csp = !!(h.get("content-security-policy") || h.get("content-security-policy-report-only"));
      const xfo = !!h.get("x-frame-options");
      const nosniff = !!h.get("x-content-type-options");
      const perm = !!h.get("permissions-policy");
      const hsts = !!h.get("strict-transport-security");

      let calcScore = 0;
      if (csp) calcScore += 30;
      if (xfo) calcScore += 20;
      if (hsts) calcScore += 20;
      if (nosniff) calcScore += 15;
      if (perm) calcScore += 15;

      scoreParam = String(calcScore);
      if (calcScore >= 85) gradeParam = "A+";
      else if (calcScore >= 70) gradeParam = "A";
      else if (calcScore >= 50) gradeParam = "B";
      else if (calcScore >= 30) gradeParam = "C";
      else gradeParam = "F";
    } catch {
      gradeParam = "ERR";
      scoreParam = "0";
    }
  }

  if (!gradeParam) gradeParam = "A+";
  const displayScore = scoreParam ? `GRADE ${gradeParam} (${scoreParam}/100)` : `GRADE ${gradeParam}`;

  let colorHex = "#10b981"; // Verde neon padrão
  if (gradeParam === "A+" || gradeParam === "A") colorHex = "#10b981";
  else if (gradeParam === "B") colorHex = "#eab308";
  else if (gradeParam === "C") colorHex = "#f97316";
  else if (gradeParam === "ERR") colorHex = "#737373";
  else colorHex = "#ef4444";

  const svg = generateSvgBadge("OBSIDIANSEC", displayScore, colorHex);
  res.status(200).send(svg);
}