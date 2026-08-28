import type { VercelRequest, VercelResponse } from "@vercel/node";
import { KNOWLEDGE_BASE } from "../src/data/knowledge";

export default function handler(req: VercelRequest, res: VercelResponse) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");

  if (req.method !== "GET") {
    res.status(405).json({ error: "Método não permitido. Use GET." });
    return;
  }

  res.status(200).json({
    total: KNOWLEDGE_BASE.length,
    items: KNOWLEDGE_BASE,
  });
}
