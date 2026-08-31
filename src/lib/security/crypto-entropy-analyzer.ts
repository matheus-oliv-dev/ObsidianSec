/**
 * Crypto & Password Hash Strength Analyzer (Inspirado no Hashcat & John the Ripper)
 * Avalia funções de derivação de chaves (KDF), resistência a ataques de força bruta
 * por GPUs/ASICs, e entropia de segredos de autenticação (JWT / HMAC).
 */

export interface HashAlgorithmProfile {
  name: string;
  category: "MODERN_KDF" | "SECURE_HASH" | "LEGACY_VULNERABLE" | "BROKEN";
  gpuCrackingResistance: "VERY_HIGH" | "HIGH" | "LOW" | "ZERO";
  recommendedCost: string;
  nistCompliance: boolean;
  verdict: string;
}

export interface PasswordEntropyResult {
  entropyBits: number;
  charsetSize: number;
  length: number;
  strengthCategory: "VERY_WEAK" | "WEAK" | "FAIR" | "STRONG" | "VERY_STRONG";
  estimatedCrackTimeGpuCluster: string;
  recommendations: string[];
}

export interface JwtSecretAuditResult {
  estimatedBits: number;
  isWeakSecret: boolean;
  knownDictionaryMatch: boolean;
  recommendation: string;
}

export const KNOWN_KDF_PROFILES: Record<string, HashAlgorithmProfile> = {
  argon2id: {
    name: "Argon2id (Winner of Password Hashing Competition)",
    category: "MODERN_KDF",
    gpuCrackingResistance: "VERY_HIGH",
    recommendedCost: "m=65536 (64MB), t=3, p=4",
    nistCompliance: true,
    verdict: "Padrão de ouro de proteção contra ataques com GPUs e circuitos ASIC dedicados.",
  },
  scrypt: {
    name: "scrypt (Memory-Hard Function)",
    category: "MODERN_KDF",
    gpuCrackingResistance: "HIGH",
    recommendedCost: "N=32768, r=8, p=1",
    nistCompliance: true,
    verdict: "Altamente resistente a ataques paralelos devido ao consumo intensivo de RAM.",
  },
  bcrypt: {
    name: "bcrypt (Blowfish Key Derivation)",
    category: "MODERN_KDF",
    gpuCrackingResistance: "HIGH",
    recommendedCost: "Work Factor (Cost) >= 12",
    nistCompliance: true,
    verdict: "Amplo suporte na indústria e forte resistência computacional.",
  },
  pbkdf2: {
    name: "PBKDF2-HMAC-SHA256 / SHA512",
    category: "MODERN_KDF",
    gpuCrackingResistance: "HIGH",
    recommendedCost: ">= 600.000 iterações (OWASP 2025/2026)",
    nistCompliance: true,
    verdict: "Conforme FIPS 140-3 quando usado com contagem adequada de iterações.",
  },
  sha256_pure: {
    name: "SHA-256 Puro (Sem KDF ou sem Salt)",
    category: "LEGACY_VULNERABLE",
    gpuCrackingResistance: "ZERO",
    recommendedCost: "Inadequado para senhas",
    nistCompliance: false,
    verdict: "Vulnerável a ataques de bilhões de tentativas/segundo via Hashcat em GPUs modernas.",
  },
  md5: {
    name: "MD5 (Message Digest 5)",
    category: "BROKEN",
    gpuCrackingResistance: "ZERO",
    recommendedCost: "PROIBIDO",
    nistCompliance: false,
    verdict: "Criptograficamente quebrado. Sujeito a colisões instantâneas e rainbow tables.",
  },
  sha1: {
    name: "SHA-1 (Secure Hash Algorithm 1)",
    category: "BROKEN",
    gpuCrackingResistance: "ZERO",
    recommendedCost: "PROIBIDO",
    nistCompliance: false,
    verdict: "Obsoleto e vulnerável a colisões (ataque SHAttered).",
  },
};

/**
 * Calcula a entropia da senha usando a fórmula de Shannon: E = L * log2(R)
 */
export function calculatePasswordEntropy(password: string): PasswordEntropyResult {
  const len = password.length;
  if (len === 0) {
    return {
      entropyBits: 0,
      charsetSize: 0,
      length: 0,
      strengthCategory: "VERY_WEAK",
      estimatedCrackTimeGpuCluster: "Instantâneo (0s)",
      recommendations: ["Forneça uma senha não vazia."],
    };
  }

  let charset = 0;
  if (/[a-z]/.test(password)) charset += 26;
  if (/[A-Z]/.test(password)) charset += 26;
  if (/[0-9]/.test(password)) charset += 10;
  if (/[^a-zA-Z0-9]/.test(password)) charset += 33;

  const entropyBits = Math.round(len * Math.log2(charset || 1));
  const recommendations: string[] = [];

  let strength: "VERY_WEAK" | "WEAK" | "FAIR" | "STRONG" | "VERY_STRONG" = "VERY_WEAK";
  let crackTime = "Instantâneo (< 1 segundo)";

  if (entropyBits < 36) {
    strength = "VERY_WEAK";
    crackTime = "Menos de 1 segundo";
    recommendations.push("Aumente o comprimento da senha para pelo menos 14 caracteres.");
  } else if (entropyBits < 56) {
    strength = "WEAK";
    crackTime = "Alguns minutos / horas em GPU cluster (RTX 4090)";
    recommendations.push("Adicione caracteres especiais, números e letras maiúsculas.");
  } else if (entropyBits < 72) {
    strength = "FAIR";
    crackTime = "Alguns meses a anos";
    recommendations.push("Considere utilizar uma frase-senha (passphrase) de 4+ palavras aleatórias.");
  } else if (entropyBits < 96) {
    strength = "STRONG";
    crackTime = "Centenas de anos (Resistente a ataques de força bruta)";
  } else {
    strength = "VERY_STRONG";
    crackTime = "Milhões de anos (Segurança criptográfica de nível militar)";
  }

  return {
    entropyBits,
    charsetSize: charset,
    length: len,
    strengthCategory: strength,
    estimatedCrackTimeGpuCluster: crackTime,
    recommendations,
  };
}

/**
 * Auditor de força de segredo para tokens JWT (HMAC-SHA256)
 */
export function auditJwtSecretStrength(secret: string): JwtSecretAuditResult {
  const commonWeakSecrets = new Set([
    "secret",
    "jwtsecret",
    "supersecret",
    "admin",
    "password",
    "123456",
    "change_me",
    "mysecretkey",
    "default_jwt_secret",
  ]);

  const lower = secret.trim().toLowerCase();
  const knownDictionaryMatch = commonWeakSecrets.has(lower);
  const estimatedBits = secret.length * 8; // Aproximação em bytes
  const isWeakSecret = knownDictionaryMatch || estimatedBits < 256;

  let recommendation = "Segredo JWT adequado e seguro (>= 256 bits de entropia).";
  if (knownDictionaryMatch) {
    recommendation = "CRÍTICO: O segredo JWT coincide com dicionários públicos de senhas fracas. Risco iminente de forja de tokens via Hashcat/John.";
  } else if (estimatedBits < 256) {
    recommendation = `Chave curta (${estimatedBits} bits). A RFC 7518 exige no mínimo 256 bits (32 bytes aleatórios) para chaves HS256.`;
  }

  return {
    estimatedBits,
    isWeakSecret,
    knownDictionaryMatch,
    recommendation,
  };
}