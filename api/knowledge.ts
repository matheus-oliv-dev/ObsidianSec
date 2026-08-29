import type { VercelRequest, VercelResponse } from "../src/types/index.ts";

export const KNOWLEDGE_BASE = [
  {
    id: "nist-zero-trust-architecture",
    title: "NIST SP 800-207: Arquitetura Zero Trust em Ambientes Web e Cloud",
    category: "ZeroTrust",
    difficulty: "Intermediário",
    frameworks: {
      nist: "NIST SP 800-207",
      mitre: "M1030 (Network Segmentation) & M1035 (Execution Prevention)",
      cis: "CIS Control 6 (Access Control Management)",
    },
    summary:
      "A premissa fundamental do Zero Trust é 'nunca confiar, sempre verificar'. Em aplicações web e APIs modernas, isso exige autenticação contínua, micro-segmentação de serviços e validação estrita de identidade em cada requisição.",
    threatMitigated: "Movimentação lateral de invasores pós-comprometimento, roubo de tokens de longa duração e elevação não autorizada de privilégios.",
    mitigations: [
      "Implementar mTLS (Mutual TLS) entre todos os microserviços e pods.",
      "Adotar tokens de acesso de curta duração (máximo 5-15 minutos) com rotação criptográfica via DPoP (RFC 9449).",
      "Segmentar APIs e bancos de dados através de políticas de rede rígidas (Kubernetes NetworkPolicies / AWS Security Groups).",
    ],
    codeExample: {
      language: "typescript",
      title: "Middleware Zero Trust com Validação Contínua de Contexto",
      code: `export async function zeroTrustContextGuard(req: Request): Promise<boolean> {
  const clientCert = req.headers.get("x-client-cert");
  const deviceFingerprint = req.headers.get("x-device-fingerprint");
  const token = req.headers.get("authorization");

  if (!token || !deviceFingerprint || !clientCert) return false;
  return true;
}`,
    },
  },
  {
    id: "post-quantum-cryptography",
    title: "Criptografia Pós-Quântica (PQC): FIPS 203 ML-KEM & Troca de Chaves Híbrida",
    category: "Cryptography",
    difficulty: "Avançado",
    frameworks: {
      nist: "NIST FIPS 203 (ML-KEM / Kyber) & FIPS 204 (ML-DSA)",
      owasp: "ASVS V6 (Cryptography)",
    },
    summary:
      "Preparação de sistemas contra a ameaça 'Harvest Now, Decrypt Later' (HNDL), onde invasores interceptam tráfego criptografado hoje para decifrá-lo no futuro com computadores quânticos.",
    threatMitigated: "Decifração retroativa de comunicações confidenciais e quebra de algoritmos assimétricos clássicos (RSA, ECDH, ECDSA).",
    mitigations: [
      "Habilitar suporte a curvas híbridas X25519Kyber768 (ML-KEM-768) no TLS 1.3 em proxies de borda.",
      "Planejar inventário de criptografia e inventário de algoritmos (Cryptographic Bill of Materials - CBOM).",
    ],
    codeExample: {
      language: "nginx",
      title: "Configuração TLS 1.3 Pós-Quântico no Nginx / Cloudflare",
      code: `ssl_protocols TLSv1.3;
ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
ssl_ecdh_curve X25519Kyber768Draft00:X25519:secp256r1;
ssl_prefer_server_ciphers on;`,
    },
  },
  {
    id: "supply-chain-slsa-sbom",
    title: "Segurança de Cadeia de Suprimentos: Níveis SLSA & Validação de SBOM (CycloneDX)",
    category: "DevSecOps",
    difficulty: "Avançado",
    frameworks: {
      nist: "NIST SP 800-161r1 (Cybersecurity Supply Chain Risk Management)",
      owasp: "OWASP CycloneDX & Software Component Verification Standard (SCVS)",
    },
    summary:
      "Mitigação de ataques em dependências de terceiros, pacotes comprometidos, typosquatting e contaminação de pipelines CI/CD.",
    threatMitigated: "Injeção de backdoors em bibliotecas npm/PyPI, dependency confusion e comprometimento de artefatos de build.",
    mitigations: [
      "Gerar SBOM automatizado em formato CycloneDX a cada release.",
      "Assinar artefatos criptograficamente com Sigstore / Cosign no GitHub Actions.",
    ],
    codeExample: {
      language: "yaml",
      title: "Pipeline GitHub Actions com Geração de SBOM e Cosign",
      code: `name: Supply Chain Defense
on: [push]
jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Generate CycloneDX SBOM
        run: npx @cyclonedx/cyclonedx-npm --output-file sbom.json`,
    },
  },
  {
    id: "container-hardening-cis",
    title: "Hardening de Contêineres & Cloud-Native: CIS Benchmark, Seccomp & Rootless",
    category: "CloudNative",
    difficulty: "Intermediário",
    frameworks: {
      cis: "CIS Docker Benchmark v1.6.0 & CIS Kubernetes Benchmark v1.9.0",
      mitre: "M1047 (Container Sandboxing)",
    },
    summary:
      "Redução drástica da superfície de ataque em contêineres Docker e pods Kubernetes através do princípio de privilégio mínimo e isolamento de syscalls do Linux.",
    threatMitigated: "Container Escape (fuga de contêiner para o host), execução de código com privilégios de root e exploração de vulnerabilidades no Kernel.",
    mitigations: [
      "Nunca executar processos como root (UID 0) dentro de contêineres.",
      "Remover todas as Linux Capabilities padrão (CAP_DROP ALL).",
      "Definir o sistema de arquivos raiz como Somente Leitura (readOnlyRootFilesystem: true).",
    ],
    codeExample: {
      language: "yaml",
      title: "SecurityContext Blindado para Kubernetes / Docker Compose",
      code: `securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: ["ALL"]
  seccompProfile:
    type: RuntimeDefault`,
    },
  },
  {
    id: "browser-trusted-types-csp3",
    title: "Browser Hardening: CSP Level 3 Strict-Dynamic & W3C Trusted Types",
    category: "ApplicationSecurity",
    difficulty: "Avançado",
    frameworks: {
      owasp: "ASVS V14.4 (HTTP Headers)",
      mitre: "D3-EPH (Execution Prevention in Host)",
    },
    summary:
      "Eliminação de DOM XSS através de políticas de tipos confiáveis (Trusted Types) e CSP com nonces criptográficos e 'strict-dynamic'.",
    threatMitigated: "Execução de scripts maliciosos em DOM Sinks perigosos (innerHTML, eval, document.write).",
    mitigations: [
      "Configurar require-trusted-types-for 'script' no Content-Security-Policy.",
      "Implementar política TrustedHTML com sanitizador DOMPurify.",
    ],
    codeExample: {
      language: "typescript",
      title: "Criação de Política W3C Trusted Types",
      code: `if (window.trustedTypes && window.trustedTypes.createPolicy) {
  window.trustedTypes.createPolicy("bomberPolicy", {
    createHTML: (string) => DOMPurify.sanitize(string),
  });
}`,
    },
  },
  {
    id: "lgpd-privacy-by-design",
    title: "LGPD (Lei nº 13.709/2018) & Privacy by Design: Proteção de Dados em Aplicações Web",
    category: "Governance",
    difficulty: "Iniciante",
    frameworks: {
      nist: "NIST Privacy Framework v1.0",
      owasp: "ASVS V8 (Data Protection) & OWASP Top 10 Privacy Risks",
      cis: "CIS Control 3 (Data Protection)",
    },
    summary:
      "Diretrizes práticas para arquitetar sistemas em conformidade com a LGPD: minimização de coleta (Art. 6º, III), anonimização/pseudonimização (Art. 13), criptografia de dados em repouso e trânsito (Art. 46) e logs auditáveis sem vazamento de PII.",
    threatMitigated: "Vazamento de dados pessoais (PII), infrações administrativas perante a ANPD e multas de até 2% do faturamento.",
    mitigations: [
      "Aplicar o princípio de minimização: coletar estritamente os campos essenciais para a regra de negócio.",
      "Criptografar campos sensíveis com AES-256-GCM antes de persistir no banco.",
      "Anonimizar dados de analytics e remover IPs ou identificadores pessoais de logs de erro.",
    ],
    codeExample: {
      language: "typescript",
      title: "Função de Mascaramento e Anonimização de PII para Logs (LGPD)",
      code: `export function maskPiiForLogging(email: string, cpf?: string): { maskedEmail: string; maskedCpf?: string } {
  const [user, domain] = email.split("@");
  const maskedEmail = user.length > 2 
    ? \`\${user.slice(0, 2)}***@\${domain}\` 
    : \`*@\${domain}\`;

  const maskedCpf = cpf ? cpf.replace(/^(\\d{3})\\.(\\d{3})\\.(\\d{3})-(\\d{2})$/, "$1.***.***-$4") : undefined;

  return { maskedEmail, maskedCpf };
}`,
    },
  },
];

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
