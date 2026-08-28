export interface KnowledgeItem {
  id: string;
  title: string;
  category: "ZeroTrust" | "Cryptography" | "DevSecOps" | "ApplicationSecurity" | "CloudNative" | "Governance";
  difficulty: "Iniciante" | "Intermediário" | "Avançado" | "Especialista";
  frameworks: {
    nist?: string;
    owasp?: string;
    mitre?: string;
    cis?: string;
  };
  summary: string;
  threatMitigated: string;
  mitigations: string[];
  codeExample: {
    language: string;
    title: string;
    code: string;
  };
}

export const KNOWLEDGE_BASE: KnowledgeItem[] = [
  {
    id: "pqc-mlkem-hybrid",
    title: "Criptografia Pós-Quântica (PQC): Troca de Chaves Híbridas em TLS 1.3",
    category: "Cryptography",
    difficulty: "Avançado",
    frameworks: {
      nist: "FIPS 203 (ML-KEM / Kyber)",
      owasp: "ASVS V6.2 (Algoritmos Criptográficos)",
      mitre: "D3-ECA (Encrypted Channel Authorization)",
    },
    summary:
      "Proteção contra ataques 'Harvest Now, Decrypt Later' (HNDL) combinando a criptografia clássica de curvas elípticas (X25519) com reticulados pós-quânticos (ML-KEM-768).",
    threatMitigated: "Quebra futura de certificados TLS e tráfego interceptado por computadores quânticos de grande escala.",
    mitigations: [
      "Adotar handshake híbrido X25519MLKEM768 no TLS 1.3.",
      "Planejar agilidade criptográfica para substituição de algoritmos sem refatorar regras de negócio.",
      "Garantir que proxies e WAFs suportem ClientHello com pacotes expandidos (~1.2KB adicionais).",
    ],
    codeExample: {
      language: "nginx",
      title: "Configuração NGINX / Cloudflare com Suporte a Cifras Híbridas PQC",
      code: `ssl_protocols TLSv1.3;
# Habilita curvas híbridas pós-quânticas ML-KEM + X25519
ssl_ecdh_curve X25519MLKEM768:X25519:secp384r1;
ssl_prefer_server_ciphers on;`,
    },
  },
  {
    id: "zero-trust-sp800-207",
    title: "Arquitetura Zero Trust (NIST SP 800-207): Never Trust, Always Verify",
    category: "ZeroTrust",
    difficulty: "Intermediário",
    frameworks: {
      nist: "NIST SP 800-207",
      cis: "CIS Control 6 (Gestão de Controle de Acesso)",
    },
    summary:
      "A rede interna não confere confiança implícita. Toda requisição deve ser autenticada, autorizada e criptografada com base na identidade e no contexto de risco da sessão.",
    threatMitigated: "Movimentação lateral de invasores dentro da rede interna e vazamento de dados por credenciais roubadas.",
    mitigations: [
      "Separar Policy Enforcement Point (PEP) de Policy Decision Point (PDP).",
      "Emitir tokens de curta duração vinculados ao contexto e checados dinamicamente.",
      "Exigir mTLS (Mutual TLS) entre todos os microsserviços.",
    ],
    codeExample: {
      language: "typescript",
      title: "Validação Zero-Trust de Requisição com Contexto Dinâmico",
      code: `export async function evaluateZeroTrustAccess(req: Request, user: UserSession): Promise<boolean> {
  const isMfaActive = user.mfaVerifiedAt && (Date.now() - user.mfaVerifiedAt < 3600000);
  const isHealthyDevice = req.headers.get("x-device-integrity") === "VERIFIED";
  
  // Rejeita acesso se não houver MFA recente ou dispositivo íntegro
  return Boolean(isMfaActive && isHealthyDevice && user.role === "ADMIN");
}`,
    },
  },
  {
    id: "supply-chain-slsa-sbom",
    title: "Segurança na Cadeia de Suprimentos: SLSA v1.0 & CycloneDX SBOM",
    category: "DevSecOps",
    difficulty: "Intermediário",
    frameworks: {
      owasp: "CycloneDX v1.6 SBOM",
      nist: "NIST CSF 2.0 (GV.SC - Supply Chain)",
    },
    summary:
      "Geração automatizada de Lista de Materiais de Software (SBOM) e assinatura criptográfica de artefatos de build com Sigstore/Cosign (Keyless Signing).",
    threatMitigated: "Ataques de Dependency Confusion, Typosquatting, injeção de código em builds e adulteração de pacotes.",
    mitigations: [
      "Gerar SBOM CycloneDX a cada build e auditar contra bases de CVEs.",
      "Assinar contêineres e imagens com Cosign no pipeline CI/CD.",
      "Bloquear pacotes sem namespace (@escopo/pacote) e congelar lockfiles com hash sha512.",
    ],
    codeExample: {
      language: "yaml",
      title: "Workflow GitHub Actions para Geração de SBOM e Assinatura Cosign",
      code: `- name: Gerar SBOM CycloneDX
  run: npx @cyclonedx/cyclonedx-npm --output-file bom.json

- name: Assinar Imagem de Contêiner com Cosign (Keyless OIDC)
  uses: sigstore/cosign-installer@v3
  run: cosign sign --yes ghcr.io/empresa/app@\${{ steps.build.outputs.digest }}`,
    },
  },
  {
    id: "container-hardening-cis",
    title: "Hardening de Contêineres & Kubernetes: CIS Benchmarks & Rootless",
    category: "CloudNative",
    difficulty: "Avançado",
    frameworks: {
      cis: "CIS Docker & Kubernetes Benchmark",
      mitre: "D3-SPP (System Process Permissions)",
    },
    summary:
      "Execução de contêineres sem privilégios de root, com sistema de arquivos somente leitura, descarte de Linux Capabilities (CAP_DROP ALL) e perfis Seccomp.",
    threatMitigated: "Fuga de contêiner (Container Escape) e sequestro do kernel do nó host.",
    mitigations: [
      "Descartar todas as Linux capabilities (drop: [ALL]).",
      "Definir readOnlyRootFilesystem: true e runAsNonRoot: true.",
      "Habilitar perfil Seccomp RuntimeDefault no Kubernetes.",
    ],
    codeExample: {
      language: "yaml",
      title: "SecurityContext Seguro em Manifesto Kubernetes",
      code: `securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  runAsUser: 10001
  capabilities:
    drop:
      - ALL
  seccompProfile:
    type: RuntimeDefault`,
    },
  },
  {
    id: "asvs-input-validation",
    title: "OWASP ASVS v4.0.3: Validação Estrita por Schema Zod & Allowlist",
    category: "ApplicationSecurity",
    difficulty: "Iniciante",
    frameworks: {
      owasp: "ASVS V5.1 (Input Validation)",
      mitre: "D3-IE (Input Encoding & Sanitization)",
    },
    summary:
      "Toda entrada de dados do usuário deve ser validada por tipagem rígida, limites de tamanho e filtros de caracteres antes do processamento ou inserção em bancos de dados.",
    threatMitigated: "Injeção SQL, NoSQL Injection, XSS, Overflow de memória e corrupção de estado.",
    mitigations: [
      "Usar validação estruturada com Zod ou JSON Schema no ponto de entrada.",
      "Nunca concatenar dados do usuário em consultas SQL ou comandos do sistema operacional.",
      "Limitar comprimento de strings e valores numéricos mínimos/máximos.",
    ],
    codeExample: {
      language: "typescript",
      title: "Schema de Validação Defensiva com Zod",
      code: `import { z } from "zod";

export const UserRegistrationSchema = z.object({
  username: z.string().min(3).max(30).regex(/^[a-zA-Z0-9_]+$/),
  email: z.string().email().max(254),
  age: z.number().int().min(18).max(120),
});`,
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
      "Usar nonces criptográficos gerados a cada requisição em substituição a 'unsafe-inline'.",
    ],
    codeExample: {
      language: "typescript",
      title: "Criação de Política W3C Trusted Types",
      code: `if (window.trustedTypes && window.trustedTypes.createPolicy) {
  window.trustedTypes.createPolicy("bomberPolicy", {
    createHTML: (string) => DOMPurify.sanitize(string),
    createScriptURL: (url) => {
      if (!url.startsWith("https://cdn.meusite.com/")) throw new Error("Origem não autorizada");
      return url;
    }
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
      "Criptografar campos sensíveis (CPF, senhas, dados de pagamento) com AES-256-GCM antes de persistir no banco.",
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
