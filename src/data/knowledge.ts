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
  {
    id: "cookie-hardening-prefixes",
    title: "Hardening de Cookies & Padrão de Prefixos __Host- / __Secure- (Burp Suite Standard)",
    category: "ApplicationSecurity",
    difficulty: "Intermediário",
    frameworks: {
      nist: "SP 800-63B (Section 7.1 Session Management)",
      owasp: "ASVS V3.4 (Session Management) & W3C Cookie Prefixes",
      mitre: "T1539 (Steal Web Session Cookie)",
    },
    summary:
      "Eliminação de ataques de fixação de sessão e sequestro de cookies através dos prefixos rígidos __Host- e __Secure-, flags HttpOnly, Secure e SameSite=Strict.",
    threatMitigated: "Exfiltração de sessão via XSS, sequestro de requisições cross-site (CSRF) e sobrescrita de cookies a partir de subdomínios vulneráveis.",
    mitigations: [
      "Utilizar o prefixo '__Host-session_id' garantindo que o cookie só seja aceito via HTTPS, sem subdomínios e com path=/.",
      "Definir estritamente 'HttpOnly; Secure; SameSite=Strict'.",
      "Rotacionar o token de sessão imediatamente após qualquer mudança de privilégio ou login.",
    ],
    codeExample: {
      language: "typescript",
      title: "Criação de Cookie com Prefixo __Host- e Flags Máximas",
      code: `export function setSecureSessionCookie(res: Response, token: string) {
  res.setHeader("Set-Cookie", [
    \`__Host-auth_token=\${token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600; Priority=High\`
  ]);
}`,
    },
  },
  {
    id: "cors-zero-trust",
    title: "CORS Zero Trust: Defesa contra Origens Maliciosas & Prevenção de Exfiltração",
    category: "ZeroTrust",
    difficulty: "Intermediário",
    frameworks: {
      nist: "SP 800-207 (Section 3.1 Policy Decision)",
      owasp: "API Security Top 10 API7:2023 (Server-Side Security Misconfiguration)",
      mitre: "T1557 (Adversary-in-the-Middle)",
    },
    summary:
      "Configuração à prova de balas de Cross-Origin Resource Sharing, bloqueando wildcard (*) associado a credenciais, reflexão cega de cabeçalho Origin e origem 'null'.",
    threatMitigated: "Roubo de dados autenticados por sites de terceiros e envenenamento de cache de API (Cache Poisoning).",
    mitigations: [
      "Nunca combinar 'Access-Control-Allow-Origin: *' com 'Access-Control-Allow-Credentials: true'.",
      "Validar origens contra uma allowlist estrita e incluir sempre o cabeçalho 'Vary: Origin'.",
      "Rejeitar 'Origin: null' para impedir explorações via iframes sandboxed.",
    ],
    codeExample: {
      language: "typescript",
      title: "Middleware CORS Seguro com Allowlist Rigorosa e Vary Origin",
      code: `const ALLOWED_ORIGINS = new Set(["https://app.obsidiansec.dev", "https://admin.obsidiansec.dev"]);

export function corsGuard(req: Request, res: Response): boolean {
  const origin = req.headers.get("origin");
  if (!origin) return true; // Requisições same-origin

  if (ALLOWED_ORIGINS.has(origin)) {
    res.headers.set("Access-Control-Allow-Origin", origin);
    res.headers.set("Access-Control-Allow-Credentials", "true");
    res.headers.set("Vary", "Origin");
    return true;
  }
  return false; // Bloqueia origens não auditadas
}`,
    },
  },
  {
    id: "kdf-password-argon2id",
    title: "Derivação de Chaves e Hashing Moderno com Argon2id (Anti-GPU / Hashcat)",
    category: "Cryptography",
    difficulty: "Avançado",
    frameworks: {
      nist: "SP 800-63B (Section 5.1.1.2 Memorized Secret Verifiers)",
      owasp: "Password Storage Cheat Sheet (Argon2id Recommendation)",
    },
    summary:
      "Implementação do algoritmo Argon2id (Memory-Hard) para hashing de credenciais, neutralizando ataques massivos de quebra por clusters de GPU e chips ASIC.",
    threatMitigated: "Quebra offline de bancos de dados vazados via dicionários e força bruta de alta velocidade (Hashcat/John the Ripper).",
    mitigations: [
      "Configurar custo de memória mínimo de 64MB (m=65536) e 3 iterações (t=3).",
      "Abandonar completamente MD5, SHA-1 e SHA-256 sem KDF para armazenamento de senhas.",
      "Adicionar 'Pepper' criptográfico server-side armazenado em HSM / KMS seguro.",
    ],
    codeExample: {
      language: "typescript",
      title: "Parâmetros Recomendados para Hashing com Argon2id",
      code: `export const ARGON2ID_SECURITY_PROFILE = {
  memoryCost: 65536, // 64 MB de RAM
  timeCost: 3,       // 3 iterações
  parallelism: 4,    // 4 threads concorrentes
  hashLength: 32,    // 256 bits de saída
};`,
    },
  },
  {
    id: "bloodhound-attack-graph",
    title: "Mapeamento de Grafo de Ataque & Redução do Raio de Explosão (Blast Radius)",
    category: "DevSecOps",
    difficulty: "Especialista",
    frameworks: {
      nist: "SP 800-53 (AC-6 Least Privilege)",
      mitre: "Enterprise ATT&CK Matrix (Lateral Movement & Privilege Escalation)",
      cis: "CIS Control 5 (Account Management)",
    },
    summary:
      "Aplicação de Teoria dos Grafos para identificar o menor caminho entre uma brecha inicial (ex: XSS ou SSRF) e a tomada de controle total da infraestrutura, eliminando elos fracos.",
    threatMitigated: "Movimentação lateral de atacantes e escalada de privilégios de contas de serviço até permissões de Super Admin.",
    mitigations: [
      "Mapear todos os relacionamentos de confiança entre microsserviços e bancos de dados.",
      "Segregar privilégios através de tokens efêmeros com escopo mínimo (Princípio do Menor Privilégio).",
      "Impor autenticação mTLS e Zero Trust entre pods e serviços internos.",
    ],
    codeExample: {
      language: "typescript",
      title: "Validador de Escopo de Token para Confinamento de Raio de Explosão",
      code: `export function enforceStrictScope(tokenScopes: string[], requiredScope: string): void {
  if (!tokenScopes.includes(requiredScope)) {
    throw new Error(\`[SecurityViolation]: Escopo insuficiente. Raio de explosão contido para '\${requiredScope}'.\`);
  }
}`,
    },
  },
];

