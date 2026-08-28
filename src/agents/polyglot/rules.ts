export type TargetLanguage =
  | "typescript"
  | "javascript"
  | "python"
  | "php"
  | "java"
  | "csharp"
  | "go"
  | "ruby"
  | "sql"
  | "unknown";

export type TargetFramework =
  | "nextjs"
  | "react"
  | "express"
  | "django"
  | "fastapi"
  | "flask"
  | "laravel"
  | "wordpress"
  | "springboot"
  | "aspnet"
  | "gin"
  | "rails"
  | "static"
  | "unknown";

export interface PolyglotSecurityRule {
  id: string;
  language: TargetLanguage;
  name: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  cwe: string;
  owasp: string;
  regex: RegExp;
  description: string;
  remediation: string;
}

export const POLYGLOT_SECURITY_RULES: PolyglotSecurityRule[] = [
  // ==========================================
  // PYTHON (Django, FastAPI, Flask, scripts)
  // ==========================================
  {
    id: "PY-01",
    language: "python",
    name: "Injeção SQL via f-strings ou formatação de strings",
    severity: "CRITICAL",
    cwe: "CWE-89 - SQL Injection",
    owasp: "A03:2021 - Injection",
    regex: /(?:execute|raw|cursor\.execute)\s*\(\s*(?:f["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)|["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*%\s*\(|["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*\.format\()/i,
    description: "Montagem de consulta SQL via concatenação ou f-string no Python permite injeção SQL direta.",
    remediation: "Utilize queries parametrizadas: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,)) ou ORM (SQLAlchemy/Django ORM).",
  },
  {
    id: "PY-02",
    language: "python",
    name: "Desserialização insegura com pickle / marshal",
    severity: "CRITICAL",
    cwe: "CWE-502 - Deserialization of Untrusted Data",
    owasp: "A08:2021 - Software and Data Integrity Failures",
    regex: /\b(?:pickle|_pickle|cPickle|marshal)\.(?:loads?|Unpickler)\s*\(/,
    description: "Carregar dados serializados com pickle de fontes não confiáveis permite Execução Remota de Código (RCE).",
    remediation: "Substitua pickle por formatos seguros de troca de dados como JSON, MsgPack ou Protocol Buffers.",
  },
  {
    id: "PY-03",
    language: "python",
    name: "Execução de comandos com shell=True no subprocess",
    severity: "HIGH",
    cwe: "CWE-78 - OS Command Injection",
    owasp: "A03:2021 - Injection",
    regex: /subprocess\.(?:Popen|call|run|check_output)\s*\([^)]*shell\s*=\s*True/i,
    description: "O uso de shell=True no módulo subprocess pode permitir injeção de comandos do sistema operacional.",
    remediation: "Passe argumentos como lista (ex: ['ls', '-l']) e defina shell=False.",
  },
  {
    id: "PY-04",
    language: "python",
    name: "Modo Debug ativado em produção (Flask / Django / FastAPI)",
    severity: "HIGH",
    cwe: "CWE-489 - Active Debug Code",
    owasp: "A05:2021 - Security Misconfiguration",
    regex: /(?:DEBUG\s*=\s*True|app\.run\s*\([^)]*debug\s*=\s*True)/,
    description: "DEBUG=True em produção expõe stack traces detalhados e console interativo com execução de código.",
    remediation: "Defina DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'.",
  },

  // ==========================================
  // PHP (Laravel, WordPress, Vanilla PHP)
  // ==========================================
  {
    id: "PHP-01",
    language: "php",
    name: "Injeção SQL via concatenação direta em mysqli / PDO",
    severity: "CRITICAL",
    cwe: "CWE-89 - SQL Injection",
    owasp: "A03:2021 - Injection",
    regex: /(?:mysqli_query|\$pdo->query|\$db->query)\s*\([^)]*\$(?:_GET|_POST|_REQUEST|id|input|email)/i,
    description: "Variáveis de entrada do usuário concatenadas diretamente em queries SQL sem Prepared Statements.",
    remediation: "Utilize PDO com Prepared Statements: $stmt = $pdo->prepare('SELECT * FROM users WHERE email = :e'); $stmt->execute(['e' => $email]);",
  },
  {
    id: "PHP-02",
    language: "php",
    name: "Desserialização insegura via unserialize()",
    severity: "CRITICAL",
    cwe: "CWE-502 - Deserialization of Untrusted Data",
    owasp: "A08:2021 - Software and Data Integrity Failures",
    regex: /\bunserialize\s*\(\s*\$(?:_GET|_POST|_COOKIE|_REQUEST|input)/,
    description: "unserialize() em dados de requisições de clientes pode disparar cadeias POP de execução de código (RCE).",
    remediation: "Substitua por json_decode($json, true) com JSON estruturado.",
  },
  {
    id: "PHP-03",
    language: "php",
    name: "Inclusão dinâmica de arquivos / LFI (Local File Inclusion)",
    severity: "HIGH",
    cwe: "CWE-98 - Improper Control of Filename for Include/Require",
    owasp: "A01:2021 - Broken Access Control",
    regex: /\b(?:include|require|include_once|require_once)\s*\(?\s*\$(?:_GET|_POST|_REQUEST)/,
    description: "Incluir caminhos baseados em parâmetros do usuário permite Local/Remote File Inclusion (LFI/RFI).",
    remediation: "Use uma lista branca (whitelist) restrita de arquivos autorizados para inclusão.",
  },
  {
    id: "PHP-04",
    language: "php",
    name: "Execução dinâmica perigosa com eval / assert / preg_replace /e",
    severity: "CRITICAL",
    cwe: "CWE-95 - Improper Neutralization of Directives in Dynamically Evaluated Code",
    owasp: "A03:2021 - Injection",
    regex: /\b(?:eval|assert)\s*\(\s*\$(?:_GET|_POST|_REQUEST)|preg_replace\s*\(\s*['"][^'"]*\/e['"]/i,
    description: "Avaliação dinâmica de código a partir de dados externos.",
    remediation: "Evite totalmente o uso de avaliação dinâmica com eval e flags depreciadas como /e em expressões regulares.",
  },

  // ==========================================
  // JAVA (Spring Boot, Jakarta EE, Quarkus)
  // ==========================================
  {
    id: "JAVA-01",
    language: "java",
    name: "Injeção SQL via concatenação em JDBC / JPA / Hibernate",
    severity: "CRITICAL",
    cwe: "CWE-89 - SQL Injection",
    owasp: "A03:2021 - Injection",
    regex: /(?:createQuery|createNativeQuery|executeQuery)\s*\(\s*["'].*?["']\s*\+\s*[a-zA-Z0-9_]+/i,
    description: "Concatenação direta de variáveis em queries HQL/JPQL ou JDBC.",
    remediation: "Utilize parâmetros nomeados ou posicionais: em.createQuery('SELECT u FROM User u WHERE u.email = :email').setParameter('email', email);",
  },
  {
    id: "JAVA-02",
    language: "java",
    name: "Desserialização insegura com ObjectInputStream / XMLDecoder",
    severity: "CRITICAL",
    cwe: "CWE-502 - Deserialization of Untrusted Data",
    owasp: "A08:2021 - Software and Data Integrity Failures",
    regex: /new\s+(?:ObjectInputStream|XMLDecoder)\s*\(/,
    description: "Desserialização de dados Java nativos de fluxos de rede sem validação de filtros de classe (JEP 290).",
    remediation: "Utilize formatos seguros (JSON via Jackson com defaultTyping desativado) ou configure ObjectInputFilter estrito.",
  },
  {
    id: "JAVA-03",
    language: "java",
    name: "Injeção de Expressão SpEL (Spring Expression Language)",
    severity: "HIGH",
    cwe: "CWE-917 - Expression Language Injection",
    owasp: "A03:2021 - Injection",
    regex: /new\s+SpelExpressionParser\s*\(\)\.parseExpression\s*\(\s*(?!["'][^"']*["']\s*\))/i,
    description: "Interpretação de SpEL baseada em entrada de usuário permite execução remota de código.",
    remediation: "Utilize SimpleEvaluationContext em vez de StandardEvaluationContext e restrinja permissões de resolução de tipos.",
  },

  // ==========================================
  // C# / .NET (ASP.NET Core, Blazor, Web API)
  // ==========================================
  {
    id: "CS-01",
    language: "csharp",
    name: "Injeção SQL via SqlCommand ou FromSqlRaw sem parâmetros",
    severity: "CRITICAL",
    cwe: "CWE-89 - SQL Injection",
    owasp: "A03:2021 - Injection",
    regex: /(?:FromSqlRaw|ExecuteSqlRaw|SqlCommand)\s*\(\s*(?:\$["'].*?\{|["'].*?["']\s*\+\s*[a-zA-Z0-9_]+)/i,
    description: "Interpolação de strings em FromSqlRaw ou SqlCommand no Entity Framework / ADO.NET.",
    remediation: "Utilize FromSqlInterpolated ou adicione parâmetros com SqlParameter.",
  },
  {
    id: "CS-02",
    language: "csharp",
    name: "Desserialização perigosa com BinaryFormatter / NetDataContractSerializer",
    severity: "CRITICAL",
    cwe: "CWE-502 - Deserialization of Untrusted Data",
    owasp: "A08:2021 - Software and Data Integrity Failures",
    regex: /new\s+(?:BinaryFormatter|NetDataContractSerializer|SoapFormatter)\s*\(\)/,
    description: "BinaryFormatter é inerentemente inseguro no ecossistema .NET e não deve ser usado.",
    remediation: "Substitua por System.Text.Json ou formatos estruturados seguros.",
  },

  // ==========================================
  // GO (Golang / Gin / Fiber / Echo / Net/HTTP)
  // ==========================================
  {
    id: "GO-01",
    language: "go",
    name: "Injeção SQL via fmt.Sprintf em database/sql ou GORM",
    severity: "CRITICAL",
    cwe: "CWE-89 - SQL Injection",
    owasp: "A03:2021 - Injection",
    regex: /(?:db\.Query|db\.Exec|db\.Raw)\s*\(\s*fmt\.Sprintf\s*\(\s*["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)/i,
    description: "Montagem de consulta SQL via fmt.Sprintf permite injeção SQL no Go.",
    remediation: "Passe argumentos como parâmetros posicionais: db.Query('SELECT * FROM users WHERE id = ?', userId).",
  },
  {
    id: "GO-02",
    language: "go",
    name: "Servidor HTTP sem timeouts de leitura/escrita configurados (DoS)",
    severity: "MEDIUM",
    cwe: "CWE-400 - Uncontrolled Resource Consumption",
    owasp: "A04:2021 - Insecure Design",
    regex: /http\.ListenAndServe\s*\(/,
    description: "http.ListenAndServe padrão não define ReadTimeout ou WriteTimeout, deixando o servidor suscetível a ataques Slowloris.",
    remediation: "Instancie um &http.Server{ ReadHeaderTimeout: 5*time.Second, ReadTimeout: 10*time.Second, WriteTimeout: 10*time.Second }.",
  },

  // ==========================================
  // JAVASCRIPT / TYPESCRIPT / NODE.JS
  // ==========================================
  {
    id: "JS-01",
    language: "javascript",
    name: "Injeção de Código em DOM Sink (innerHTML / outerHTML)",
    severity: "HIGH",
    cwe: "CWE-79 - Cross-site Scripting",
    owasp: "A03:2021 - Injection",
    regex: /\b(?:innerHTML|outerHTML)\s*=\s*(?!["'`]\s*["'`])(?!\s*(?:escapeHtml|sanitizeInput|DOMPurify\.sanitize))/,
    description: "Atribuição direta a innerHTML sem sanitização pode permitir execução de DOM XSS.",
    remediation: "Utilize textContent ou sanitizeInput() / Trusted Types API.",
  },
  {
    id: "JS-02",
    language: "javascript",
    name: "Algoritmo JWT inseguro ('alg: none')",
    severity: "CRITICAL",
    cwe: "CWE-347 - Improper Verification of Cryptographic Signature",
    owasp: "A02:2021 - Cryptographic Failures",
    regex: /['"]alg['"]\s*:\s*['"]none['"]/i,
    description: "Algoritmo 'none' permite bypass de autenticação por tokens sem assinatura.",
    remediation: "Exija algoritmos criptográficos fortes como HS256 ou RS256.",
  },
];
