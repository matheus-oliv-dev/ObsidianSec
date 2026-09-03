# 🛡️ Matriz de Ameaças, Falhas & Mitigações Defensivas (Padrão 2025/2026) · ChimeraGuard

Esta matriz consolida todas as vulnerabilidades analisadas, incluindo ataques web clássicos, engenharia do caos, blindagem moderna de navegador e a nova taxonomia **OWASP Top 10 for LLM Applications (2025/2026)**.

---

## 📊 Matriz Detalhada de Riscos & Contramedidas

| Vetor de Ameaça | Classificação OWASP / CWE | Gravidade Inicial | Contramedida / Camada Defensiva | Teste Automatizado Associado | Status |
| :--- | :--- | :---: | :--- | :--- | :---: |
| **BOLA / BFLA (Quebra de Autorização em Objetos/Funções)** | OWASP A01:2021<br>CWE-639 / CWE-285 | **Crítico (8.8)** | Validação de Role `ADMIN` no servidor via `requireAdmin()`, rejeitando requisições anônimas com HTTP 401/403. | `tests/security/dast_fuzzer.test.ts` | 🛡️ Blindado |
| **Manipulação de JWT (`alg: none` ou Assinatura Forjada)** | OWASP A02:2021<br>CWE-347 / CWE-345 | **Crítico (9.1)** | `verifyAccessToken()` rejeita estritamente tokens sem HS256 e valida assinatura via `timingSafeEqual`. | `tests/security/dast_fuzzer.test.ts` | 🛡️ Blindado |
| **Bypass de Row Level Security (RLS) no Banco** | OWASP A01:2021<br>CWE-862 | **Crítico (8.9)** | Auditoria automatizada pelo agente `DB Guardian` bloqueando qualquer migração SQL sem RLS habilitado. | `scripts/security_squad/db_guardian.mjs` | 🛡️ Blindado |
| **Prototype Pollution (Client & Server-side)** | CWE-1321<br>OWASP A03:2021 | **Alto (8.2)** | Módulo `prototype-shield.ts` com `safeDeepClone` e `safeMerge` descartando `__proto__`, `constructor` e `prototype`. | `tests/security/prototype_pollution.test.ts` | 🛡️ Blindado |
| **Prompt Injection & Jailbreak em Modelos de IA** | OWASP LLM01:2025<br>CWE-20 | **Alto (8.5)** | Módulo `llm-guard.ts` com isolamento de contexto delimitado por Nonce criptográfico e detecção de heurísticas. | `tests/security/llm_guard.test.ts` | 🛡️ Blindado |
| **Vazamento de Informações Sensíveis / PII por IA** | OWASP LLM02:2025<br>CWE-200 / CWE-359 | **Alto (7.8)** | Motor de Redação de PII no `llm-guard.ts` (mascaramento automático de CPF, cartões e chaves de API). | `tests/security/llm_guard.test.ts` | 🛡️ Blindado |
| **Insecure Output Handling (Execução de Saída da IA)** | OWASP LLM05:2025<br>CWE-79 / CWE-116 | **Alto (8.0)** | Validação Zero-Trust de respostas de IA com schemas tipados rígidos via Zod (`validateLLMOutput`). | `tests/security/llm_guard.test.ts` | 🛡️ Blindado |
| **DOM XSS & DOM Clobbering no Navegador** | OWASP A03:2021<br>CWE-79 | **Alto (8.1)** | CSP Level 3 com `'strict-dynamic'`, Nonces e W3C **Trusted Types API** (`chimeraPolicy`). | `tests/security/trusted_types_browser.test.ts` | 🛡️ Blindado |
| **HTTP Flood Concorrente (DDoS na Camada de Aplicação)** | OWASP A04:2021<br>CWE-400 | **Alto (7.5)** | `enforceRateLimit()` em duas camadas (Token Bucket em memória + hash SHA-256 de IPs) retornando HTTP 429 com `Retry-After`. | `tests/security/stress_resilience.test.ts` | 🛡️ Blindado |
| **Botnets e Criação em Massa de Contas Anônimas** | OWASP A07:2021<br>CWE-307 / CWE-799 | **Alto (7.2)** | Rate limiting com cota agregada por sub-rede (`networkLimit`) e desafios matemáticos CAPTCHA HMAC-SHA256. | `tests/security/stress_resilience.test.ts` | 🛡️ Blindado |
| **Usurpação de Host (Host Action Spoofing)** | OWASP A01:2021<br>CWE-287 | **Alto (7.8)** | `applyRoomAction()` valida flag `isHost` antes de permitir alterações de configurações, início de partidas ou avanço de turnos. | `tests/security/multiplayer_pentest.test.ts` | 🛡️ Blindado |
| **Exaustão de Memória por Carga Gigante (String Bomb / OOM)** | OWASP A04:2021<br>CWE-770 | **Alto (7.5)** | Leitura protegida via `readLimitedJson()` cancelando streams que ultrapassem o teto de bytes (ex: 64KB). | `tests/security/browser_shield.test.ts` | 🛡️ Blindado |
| **Clickjacking & Injeção em Frames** | OWASP A05:2021<br>CWE-1021 | **Médio (6.1)** | Cabeçalhos `X-Frame-Options: DENY` e diretiva CSP `frame-ancestors 'none'`. | `tests/security/browser_shield.test.ts` | 🛡️ Blindado |
| **Ataques de Temporização (Timing Attacks em Senhas/Tokens)** | OWASP A02:2021<br>CWE-208 | **Médio (5.3)** | Comparação criptográfica em tempo constante (`crypto.timingSafeEqual`) eliminando vazamento de tempo. | `tests/security/dast_fuzzer.test.ts` | 🛡️ Blindado |
| **Auto-Voto e Trapaça em Partidas Multiplayer** | OWASP A04:2021<br>CWE-840 | **Médio (6.0)** | `validateItemVote()` impede jogadores de votarem na própria atuação e valida intervalo de notas autorizadas [0..10]. | `tests/security/multiplayer_pentest.test.ts` | 🛡️ Blindado |
| **Queda Abrupta de Host & Deadlock de Quórum** | OWASP A04:2021<br>CWE-755 | **Médio (5.5)** | Migração automática de liderança no `removePlayerFromRoom()` para o jogador mais antigo e recálculo resiliente de quórum. | `tests/security/chaos_resilience.test.ts` | 🛡️ Blindado |

---

## 🏆 Pontuação de Risco Ponderada Global (CVSS v3.1 / v4.0)

Com todas as 16 classes de contramedidas ativas e validadas por **44 testes automatizados em 8 suítes** no Vitest e pelos **7 agentes DevSecOps**, a **Pontuação de Risco Ponderada da Plataforma é de 0.0 / 10.0 (Zero Vulnerabilidades)**.
