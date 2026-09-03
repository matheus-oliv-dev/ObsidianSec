# 🛡️ Arquitetura Defensiva, Zero-Trust & DevSecOps

O Redubla adota o modelo de **Defesa em Profundidade em 7 Camadas**. Cada camada opera de forma independente, garantindo que o comprometimento de uma barreira não comprometa a segurança global do sistema.

---

## 🏰 1. As 7 Camadas Defensivas

```
┌─────────────────────────────────────────────────────────────┐
│ Camada 1: CAMUFLAGEM DE BORDA (src/proxy.ts)                │
│ -> /admin responde HTTP 404 sem a chave ADMIN_GATE_KEY      │
├─────────────────────────────────────────────────────────────┤
│ Camada 2: CAPTCHA CRIPTOGRÁFICO (src/lib/security/captcha.ts│
│ -> Desafio SVG assinado com HMAC-SHA256 e nonce descartável │
├─────────────────────────────────────────────────────────────┤
│ Camada 3: AUTENTICAÇÃO LOCAL & 2FA (src/lib/supabase/admin) │
│ -> Validação JWT na RAM + Segundo Fator Obrigatório (aal2)  │
├─────────────────────────────────────────────────────────────┤
│ Camada 4: ROW LEVEL SECURITY & ZERO-TRUST (PostgreSQL)      │
│ -> Email removido de profiles; tabelas fechadas a anon      │
├─────────────────────────────────────────────────────────────┤
│ Camada 5: RATE LIMITING HÍBRIDO (RAM + Postgres RPC)        │
│ -> Absorve >90% na RAM e bloqueia DDoS / DoS em microsseg.  │
├─────────────────────────────────────────────────────────────┤
│ Camada 6: STREAMING SEGURO ANTI-OOM (src/lib/security/)     │
│ -> readLimitedJson corta conexões com payloads gigantes     │
├─────────────────────────────────────────────────────────────┤
│ Camada 7: ESQUADRÃO DEVSECOPS & PRE-PUSH HOOK (.githooks/)  │
│ -> 4 Agentes de IA barram vulnerabilidades antes do commit  │
└─────────────────────────────────────────────────────────────┘
```

---

## 🤖 2. Esquadrão Multi-Agente DevSecOps

O projeto possui um pipeline automatizado de auditoria executado tanto localmente via **Git Hook `pre-push`** quanto no **GitHub Actions** (`.github/workflows/security-audit.yml`):

1. **DB & RLS Guardian (`scripts/security_squad/engine.py`):**
   * Analisa todas as migrações SQL em `supabase/migrations/`.
   * Bloqueia qualquer tabela sem RLS habilitado ou concessão pública a `anon`.
2. **Code & API Sentinel (`.semgrep/admin-security.yml`):**
   * Análise estática da AST do código Next.js.
   * Exige que rotas `/api/admin/*` invoquem `requireAdmin`.
   * Proíbe uso de algoritmos inseguros (`alg: none`).
3. **Red Team Fuzzer DAST (`tests/security/dast_fuzzer.test.ts`):**
   * Simulação dinâmica de ataques (BOLA, força bruta de senhas, adulteração de tokens).
4. **Resilience & DoS Specialist (`tests/security/stress_resilience.test.ts`):**
   * Simula rajadas de requisições concorrentes e botnets criando 500 contas em massa.
5. **Security Lead Orchestrator (`scripts/security_squad/run.py`):**
   * Consolida métricas, calcula a pontuação de risco CVSS v3.1 e bloqueia merges com pontuação > 0.0.

---

## 🔒 3. Políticas de Storage e Mídias Privadas

* **Bucket de Clipes (`clips`):** Apenas leitura pública de mídias ativas (`status = 'ACTIVE'`). Escrita e exclusão restritas exclusivamente ao `service_role`.
* **Bucket de Gravações (`recordings`):** 100% privado. Uploads usam URLs assinadas temporárias (`createUploadUrl`) com tokens de curta duração.
* **Auto-Expiração:** Mídias temporárias de salas encerradas são purgadas automaticamente pelas rotinas de limpeza periódica.


---
*Documentação integrada da suíte ChimeraGuard DevSecOps.*
