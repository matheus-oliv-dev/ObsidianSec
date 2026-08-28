# 🌐 Guia Completo de Blindagem do Navegador (Browser Security Shield)

Este documento estabelece as diretrizes de segurança aplicadas no lado do cliente (navegador) para mitigar vetores de ataque como **Cross-Site Scripting (XSS)**, **Cross-Site Request Forgery (CSRF)**, **Clickjacking**, **Exfiltração de Sessões** e **Ataques de Canal Lateral**.

---

## 🛡️ 1. Content Security Policy (CSP Level 3)

A Política de Segurança de Conteúdo restringe os recursos (scripts, imagens, fontes, conexões) que o navegador tem permissão de carregar e executar.

### Diretivas Implementadas no `Browser Shield`:
```http
Content-Security-Policy: 
  default-src 'self';
  script-src 'self' 'nonce-{RANDOM_NONCE}';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: blob: https:;
  media-src 'self' blob: https:;
  font-src 'self' data:;
  connect-src 'self' wss: https:;
  frame-ancestors 'none';
  object-src 'none';
  base-uri 'self';
  form-action 'self';
  upgrade-insecure-requests;
```

### 🔑 Pontos-Chave:
* **Uso de Nonces Criptográficos:** Todo `<script>` inline gerado no servidor deve conter o atributo `nonce="..."`. Scripts injetados por invasores (DOM XSS) não possuirão o nonce válido e serão terminantemente bloqueados pelo navegador.
* **`frame-ancestors 'none'`:** Impede que qualquer site incorpore a aplicação em `<iframe>`, anulando ataques de Clickjacking.
* **`object-src 'none'`:** Desativa plugins legados como Flash e Java Applets.

---

## 🔒 2. Isolamento de Origem Cruzada (Cross-Origin Isolation)

Para proteger buffers de memória e impedir ataques de canal lateral como **Spectre**:

1. **`Cross-Origin-Opener-Policy (COOP): same-origin`**
   * Desconecta janelas abertas por scripts de terceiros (`window.opener = null`), impedindo manipulações maliciosas entre abas.
2. **`Cross-Origin-Embedder-Policy (COEP): require-corp`**
   * Garante que recursos externos (imagens, áudios) só sejam carregados se declararem explicitamente permissão via CORS/CORP.
3. **`Cross-Origin-Resource-Policy (CORP): same-origin`**
   * Impede que outros domínios façam download ou leiam mídias privadas da aplicação.

---

## 🍪 3. Arquitetura Segura de Cookies & Sessão

Armazenar tokens JWT sensíveis em `localStorage` expõe a credencial a qualquer script executado via XSS. O ecossistema adota a estratégia de **Cookies com Prefixo `__Host-`**:

```http
Set-Cookie: __Host-session_token=jwt_value_here; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600
```

### Propriedades de Blindagem:
* **Prefixo `__Host-`:** O navegador exige que o cookie seja transmitido apenas via HTTPS, que o caminho seja exatamente `/` e proíbe subdomínios de subscreverem ou sobrescreverem este cookie.
* **`HttpOnly`:** Impede que `document.cookie` acesse o token via JavaScript (mitigando roubo de sessão em caso de XSS parcial).
* **`Secure`:** Garante que o cookie nunca trafegue em conexões HTTP inseguras.
* **`SameSite=Strict`:** Impede o envio do cookie em requisições disparadas por outros sites (mitigando CSRF em 100%).

---

## 🎛️ 4. Restrição de APIs de Hardware (Permissions-Policy)

O cabeçalho `Permissions-Policy` desativa explicitamente sensores e recursos do dispositivo que não são necessários:

```http
Permissions-Policy: microphone=(self), camera=(), geolocation=(), payment=(), usb=(), screen-wake-lock=()
```

* O **microfone** é liberado estritamente para a origem da aplicação (`self`) para gravação de áudio.
* Câmera, GPS, API de Pagamentos e WebUSB ficam bloqueados mesmo se scripts maliciosos tentarem solicitá-los.

---

## 🧩 5. Prevenção Contra DOM Clobbering & String Bombs

1. **DOM Clobbering:** O módulo `sanitizer.ts` remove tags HTML que usam atributos `id` ou `name` para substituir propriedades globais do objeto `window` ou de formulários (`form.elements`).
2. **String Bomb / Anti-OOM:** O utilitário `readLimitedJson()` lê requisições via `ReadableStream` com contador estrito de bytes, interrompendo imediatamente o tráfego se o payload exceder o teto seguro (ex: 64KB).
