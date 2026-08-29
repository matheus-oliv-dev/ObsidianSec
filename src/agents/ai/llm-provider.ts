export interface LLMMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface LLMOptions {
  model?: string;
  temperature?: number;
  maxTokens?: number;
  responseFormat?: "json" | "text";
}

export interface LLMProvider {
  name: string;
  generateResponse(messages: LLMMessage[], options?: LLMOptions): Promise<string>;
}

/**
 * Modelos Ativos Confirmados na sua Conta Google AI Studio (com Rotação Inteligente de Cota)
 */
export const GEMINI_ACTIVE_MODELS = [
  "gemini-3-flash-preview",  // Pool 1 (Ultra-rápido ~1.2s)
  "gemini-3.6-flash",        // Pool 2 (~2.3s)
  "gemini-3.7-flash",        // Pool 3
  "gemini-3.5-flash",        // Pool 4
];

// Contador de Round-Robin para balanceamento de carga entre as cotas
let roundRobinIndex = 0;

/**
 * Provedor Google Gemini com Balanceamento Round-Robin de Cotas e Fallback Resiliente
 */
export class GeminiProvider implements LLMProvider {
  public name = "Google Gemini 3.x Multi-Pool";
  private apiKey: string;

  constructor(apiKey?: string) {
    this.apiKey = apiKey || process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY || "";
  }

  async generateResponse(messages: LLMMessage[], options: LLMOptions = {}): Promise<string> {
    if (!this.apiKey) {
      throw new Error("Chave GEMINI_API_KEY não configurada.");
    }

    const systemMsg = messages.find((m) => m.role === "system")?.content || "";
    const conversation = messages.filter((m) => m.role !== "system");

    const contents = conversation.map((m) => ({
      role: m.role === "assistant" ? "model" : "user",
      parts: [{ text: m.content }],
    }));

    const body: any = {
      contents,
      generationConfig: {
        temperature: options.temperature ?? 0.2,
        maxOutputTokens: options.maxTokens ?? 1500,
      },
    };

    if (systemMsg) {
      body.systemInstruction = { parts: [{ text: systemMsg }] };
    }

    if (options.responseFormat === "json") {
      body.generationConfig.responseMimeType = "application/json";
    }

    // Balanceamento Round-Robin: Inicia cada requisição em um modelo diferente para distribuir a cota de 5 RPM / 20 RPD
    const startIdx = roundRobinIndex % GEMINI_ACTIVE_MODELS.length;
    roundRobinIndex++;

    const rotatedModels = [
      ...GEMINI_ACTIVE_MODELS.slice(startIdx),
      ...GEMINI_ACTIVE_MODELS.slice(0, startIdx),
    ];

    const modelsToTry = options.model ? [options.model, ...rotatedModels.filter((m) => m !== options.model)] : rotatedModels;

    let lastError: any = null;

    for (const model of modelsToTry) {
      try {
        const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${encodeURIComponent(this.apiKey)}`;

        const res = await fetch(endpoint, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-goog-api-key": this.apiKey,
          },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(2500),
        });

        if (res.ok) {
          const data = await res.json();
          const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
          if (text) {
            return text;
          }
        }

        if (res.status === 503 || res.status === 429) {
          console.warn(`[GEMINI API] Google AI ocupado (${res.status}). Ativando fallback cognitivo instantâneo...`);
          throw new Error(`Google Gemini com sobrecarga (${res.status}). Ativando fallback seguro.`);
        }

        const errText = await res.text();
        console.warn(`[GEMINI API] Modelo ${model} (${res.status}): ${errText.slice(0, 80)}... Rotacionando para próximo pool...`);
        lastError = new Error(`Erro Gemini [${model}]: ${errText}`);
      } catch (err: any) {
        if (err.message.includes("sobrecarga")) throw err;
        console.warn(`[GEMINI API] Exceção em ${model}: ${err.message}. Rotacionando...`);
        lastError = err;
        break; // Não trava o usuário em múltiplos timeouts sucessivos
      }
    }

    throw lastError || new Error("Falha ao comunicar com os modelos da API Gemini.");
  }
}

/**
 * Provedor OpenAI / Modelos Compatíveis
 */
export class OpenAIProvider implements LLMProvider {
  public name = "OpenAI";
  private apiKey: string;
  private baseUrl: string;

  constructor(apiKey?: string, baseUrl = "https://api.openai.com/v1") {
    this.apiKey = apiKey || process.env.OPENAI_API_KEY || "";
    this.baseUrl = baseUrl;
  }

  async generateResponse(messages: LLMMessage[], options: LLMOptions = {}): Promise<string> {
    if (!this.apiKey) throw new Error("Chave OPENAI_API_KEY não configurada.");

    const body: any = {
      model: options.model || "gpt-4o-mini",
      messages,
      temperature: options.temperature ?? 0.2,
      max_tokens: options.maxTokens ?? 2000,
    };

    if (options.responseFormat === "json") body.response_format = { type: "json_object" };

    const res = await fetch(`${this.baseUrl}/chat/completions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(5000),
    });

    if (!res.ok) throw new Error(`Erro na API OpenAI (${res.status}): ${await res.text()}`);
    const data = await res.json();
    return data.choices?.[0]?.message?.content || "";
  }
}

/**
 * Provedor Local Ollama (Offline)
 */
export class OllamaLocalProvider implements LLMProvider {
  public name = "Ollama Local (DeepSeek/Llama)";
  private host: string;

  constructor(host = process.env.OLLAMA_HOST || "http://localhost:11434") {
    this.host = host;
  }

  async generateResponse(messages: LLMMessage[], options: LLMOptions = {}): Promise<string> {
    const model = options.model || "deepseek-r1:latest";
    const prompt = messages.map((m) => `${m.role.toUpperCase()}: ${m.content}`).join("\n\n");

    const res = await fetch(`${this.host}/api/generate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model,
        prompt,
        stream: false,
        format: options.responseFormat === "json" ? "json" : undefined,
        options: { temperature: options.temperature ?? 0.2 },
      }),
      signal: AbortSignal.timeout(10000),
    });

    if (!res.ok) throw new Error(`Ollama indisponível no endpoint ${this.host}`);
    const data = await res.json();
    return data.response || "";
  }
}

/**
 * Provedor Simulado / Motor Cognitivo Embutido (Offline Sandbox)
 */
export class BuiltinCognitiveSimulator implements LLMProvider {
  public name = "BomberCyber Built-in Cognitive Engine (Offline)";

  async generateResponse(messages: LLMMessage[]): Promise<string> {
    const analysis = {
      thoughtProcess: [
        "1. Analisando logs brutos de auditoria...",
        "2. Correlacionando cabeçalhos de borda com políticas de mitigação...",
        "3. Sintetizando diagnóstico defensivo...",
      ],
      cognitiveDiagnosis: {
        threatAssessment: "Risco mitigável através de cabeçalhos de borda e sanitização de dados no ponto de entrada.",
        deepAnalysis: "Recomenda-se reforço nas políticas de isolamento de origem e CSP.",
      },
      recommendedExploratoryTests: [
        {
          testName: "Fuzzing de Parâmetros com Delimitadores Nulos e Unicode",
          targetScope: "Endpoints de entrada de dados / API",
          rationale: "Validar se caracteres de controle ou buffers gigantes são devidamente truncados.",
        },
        {
          testName: "Auditoria de Isolamento de Sub-Rede (Rate Limiting Concorrente)",
          targetScope: "Controle de taxa de requisições",
          rationale: "Garantir que múltiplos clientes sob o mesmo bloco CIDR não causem negação de serviço mútua.",
        },
      ],
      autoPatches: [
        {
          file: "security.config.json",
          description: "Política de cabeçalhos de máxima restrição",
          patchCode: '{\n  "X-Frame-Options": "DENY",\n  "Content-Security-Policy": "default-src \'self\';"\n}',
        },
      ],
      qualityGateAdvice: "Aprovado com recomendação de monitoramento contínuo",
      verdict: "O esquadrão pode proceder com a aplicação do patch e validação do Quality Gate.",
    };

    return JSON.stringify(analysis, null, 2);
  }
}

/**
 * Fábrica inteligente de provedores de IA
 */
export function getAutoLLMProvider(): LLMProvider {
  if (process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY) return new GeminiProvider();
  if (process.env.OPENAI_API_KEY) return new OpenAIProvider();
  return new BuiltinCognitiveSimulator();
}
