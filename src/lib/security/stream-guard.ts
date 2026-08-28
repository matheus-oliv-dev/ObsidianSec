/**
 * Módulo de Proteção de Streaming e Anti-OOM (Out-of-Memory).
 * Garante que corpos de requisições JSON não excedam limites seguros antes do parse.
 */

export interface ReadLimitedJsonOptions {
  maxBytes?: number;
}

export class PayloadTooLargeError extends Error {
  constructor(message = "Corpo da requisição excede o tamanho máximo permitido") {
    super(message);
    this.name = "PayloadTooLargeError";
  }
}

/**
 * Lê de forma segura o corpo JSON de uma requisição com limite de bytes estrito.
 * Interrompe a leitura imediatamente se o limite for ultrapassado.
 */
export async function readLimitedJson<T = unknown>(
  request: Request,
  options: ReadLimitedJsonOptions = {},
): Promise<T> {
  const maxBytes = options.maxBytes ?? 64 * 1024; // 64 KB por padrão

  // Verifica cabeçalho Content-Length preliminar
  const contentLength = request.headers.get("content-length");
  if (contentLength && parseInt(contentLength, 10) > maxBytes) {
    throw new PayloadTooLargeError(`Content-Length (${contentLength} bytes) excede o limite de ${maxBytes} bytes.`);
  }

  if (!request.body) {
    throw new Error("Corpo da requisição vazio.");
  }

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      if (value) {
        totalBytes += value.length;
        if (totalBytes > maxBytes) {
          // Cancela o stream imediatamente para economizar recursos de rede/memória
          await reader.cancel();
          throw new PayloadTooLargeError(`Tamanho da carga útil excedeu o limite seguro de ${maxBytes} bytes.`);
        }
        chunks.push(value);
      }
    }
  } catch (err) {
    if (err instanceof PayloadTooLargeError) throw err;
    throw new Error(`Erro ao ler o stream da requisição: ${(err as Error).message}`);
  }

  const merged = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.length;
  }

  const text = new TextDecoder("utf-8").decode(merged);
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new Error("JSON malformado no corpo da requisição.");
  }
}
