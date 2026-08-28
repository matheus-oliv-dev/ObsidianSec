/**
 * Módulo Prototype Shield: Proteção contra Prototype Pollution (CWE-1321).
 * Sanitiza objetos recursivamente, descarte de chaves __proto__, constructor e prototype,
 * e suporte a congelamento defensivo de protótipos em runtime.
 */

const DANGEROUS_KEYS = new Set(["__proto__", "constructor", "prototype"]);

/**
 * Verifica se um objeto contém chaves potencialmente perigosas para poluição de protótipo.
 */
export function containsPrototypePollution(obj: unknown): boolean {
  if (!obj || typeof obj !== "object") return false;

  if (Array.isArray(obj)) {
    return obj.some((item) => containsPrototypePollution(item));
  }

  for (const key of Object.keys(obj)) {
    if (DANGEROUS_KEYS.has(key)) {
      return true;
    }
    const val = (obj as Record<string, unknown>)[key];
    if (val && typeof val === "object" && containsPrototypePollution(val)) {
      return true;
    }
  }

  return false;
}

/**
 * Clona e sanitiza um objeto de forma profunda, removendo chaves que tentam sobrescrever o protótipo.
 */
export function safeDeepClone<T>(input: T): T {
  if (input === null || typeof input !== "object") {
    return input;
  }

  if (Array.isArray(input)) {
    return input.map((item) => safeDeepClone(item)) as unknown as T;
  }

  const cleanObject: Record<string, unknown> = Object.create(null);

  for (const [key, value] of Object.entries(input)) {
    if (DANGEROUS_KEYS.has(key)) {
      continue; // Descarta __proto__, constructor, prototype
    }
    cleanObject[key] = safeDeepClone(value);
  }

  return cleanObject as T;
}

/**
 * Realiza merge seguro entre múltiplos objetos evitando prototype pollution.
 */
export function safeMerge<T extends Record<string, any>>(target: T, source: Record<string, any>): T {
  if (!source || typeof source !== "object") return target;

  for (const key of Object.keys(source)) {
    if (DANGEROUS_KEYS.has(key)) {
      continue;
    }

    const sourceVal = source[key];
    const targetVal = target[key];

    if (
      sourceVal &&
      typeof sourceVal === "object" &&
      !Array.isArray(sourceVal) &&
      targetVal &&
      typeof targetVal === "object" &&
      !Array.isArray(targetVal)
    ) {
      safeMerge(targetVal, sourceVal);
    } else if (sourceVal !== undefined) {
      target[key as keyof T] = safeDeepClone(sourceVal);
    }
  }

  return target;
}

/**
 * Congela os protótipos globais de Object e Array para imunidade em runtime (Zero-Day defense).
 */
export function freezeGlobalPrototypes(): void {
  if (typeof Object.freeze === "function") {
    try {
      Object.freeze(Object.prototype);
      Object.freeze(Array.prototype);
      Object.freeze(Function.prototype);
    } catch {
      // Ignora se já estiver congelado em runtime estrito
    }
  }
}
