/**
 * zero-pii-redactor: Bounded built-in PII redactor, tokenizer, auditor, and pseudonymizer.
 * Built with native WebCrypto. Zero Runtime Dependencies.
 */

export * from './luhn.js';
export * from './patterns.js';

import { scanPii, RedactMode, CustomDetector } from './patterns.js';

export interface RedactOptions {
  /** Redaction mode: 'mask' (partial obfuscation) or 'replace' (tag tokens). Defaults to 'mask'. */
  mode?: RedactMode;
  /** When provided, replaces the built-in sensitive-key list; include every key that must be redacted. */
  sensitiveKeys?: string[];
  /** Custom salt for pseudonymization. */
  salt?: string;
  /** Custom detectors for proprietary tokens, IDs, or patterns. */
  customDetectors?: CustomDetector[];
}

export interface PiiAuditReport {
  total: number;
  riskLevel: 'none' | 'low' | 'medium' | 'high' | 'critical';
  counts: Record<string, number>;
  types: string[];
  hasCredentials: boolean;
  hasFinancials: boolean;
}

const DEFAULT_SENSITIVE_KEYS = new Set([
  'password',
  'pass',
  'secret',
  'apikey',
  'api_key',
  'accesstoken',
  'access_token',
  'refreshtoken',
  'refresh_token',
  'authorization',
  'auth',
  'creditcard',
  'credit_card',
  'cardnumber',
  'card_number',
  'cvv',
  'cvc',
  'ssn',
  'mynumber',
]);
const MAX_STRING_CHARS = 1_048_576;
const MAX_OBJECT_DEPTH = 128;
const MAX_OBJECT_NODES = 100_000;

/**
 * Redact PII using bounded built-in patterns; caller-provided detector regexes must be trusted.
 */
export function redactText(text: string, options: RedactOptions = {}): string {
  if (typeof text !== 'string' || !text) {
    return text;
  }

  const mode = options.mode ?? 'mask';
  if (mode === 'pseudonymize') throw new Error('Use pseudonymize(value, salt) for deterministic one-way identifier hashing');
  const matches = scanPii(text, mode, options.customDetectors);
  let result = '';
  let offset = 0;
  for (const match of matches) {
    result += text.slice(offset, match.startIndex) + match.replacement;
    offset = match.endIndex;
  }
  return result + text.slice(offset);
}

/**
 * Deeply and recursively redact PII from strings, arrays, and JSON objects.
 * Protects both values and sensitive object keys.
 */
export function redact<T = any>(input: T, options: RedactOptions = {}): T {
  const normalize = (key: string) => key.toLowerCase().replace(/[-_]/g, '');
  const customKeys = options.sensitiveKeys
    ? new Set(options.sensitiveKeys.map(normalize))
    : new Set([...DEFAULT_SENSITIVE_KEYS].map(normalize));
  const seen = new WeakMap<object, any>();
  let visitedNodes = 0;
  const visit = (value: any, depth = 0): any => {
    if (typeof value === 'string') return redactText(value, options);
    if (value === null || typeof value !== 'object') return value;
    const existing = seen.get(value);
    if (existing) return existing;
    if (depth >= MAX_OBJECT_DEPTH) throw new RangeError(`Redaction object depth exceeds ${MAX_OBJECT_DEPTH}`);
    if (++visitedNodes > MAX_OBJECT_NODES) throw new RangeError(`Redaction object exceeds ${MAX_OBJECT_NODES} values`);
    if (Array.isArray(value)) {
      const result: any[] = [];
      seen.set(value, result);
      for (const item of value) {
        if (++visitedNodes > MAX_OBJECT_NODES) throw new RangeError(`Redaction object exceeds ${MAX_OBJECT_NODES} values`);
        result.push(visit(item, depth + 1));
      }
      return result;
    }
    const result: Record<string, any> = {};
    seen.set(value, result);
    for (const key in value) {
      if (!Object.prototype.hasOwnProperty.call(value, key)) continue;
      if (++visitedNodes > MAX_OBJECT_NODES) throw new RangeError(`Redaction object exceeds ${MAX_OBJECT_NODES} values`);
      const nested = value[key];
      const redacted = customKeys.has(normalize(key))
        ? options.mode === 'replace' ? `[REDACTED_${key.toUpperCase()}]` : '********'
        : visit(nested, depth + 1);
      Object.defineProperty(result, key, { value: redacted, enumerable: true, configurable: true, writable: true });
    }
    return result;
  };
  return visit(input);
}

/**
 * Audit and evaluate the privacy risk level of text or structured data without masking.
 */
export function auditPii(input: any, customDetectors: CustomDetector[] = []): PiiAuditReport {
  let text = '';
  if (typeof input === 'string') {
    text = input;
  } else {
    try {
      text = JSON.stringify(input);
    } catch {
      text = String(input);
    }
  }

  const matches = scanPii(text, 'mask', customDetectors);
  const countMap = new Map<string, number>();

  for (const m of matches) {
    countMap.set(m.type, (countMap.get(m.type) ?? 0) + 1);
  }

  const counts: Record<string, number> = {};
  for (const [type, count] of countMap) Object.defineProperty(counts, type, { value: count, enumerable: true, configurable: true, writable: true });

  const total = matches.length;
  const types = Object.keys(counts);

  const hasCredentials = Boolean(counts.jwt || counts.aws_key || counts.github_token || counts.slack_token);
  const hasFinancials = Boolean(counts.credit_card || counts.mynumber);

  let riskLevel: PiiAuditReport['riskLevel'] = 'none';
  if (hasCredentials || counts.credit_card || counts.mynumber) {
    riskLevel = 'critical';
  } else if (counts.email || counts.phone) {
    riskLevel = 'high';
  } else if (counts.ipv4 || counts.ipv6 || counts.postal) {
    riskLevel = 'medium';
  } else if (total > 0) {
    riskLevel = 'low';
  }

  return {
    total,
    riskLevel,
    counts,
    types,
    hasCredentials,
    hasFinancials,
  };
}

/**
 * Create a Web Streams TransformStream for real-time streaming redaction.
 */
export function createRedactorTransform(options: RedactOptions = {}): TransformStream<string, string> {
  const maxRecordChars = 65_536;
  let pending = '';
  return new TransformStream<string, string>({
    transform(chunk, controller) {
      if (typeof chunk !== 'string') throw new TypeError('Redactor stream accepts string chunks only');
      pending += chunk;
      let newline = pending.indexOf('\n');
      while (newline !== -1) {
        const record = pending.slice(0, newline + 1);
        if (record.length > maxRecordChars) throw new RangeError('Redactor stream record exceeds 65536 characters');
        controller.enqueue(redactText(record, options));
        pending = pending.slice(newline + 1);
        newline = pending.indexOf('\n');
      }
      if (pending.length > maxRecordChars) throw new RangeError('Redactor stream record exceeds 65536 characters');
    },
    flush(controller) {
      if (pending) controller.enqueue(redactText(pending, options));
    },
  });
}

export function getWebCrypto(): Crypto {
  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto?.subtle) {
    return globalThis.crypto;
  }
  throw new Error('WebCrypto SubtleCrypto is not available in this environment');
}

/**
 * Pseudonymize an identifier with keyed HMAC-SHA-256 (one-way deterministic token).
 */
export async function pseudonymize(value: string, salt: string): Promise<string> {
  if (typeof value !== 'string' || typeof salt !== 'string' || value.length > MAX_STRING_CHARS || salt.length > 4096) {
    throw new RangeError('Pseudonymization input exceeds its size limit');
  }
  const encoder = new TextEncoder();
  const saltBytes = encoder.encode(salt);
  const valueBytes = encoder.encode(value);
  if (saltBytes.byteLength < 16 || saltBytes.byteLength > 4096 || valueBytes.byteLength > MAX_STRING_CHARS) {
    throw new Error('Pseudonymization requires an input no larger than 1 MiB and a 16-byte to 4-KiB salt');
  }
  const crypto = getWebCrypto();
  const key = await crypto.subtle.importKey('raw', saltBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const domainSeparatedValue = encoder.encode(`zero-pii-redactor:pseudonym:v2\0${value}`);
  const hashBuffer = await crypto.subtle.sign('HMAC', key, domainSeparatedValue);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  return `pii_hash:${hex}`;
}

/**
 * Securely tokenize sensitive text with reversible AES-256-GCM encryption.
 */
export async function tokenize(secret: string, plaintext: string): Promise<string> {
  if (typeof secret !== 'string' || typeof plaintext !== 'string' || plaintext.length > MAX_STRING_CHARS) {
    throw new RangeError('Token plaintext must be a string no larger than 1 MiB');
  }
  const crypto = getWebCrypto();
  const encoder = new TextEncoder();
  const plaintextBytes = encoder.encode(plaintext);
  if (plaintextBytes.byteLength > MAX_STRING_CHARS) throw new RangeError('Token plaintext must be no larger than 1 MiB when encoded');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cryptoKey = await deriveTokenKey(secret, salt, ['encrypt']);

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as unknown as BufferSource },
    cryptoKey,
    plaintextBytes as unknown as BufferSource
  );

  const ivHex = Array.from(iv).map((b) => b.toString(16).padStart(2, '0')).join('');
  const cipherHex = Array.from(new Uint8Array(ciphertext)).map((b) => b.toString(16).padStart(2, '0')).join('');

  const saltHex = Array.from(salt).map((b) => b.toString(16).padStart(2, '0')).join('');
  return `pii_tok_v2_${saltHex}_${ivHex}_${cipherHex}`;
}

/**
 * Detokenize an encrypted token back to plaintext.
 */
export async function detokenize(secret: string, token: string): Promise<string> {
  const maxTokenChars = 2 * (MAX_STRING_CHARS + 16) + 128;
  if (typeof secret !== 'string' || typeof token !== 'string' || token.length > maxTokenChars) {
    throw new RangeError('Encrypted token must be a string no larger than 2 MiB');
  }
  if (!token.startsWith('pii_tok_')) {
    throw new Error('Invalid token prefix');
  }

  const parts = token.slice('pii_tok_'.length).split('_');
  if (parts.length !== 4) throw new Error('Malformed token structure');
  if (parts[0] !== 'v2') throw new Error('Unsupported token version; legacy tokens require re-tokenization');

  const [, saltHex, ivHex, cipherHex] = parts;
  const salt = parseHex(saltHex, 16);
  const iv = parseHex(ivHex, 12);
  if (!/^(?:[0-9a-f]{2}){16,}$/i.test(cipherHex) || cipherHex.length > 2 * (MAX_STRING_CHARS + 16)) {
    throw new Error('Malformed encrypted token');
  }
  const ciphertext = parseHex(cipherHex);

  const crypto = getWebCrypto();
  const cryptoKey = await deriveTokenKey(secret, salt, ['decrypt']);

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv as unknown as BufferSource },
    cryptoKey,
    ciphertext as unknown as BufferSource
  );

  return new TextDecoder().decode(decrypted);
}

async function deriveTokenKey(secret: string, salt: Uint8Array, usages: KeyUsage[]): Promise<CryptoKey> {
  const crypto = getWebCrypto();
  const encoder = new TextEncoder();
  if (typeof secret !== 'string' || secret.length > 4096) throw new Error('Token secret must be a string no larger than 4 KiB');
  const secretBytes = encoder.encode(secret);
  if (secretBytes.length < 32 || secretBytes.length > 4096) throw new Error('Token secret must contain 32 bytes to 4 KiB of UTF-8');
  const base = await crypto.subtle.importKey('raw', secretBytes as unknown as BufferSource, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey({
    name: 'HKDF', hash: 'SHA-256', salt: salt as unknown as BufferSource,
    info: encoder.encode('zero-pii-redactor:token:v2') as unknown as BufferSource,
  }, base, { name: 'AES-GCM', length: 256 }, false, usages);
}

function parseHex(value: string, expectedBytes?: number): Uint8Array {
  if (!/^(?:[0-9a-f]{2})*$/i.test(value) || (expectedBytes !== undefined && value.length !== expectedBytes * 2)) {
    throw new Error('Malformed encrypted token');
  }
  return new Uint8Array(value.match(/.{2}/g)?.map((byte) => parseInt(byte, 16)) ?? []);
}
