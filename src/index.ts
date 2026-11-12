/**
 * zero-pii-redactor: ReDoS-free, high-speed PII redactor, tokenizer, auditor, and pseudonymizer.
 * Built with native WebCrypto. Zero Runtime Dependencies.
 */

export * from './luhn.js';
export * from './patterns.js';

import { scanPii, RedactMode, CustomDetector } from './patterns.js';

export interface RedactOptions {
  /** Redaction mode: 'mask' (partial obfuscation) or 'replace' (tag tokens). Defaults to 'mask'. */
  mode?: RedactMode;
  /** Custom list of sensitive object key names to redact unconditionally. */
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

/**
 * Redact PII from a plain string with zero ReDoS risk.
 */
export function redactText(text: string, options: RedactOptions = {}): string {
  if (typeof text !== 'string' || !text) {
    return text;
  }

  const mode = options.mode ?? 'mask';
  const matches = scanPii(text, mode, options.customDetectors);

  let result = text;
  for (const match of matches) {
    result = result.slice(0, match.startIndex) + match.replacement + result.slice(match.endIndex);
  }

  return result;
}

/**
 * Deeply and recursively redact PII from strings, arrays, and JSON objects.
 * Protects both values and sensitive object keys.
 */
export function redact<T = any>(input: T, options: RedactOptions = {}): T {
  if (input === null || typeof input !== 'object') {
    if (typeof input === 'string') {
      return redactText(input, options) as unknown as T;
    }
    return input;
  }

  if (Array.isArray(input)) {
    return input.map((item) => redact(item, options)) as unknown as T;
  }

  const customKeys = options.sensitiveKeys
    ? new Set(options.sensitiveKeys.map((k) => k.toLowerCase()))
    : DEFAULT_SENSITIVE_KEYS;

  const result: Record<string, any> = {};
  for (const [key, value] of Object.entries(input as Record<string, any>)) {
    const lowerKey = key.toLowerCase().replace(/[-_]/g, '');
    if (customKeys.has(lowerKey)) {
      result[key] = options.mode === 'replace' ? `[REDACTED_${key.toUpperCase()}]` : '********';
    } else {
      result[key] = redact(value, options);
    }
  }

  return result as T;
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
  const counts: Record<string, number> = {};

  for (const m of matches) {
    counts[m.type] = (counts[m.type] || 0) + 1;
  }

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
  return new TransformStream<string, string>({
    transform(chunk, controller) {
      controller.enqueue(redactText(chunk, options));
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
 * Pseudonymize an identifier with salted SHA-256 (one-way deterministic token).
 */
export async function pseudonymize(value: string, salt: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(`${salt}:${value}`);
  const crypto = getWebCrypto();
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  return `pii_hash:${hex.slice(0, 16)}`;
}

/**
 * Securely tokenize sensitive text with reversible AES-256-GCM encryption.
 */
export async function tokenize(secret: string, plaintext: string): Promise<string> {
  const crypto = getWebCrypto();
  const encoder = new TextEncoder();
  const rawKey = encoder.encode(secret.padEnd(32, '0').slice(0, 32));
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    rawKey as unknown as BufferSource,
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as unknown as BufferSource },
    cryptoKey,
    encoder.encode(plaintext) as unknown as BufferSource
  );

  const ivHex = Array.from(iv).map((b) => b.toString(16).padStart(2, '0')).join('');
  const cipherHex = Array.from(new Uint8Array(ciphertext)).map((b) => b.toString(16).padStart(2, '0')).join('');

  return `pii_tok_${ivHex}_${cipherHex}`;
}

/**
 * Detokenize an encrypted token back to plaintext.
 */
export async function detokenize(secret: string, token: string): Promise<string> {
  if (!token.startsWith('pii_tok_')) {
    throw new Error('Invalid token prefix');
  }

  const parts = token.slice('pii_tok_'.length).split('_');
  if (parts.length !== 2) {
    throw new Error('Malformed token structure');
  }

  const [ivHex, cipherHex] = parts;
  const iv = new Uint8Array(ivHex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16)));
  const ciphertext = new Uint8Array(cipherHex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16)));

  const crypto = getWebCrypto();
  const encoder = new TextEncoder();
  const rawKey = encoder.encode(secret.padEnd(32, '0').slice(0, 32));
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    rawKey as unknown as BufferSource,
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv as unknown as BufferSource },
    cryptoKey,
    ciphertext as unknown as BufferSource
  );

  return new TextDecoder().decode(decrypted);
}
