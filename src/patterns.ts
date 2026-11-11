import { isValidLuhn } from './luhn.js';

export interface PiiMatch {
  type: string;
  value: string;
  startIndex: number;
  endIndex: number;
  replacement: string;
}

export type RedactMode = 'mask' | 'replace' | 'pseudonymize';

// Strict, linear O(N) bounded regexes without backtracking or unbounded quantifiers (ReDoS-free)
// RFC 5321 limits: local part max 64 chars, domain max 253 chars, TLD max 63 chars
const EMAIL_REGEX = /\b[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[a-zA-Z0-9-]{1,63}(?:\.[a-zA-Z0-9-]{1,63})*\.[a-zA-Z]{2,63}\b/g;

// IPv4 and IPv6
const IPV4_REGEX = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
const IPV6_REGEX = /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g;

// Tokens and credentials
const JWT_REGEX = /\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b/g;
const AWS_KEY_REGEX = /\bAKIA[0-9A-Z]{16}\b/g;
const GITHUB_TOKEN_REGEX = /\bgh[pousr]_[A-Za-z0-9_]{36,255}\b/g;
const SLACK_TOKEN_REGEX = /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g;

// Credit cards (13 to 19 digits, partitioned with single space or hyphen)
const POTENTIAL_CC_REGEX = /\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{1,7}\b/g;

// Phone numbers (E.164 and international/domestic standard formats)
const PHONE_REGEX = /(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{2,4}[-.\s]?\d{3,4}\b/g;

export function maskEmail(email: string, mode: RedactMode): string {
  if (mode === 'replace') return '[REDACTED_EMAIL]';
  const [local, domain] = email.split('@');
  if (!domain) return '[REDACTED_EMAIL]';

  const maskedLocal = local.length <= 2
    ? `${local[0]}*`
    : `${local[0]}${'*'.repeat(Math.min(local.length - 2, 5))}${local[local.length - 1]}`;

  return `${maskedLocal}@${domain}`;
}

export function maskCreditCard(cc: string, mode: RedactMode): string {
  if (mode === 'replace') return '[REDACTED_CREDIT_CARD]';
  const digits = cc.replace(/\D/g, '');
  const last4 = digits.slice(-4);
  const first1 = digits[0];
  return `${first1}***-****-****-${last4}`;
}

export function maskToken(token: string, type: string, mode: RedactMode): string {
  if (mode === 'replace') return `[REDACTED_${type.toUpperCase()}]`;
  if (token.length <= 8) return '********';
  return `${token.slice(0, 4)}...${token.slice(-4)}`;
}

export function maskPhone(phone: string, mode: RedactMode): string {
  if (mode === 'replace') return '[REDACTED_PHONE]';
  const digits = phone.replace(/\D/g, '');
  if (digits.length <= 4) return '***-***';
  return `***-***-${digits.slice(-4)}`;
}

export function maskIp(ip: string, mode: RedactMode): string {
  if (mode === 'replace') return '[REDACTED_IP]';
  if (ip.includes('.')) {
    const parts = ip.split('.');
    return `${parts[0]}.${parts[1]}.*.*`;
  }
  return '****:****:****:****';
}

/**
 * Scan a text string for all PII items and return match replacements.
 */
export function scanPii(text: string, mode: RedactMode = 'mask'): PiiMatch[] {
  const matches: PiiMatch[] = [];

  // 1. Tokens and API Keys (scan first before general numbers)
  scanRegex(text, JWT_REGEX, (val, start, end) => {
    matches.push({ type: 'jwt', value: val, startIndex: start, endIndex: end, replacement: maskToken(val, 'jwt', mode) });
  });

  scanRegex(text, AWS_KEY_REGEX, (val, start, end) => {
    matches.push({ type: 'aws_key', value: val, startIndex: start, endIndex: end, replacement: maskToken(val, 'aws_key', mode) });
  });

  scanRegex(text, GITHUB_TOKEN_REGEX, (val, start, end) => {
    matches.push({ type: 'github_token', value: val, startIndex: start, endIndex: end, replacement: maskToken(val, 'github_token', mode) });
  });

  scanRegex(text, SLACK_TOKEN_REGEX, (val, start, end) => {
    matches.push({ type: 'slack_token', value: val, startIndex: start, endIndex: end, replacement: maskToken(val, 'slack_token', mode) });
  });

  // 2. Emails
  scanRegex(text, EMAIL_REGEX, (val, start, end) => {
    matches.push({ type: 'email', value: val, startIndex: start, endIndex: end, replacement: maskEmail(val, mode) });
  });

  // 3. IPs
  scanRegex(text, IPV4_REGEX, (val, start, end) => {
    matches.push({ type: 'ipv4', value: val, startIndex: start, endIndex: end, replacement: maskIp(val, mode) });
  });
  scanRegex(text, IPV6_REGEX, (val, start, end) => {
    matches.push({ type: 'ipv6', value: val, startIndex: start, endIndex: end, replacement: maskIp(val, mode) });
  });

  // 4. Credit Cards with Luhn Check
  scanRegex(text, POTENTIAL_CC_REGEX, (val, start, end) => {
    if (isValidLuhn(val)) {
      matches.push({ type: 'credit_card', value: val, startIndex: start, endIndex: end, replacement: maskCreditCard(val, mode) });
    }
  });

  // Sort matches by start position descending to allow safe text slicing
  return matches.sort((a, b) => b.startIndex - a.startIndex);
}

function scanRegex(text: string, regex: RegExp, onMatch: (val: string, start: number, end: number) => void): void {
  regex.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = regex.exec(text)) !== null) {
    onMatch(m[0], m.index, m.index + m[0].length);
  }
}
