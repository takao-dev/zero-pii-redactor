import { isValidLuhn, isValidMyNumber } from './luhn.js';

export interface PiiMatch {
  type: string;
  value: string;
  startIndex: number;
  endIndex: number;
  replacement: string;
}

export type RedactMode = 'mask' | 'replace' | 'pseudonymize';

export interface CustomDetector {
  type: string;
  pattern: RegExp;
  validator?: (match: string) => boolean;
  replacer?: (match: string, mode: RedactMode) => string;
}

// Strict, linear O(N) bounded regexes without backtracking or unbounded quantifiers (ReDoS-free)
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

// Japan Phone numbers (Official Ministry of Internal Affairs 10/11-digit numbering plan)
// Mobile/IP: 090/080/070/050-xxxx-xxxx (11 digits), Landline: 03/06-xxxx-xxxx or 0xx-xxx-xxxx etc. (10 digits)
const JP_PHONE_REGEX = /\b0(?:[5789]0-\d{4}-\d{4}|[1-9]\d-\d{4}-\d{4}|[1-9]\d{2}-\d{3}-\d{4}|[1-9]\d{3}-\d{2}-\d{4})\b/g;

// Japan Postal code (〒123-4567 or 123-4567)
const JP_POSTAL_REGEX = /(?:〒\s*)?\b\d{3}-\d{4}\b/g;

// Potential Japan MyNumber (12 digits with optional spaces/hyphens: xxxx-xxxx-xxxx)
const POTENTIAL_MYNUMBER_REGEX = /\b\d{4}[ -]?\d{4}[ -]?\d{4}\b/g;

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

export function maskMyNumber(num: string, mode: RedactMode): string {
  if (mode === 'replace') return '[REDACTED_MYNUMBER]';
  const digits = num.replace(/\D/g, '');
  return `****-****-${digits.slice(-4)}`;
}

export function maskToken(token: string, type: string, mode: RedactMode): string {
  if (mode === 'replace') return `[REDACTED_${type.toUpperCase()}]`;
  if (token.length <= 8) return '********';
  return `${token.slice(0, 4)}...${token.slice(-4)}`;
}

export function maskPhone(phone: string, mode: RedactMode): string {
  if (mode === 'replace') return '[REDACTED_PHONE]';
  const digits = phone.replace(/\D/g, '');
  return `***-****-${digits.slice(-4)}`;
}

export function maskPostal(postal: string, mode: RedactMode): string {
  if (mode === 'replace') return '[REDACTED_POSTAL]';
  return '***-****';
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
 * Scan text for all PII patterns and custom detectors.
 */
export function scanPii(
  text: string,
  mode: RedactMode = 'mask',
  customDetectors: CustomDetector[] = []
): PiiMatch[] {
  const matches: PiiMatch[] = [];

  // 1. Tokens and API Keys
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

  // 5. Japan MyNumber with Modulo 11 check digit
  scanRegex(text, POTENTIAL_MYNUMBER_REGEX, (val, start, end) => {
    if (isValidMyNumber(val)) {
      matches.push({ type: 'mynumber', value: val, startIndex: start, endIndex: end, replacement: maskMyNumber(val, mode) });
    }
  });

  // 6. Japan Phone & Postal
  scanRegex(text, JP_PHONE_REGEX, (val, start, end) => {
    matches.push({ type: 'phone', value: val, startIndex: start, endIndex: end, replacement: maskPhone(val, mode) });
  });

  scanRegex(text, JP_POSTAL_REGEX, (val, start, end) => {
    matches.push({ type: 'postal', value: val, startIndex: start, endIndex: end, replacement: maskPostal(val, mode) });
  });

  // 7. Custom Detectors
  for (const detector of customDetectors) {
    scanRegex(text, detector.pattern, (val, start, end) => {
      if (!detector.validator || detector.validator(val)) {
        const replacement = detector.replacer
          ? detector.replacer(val, mode)
          : (mode === 'replace' ? `[REDACTED_${detector.type.toUpperCase()}]` : '********');
        matches.push({ type: detector.type, value: val, startIndex: start, endIndex: end, replacement });
      }
    });
  }

  // Prioritize longer matches first, then deduplicate overlapping ranges
  matches.sort((a, b) => (b.endIndex - b.startIndex) - (a.endIndex - a.startIndex));
  const deduped: PiiMatch[] = [];
  const coveredRanges: [number, number][] = [];

  for (const m of matches) {
    const isOverlapping = coveredRanges.some(([start, end]) => m.startIndex < end && m.endIndex > start);
    if (!isOverlapping) {
      deduped.push(m);
      coveredRanges.push([m.startIndex, m.endIndex]);
    }
  }

  // Sort descending by start position for safe string replacement
  return deduped.sort((a, b) => b.startIndex - a.startIndex);
}

function scanRegex(text: string, regex: RegExp, onMatch: (val: string, start: number, end: number) => void): void {
  regex.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = regex.exec(text)) !== null) {
    onMatch(m[0], m.index, m.index + m[0].length);
  }
}
