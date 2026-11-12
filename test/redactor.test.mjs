import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';

if (!globalThis.crypto || !globalThis.crypto.subtle) {
  globalThis.crypto = webcrypto;
}

import {
  redactText,
  redact,
  auditPii,
  createRedactorTransform,
  isValidLuhn,
  isValidMyNumber,
  pseudonymize,
  tokenize,
  detokenize,
  getWebCrypto,
} from '../dist/index.js';

test('Luhn validator verifies standard card numbers and rejects non-cards', () => {
  assert.equal(isValidLuhn('4532015112830366'), true); // Visa
  assert.equal(isValidLuhn('4532-0151-1283-0366'), true);
  assert.equal(isValidLuhn('4532015112830367'), false); // Invalid checksum
  assert.equal(isValidLuhn('1234567890123456'), false);
});

test('Japan MyNumber Modulo 11 check digit verifies authentic numbers and rejects typos', () => {
  // Test case calculation:
  // Digits 1 to 11: 12345678901 -> remainder = sum % 11 -> check digit
  // Let's test with a mathematically valid 12-digit number:
  // e.g. 123456789018 -> check digit 8
  const validMyNumber = '123456789018';
  assert.equal(isValidMyNumber(validMyNumber), true);
  assert.equal(isValidMyNumber('1234-5678-9018'), true);

  // Single digit typo must be rejected
  assert.equal(isValidMyNumber('123456789017'), false);
  assert.equal(isValidMyNumber('123456789019'), false);
  assert.equal(isValidMyNumber('000000000001'), false);
});

test('Redaction detects and masks Japan specific PII (MyNumber, phone, postal)', () => {
  const text = '個人番号: 1234-5678-9018, 携帯: 090-1234-5678, 郵便番号: 〒150-0002';
  const masked = redactText(text, { mode: 'mask' });

  assert.ok(!masked.includes('1234-5678-9018'));
  assert.ok(masked.includes('****-****-9018'));
  assert.ok(!masked.includes('090-1234-5678'));
  assert.ok(masked.includes('***-****-5678'));
  assert.ok(masked.includes('***-****'));

  const replaced = redactText(text, { mode: 'replace' });
  assert.ok(replaced.includes('[REDACTED_MYNUMBER]'));
  assert.ok(replaced.includes('[REDACTED_PHONE]'));
  assert.ok(replaced.includes('[REDACTED_POSTAL]'));
});

test('auditPii evaluates privacy risk score and categorizes sensitive data', () => {
  const dangerousPayload = {
    auth: 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgN_p_v1234567890',
    card: '4532-0151-1283-0366',
    email: 'admin@system.local',
  };

  const report = auditPii(dangerousPayload);
  assert.equal(report.riskLevel, 'critical');
  assert.equal(report.hasCredentials, true);
  assert.equal(report.hasFinancials, true);
  assert.ok(report.counts.jwt >= 1);
  assert.ok(report.counts.credit_card >= 1);
  assert.ok(report.counts.email >= 1);
});

test('Custom detectors support proprietary company formats with validators', () => {
  const customEmployeeDetector = {
    type: 'employee_id',
    pattern: /\bEMP-[A-Z]{2}-\d{4}\b/g,
    validator: (match) => !match.endsWith('0000'), // Reject reserved 0000
    replacer: (match) => `EMP-**-****`,
  };

  const text = 'Staff member EMP-US-4821 and test account EMP-QA-0000 in meeting';
  const masked = redactText(text, {
    customDetectors: [customEmployeeDetector],
  });

  assert.ok(!masked.includes('EMP-US-4821'));
  assert.ok(masked.includes('EMP-**-****'));
  // Validator rejected 0000, so it remains unchanged
  assert.ok(masked.includes('EMP-QA-0000'));
});

test('createRedactorTransform streams and redacts chunks via Web Streams', async () => {
  const transform = createRedactorTransform({ mode: 'replace' });
  const writer = transform.writable.getWriter();
  const reader = transform.readable.getReader();

  const writePromise = (async () => {
    await writer.write('Log line 1: secret@corp.com\n');
    await writer.write('Log line 2: 192.168.1.1\n');
    await writer.close();
  })();

  const chunk1 = await reader.read();
  assert.ok(chunk1.value.includes('[REDACTED_EMAIL]'));

  const chunk2 = await reader.read();
  assert.ok(chunk2.value.includes('[REDACTED_IP]'));

  await writePromise;
});

test('ReDoS safety: executes in linear time even on adversarial input', () => {
  const evilString = 'a'.repeat(50_000) + '@' + 'b'.repeat(50_000);
  const start = performance.now();
  const res = redactText(evilString);
  const elapsed = performance.now() - start;

  assert.ok(typeof res === 'string');
  assert.ok(elapsed < 200, `Execution took ${elapsed}ms, should be linear under 200ms`);
});

test('pseudonymize generates consistent, one-way deterministic hashes', async () => {
  const salt = 'customer-salt-xyz';
  const id1 = await pseudonymize('user_9999', salt);
  const id2 = await pseudonymize('user_9999', salt);
  const id3 = await pseudonymize('user_8888', salt);

  assert.equal(id1, id2);
  assert.notEqual(id1, id3);
  assert.ok(id1.startsWith('pii_hash:'));
});

test('tokenize and detokenize reversibly encrypts sensitive plaintext', async () => {
  const secret = 'super-secret-master-token-key-32';
  const sensitive = '4532-0151-1283-0366';

  const token = await tokenize(secret, sensitive);
  assert.ok(token.startsWith('pii_tok_'));
  assert.ok(!token.includes(sensitive));

  const restored = await detokenize(secret, token);
  assert.equal(restored, sensitive);
});

test('Luhn and MyNumber checksum validator boundary conditions', () => {
  // Luhn length boundaries
  assert.equal(isValidLuhn('123456789012'), false); // 12 digits (too short)
  assert.equal(isValidLuhn('12345678901234567890'), false); // 20 digits (too long)

  // MyNumber length and character boundaries
  assert.equal(isValidMyNumber('12345678901'), false); // 11 digits
  assert.equal(isValidMyNumber('1234567890123'), false); // 13 digits
  assert.equal(isValidMyNumber(''), false);
});

test('redact recursively scrubs nested objects, arrays, and sensitive keys', () => {
  const payload = {
    user: 'Alice',
    password: 'super-secret-password-123',
    apiKey: 'sk-1234567890abcdef',
    details: {
      email: 'alice@example.com',
      notes: 'Call me at 090-1234-5678',
      tokens: ['ghp_123456789012345678901234567890123456', 42, null, true],
    },
    nonString: 100,
  };

  const masked = redact(payload);
  assert.equal(masked.password, '********');
  assert.equal(masked.apiKey, '********');
  assert.ok(!masked.details.email.includes('alice@example.com'));
  assert.ok(masked.details.notes.includes('***-****-5678'));
  assert.equal(masked.nonString, 100);

  // mode: replace with custom keys
  const replaced = redact(payload, {
    mode: 'replace',
    sensitiveKeys: ['apiKey', 'customSecret'],
  });
  assert.equal(replaced.apiKey, '[REDACTED_APIKEY]');

  // Primitives and empty inputs
  assert.equal(redact(null), null);
  assert.equal(redact(123), 123);
  assert.ok(redact('user@example.com').includes('@example.com'));
  assert.ok(redact(['test@example.com'])[0].includes('@example.com'));
});

test('scanPii and redactText with replace mode, IPv6, and short tokens', () => {
  // replace mode for different types
  const text = 'IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334 Postal: 100-0001 Short: ghp_1234';
  const replaced = redactText(text, { mode: 'replace' });
  assert.ok(replaced.includes('[REDACTED_POSTAL]'));
  assert.ok(replaced.includes('[REDACTED_IP]'));

  // mask mode for IPv6
  const masked = redactText('IP is 2001:0db8:85a3:0000:0000:8a2e:0370:7334');
  assert.ok(masked.includes('****:****:****:****'));

  // Custom detector with fallback replacement
  const withCustom = redactText('ID: SECRET-999', {
    mode: 'replace',
    customDetectors: [
      { type: 'secret_id', pattern: /SECRET-\d+/g },
    ],
  });
  assert.ok(withCustom.includes('[REDACTED_SECRET_ID]'));

  // Empty or non-string text
  assert.equal(redactText(''), '');
  assert.equal(redactText(null), null);
});

test('auditPii reports various risk levels: critical, high, medium, low, none', () => {
  // None
  const rNone = auditPii('Just a harmless log message.');
  assert.equal(rNone.riskLevel, 'none');
  assert.equal(rNone.total, 0);

  // High (email or phone)
  const rHigh = auditPii('Contact: user@domain.com');
  assert.equal(rHigh.riskLevel, 'high');
  assert.equal(rHigh.hasCredentials, false);
  assert.equal(rHigh.hasFinancials, false);

  // Medium (IP or postal only)
  const rMed = auditPii('Request from 192.168.1.50 and zip 100-0001');
  assert.equal(rMed.riskLevel, 'medium');

  // Low (custom detector only)
  const rLow = auditPii('Employee EMP-1234', [
    { type: 'emp_id', pattern: /EMP-\d+/g },
  ]);
  assert.equal(rLow.riskLevel, 'low');

  // Non-string input to auditPii
  const rObj = auditPii({ ip: '10.0.0.1' });
  assert.equal(rObj.riskLevel, 'medium');

  // Circular or unstringifiable object fallback
  const circular = {};
  circular.self = circular;
  const rCirc = auditPii(circular);
  assert.equal(rCirc.riskLevel, 'none');
});

test('detokenize error handling', async () => {
  await assert.rejects(() => detokenize('secret', 'invalid_prefix'), /invalid token prefix/i);
  await assert.rejects(() => detokenize('secret', 'pii_tok_onlyOnePart'), /malformed token structure/i);
});

test('masks AWS access keys and Slack API tokens', () => {
  const awsSample = 'AWS_KEY=AKIAIOSFODNN7EXAMPLE';
  const maskedAws = redactText(awsSample, { mode: 'mask' });
  assert.ok(!maskedAws.includes('AKIAIOSFODNN7EXAMPLE'));
  assert.ok(maskedAws.includes('AKIA...MPLE'));

  const slackSample = 'Token: xoxb-123456789012-abcdefghij';
  const maskedSlack = redactText(slackSample, { mode: 'mask' });
  assert.ok(!maskedSlack.includes('xoxb-123456789012-abcdefghij'));
  assert.ok(maskedSlack.includes('xoxb...ghij'));
});

test('getWebCrypto throws when crypto is unavailable', () => {
  const originalCrypto = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  try {
    Object.defineProperty(globalThis, 'crypto', { configurable: true, value: undefined });
    assert.throws(() => getWebCrypto(), /WebCrypto SubtleCrypto is not available/i);
  } finally {
    if (originalCrypto) {
      Object.defineProperty(globalThis, 'crypto', originalCrypto);
    }
  }
});
