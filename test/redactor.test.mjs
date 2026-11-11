import test from 'node:test';
import assert from 'node:assert/strict';
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
