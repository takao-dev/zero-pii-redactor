import test from 'node:test';
import assert from 'node:assert/strict';
import {
  redactText,
  redact,
  isValidLuhn,
  pseudonymize,
  tokenize,
  detokenize,
} from '../dist/index.js';

test('Luhn validator verifies standard card numbers and rejects non-cards', () => {
  // Standard test card numbers
  assert.equal(isValidLuhn('4532015112830366'), true); // Visa
  assert.equal(isValidLuhn('4532-0151-1283-0366'), true);
  // Invalid checksum
  assert.equal(isValidLuhn('4532015112830367'), false);
  // Random numbers not passing Luhn
  assert.equal(isValidLuhn('1234567890123456'), false);
});

test('redactText masks emails, tokens, and credit cards', () => {
  const sample =
    'Contact user@example.com with key AKIAIOSFODNN7EXAMPLE and card 4532-0151-1283-0366 at IP 192.168.1.50';

  const masked = redactText(sample, { mode: 'mask' });
  assert.ok(!masked.includes('user@example.com'));
  assert.ok(masked.includes('@example.com'));
  assert.ok(!masked.includes('AKIAIOSFODNN7EXAMPLE'));
  assert.ok(!masked.includes('4532-0151-1283-0366'));
  assert.ok(masked.includes('4***-****-****-0366'));
  assert.ok(masked.includes('192.168.*.*'));

  const replaced = redactText(sample, { mode: 'replace' });
  assert.ok(replaced.includes('[REDACTED_EMAIL]'));
  assert.ok(replaced.includes('[REDACTED_AWS_KEY]'));
  assert.ok(replaced.includes('[REDACTED_CREDIT_CARD]'));
  assert.ok(replaced.includes('[REDACTED_IP]'));
});

test('redact deep recurses JSON objects and arrays, protecting sensitive keys', () => {
  const input = {
    user: {
      name: 'Alice',
      email: 'alice@corp.com',
      password: 'PlaintextSuperSecret123!',
      nested: {
        apiKey: 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
        active: true,
      },
    },
    logs: [
      'Failed login for bob@test.org from 10.0.0.1',
      { card_number: '4532015112830366' },
    ],
  };

  const sanitized = redact(input, { mode: 'mask' });

  // Value redactions
  assert.ok(!sanitized.user.email.includes('alice@corp.com'));
  assert.equal(sanitized.user.password, '********');
  assert.equal(sanitized.user.nested.apiKey, '********');
  assert.ok(sanitized.logs[0].includes('@test.org'));
  assert.ok(!sanitized.logs[0].includes('bob@test.org'));
  assert.equal(sanitized.logs[1].card_number, '********');
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
