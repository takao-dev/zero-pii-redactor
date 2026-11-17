# zero-pii-redactor

High-speed PII (Personally Identifiable Information) redactor, tokenizer, and pseudonymizer for logs, AI prompts, telemetry, and Edge runtimes. Built with native WebCrypto and zero runtime dependencies.

## Token and pseudonym compatibility

- Reversible tokens now use the `pii_tok_v2_` format and HKDF-SHA-256. This version rejects older tokens. If old tokens must be retained, detokenize and re-tokenize them with the older trusted version in a controlled migration; token secrets must contain at least 32 UTF-8 bytes.
- Pseudonymization now uses domain-separated HMAC-SHA-256. Existing pseudonym values will change and cannot be migrated without the original identifiers and salt; plan any downstream joins or analytics accordingly.

[![npm version](https://img.shields.io/npm/v/zero-pii-redactor.svg)](https://www.npmjs.com/package/zero-pii-redactor)
[![npm downloads](https://img.shields.io/npm/dw/zero-pii-redactor.svg)](https://www.npmjs.com/package/zero-pii-redactor)
[![CI](https://github.com/takao-dev/zero-pii-redactor/actions/workflows/ci.yml/badge.svg)](https://github.com/takao-dev/zero-pii-redactor/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/takao-dev/zero-pii-redactor/branch/main/graph/badge.svg)](https://codecov.io/gh/takao-dev/zero-pii-redactor)
[![CodeQL](https://github.com/takao-dev/zero-pii-redactor/actions/workflows/codeql.yml/badge.svg)](https://github.com/takao-dev/zero-pii-redactor/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)]()
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)]()

---

## Features

- **Bounded Built-in Scanning**: Built-in detectors use bounded patterns and reject input over 1 MiB. Custom detector regular expressions are caller-controlled code and must be trusted; JavaScript cannot interrupt a catastrophic custom expression.
- **Luhn Algorithm Validation**: Verifies credit card numbers via Modulo-10 checksum to eliminate false positives on arbitrary sequences of digits.
- **Deep JSON & Object Sanitization**: Recursively scrubs nested payloads, strings, and sensitive dictionary keys (`password`, `apiKey`, `secret`, `ssn`, etc.).
- **Multiple Redaction Modes**:
  - `'mask'`: Partial character masking (e.g., `a***e@corp.com`, `4***-****-****-0366`).
  - `'replace'`: Replaces matches with semantic tokens (`[REDACTED_EMAIL]`, `[REDACTED_CREDIT_CARD]`).
  - `'pseudonymize'`: Keyed HMAC-SHA-256 pseudonym for correlation analysis without leaking plaintext.
- **Reversible AES-GCM Tokenizer**: Safely tokenize sensitive strings into `pii_tok_...` tokens and restore them when authorized.
- **Zero Runtime Dependencies**: Pure TypeScript/JavaScript with zero third-party dependencies.

---

## Installation

```bash
npm install zero-pii-redactor
```

---

## Usage

### 1. Plain Text Redaction

```typescript
import { redactText } from 'zero-pii-redactor';

const log = 'User alice@example.com paid with card 4532-0151-1283-0366 from IP 192.168.1.1';

// Masking
console.log(redactText(log, { mode: 'mask' }));
// "User a***e@example.com paid with card 4***-****-****-0366 from IP 192.168.*.*"

// Replacing with tokens
console.log(redactText(log, { mode: 'replace' }));
// "User [REDACTED_EMAIL] paid with card [REDACTED_CREDIT_CARD] from IP [REDACTED_IP]"
```

### 2. Deep Object & JSON Sanitization

```typescript
import { redact } from 'zero-pii-redactor';

const payload = {
  user: {
    email: 'bob@company.org',
    password: 'SuperSecretPassword123!',
  },
  tokens: ['ghp_1234567890abcdefghijklmnopqrstuvwxyz'],
};

const clean = redact(payload);
// {
//   user: {
//     email: 'b*b@company.org',
//     password: '********'
//   },
//   tokens: ['ghp_...wxyz']
// }
```

### 3. Pseudonymization & Reversible Tokenization

```typescript
import { pseudonymize, tokenize, detokenize } from 'zero-pii-redactor';

// One-way correlation hash
const hash = await pseudonymize('user_12345', 'customer-daily-rotation-salt');
// "pii_hash:7f83b165..."

// Reversible encryption
const token = await tokenize('master-key-32-chars-long!!!!!!!!', 'Sensitive Social Security Number');
// "pii_tok_6a1f..._3c8e..."

const original = await detokenize('master-key-32-chars-long!!!!!!!!', token);
// "Sensitive Social Security Number"
```

---

## Related Edge Security Packages

Complementary zero-dependency, high-performance security modules for Edge runtimes, Cloudflare Workers, and modern Node.js:

- [wasm-crypto-hash](https://github.com/takao-dev/wasm-crypto-hash): Ultra-fast WebAssembly & WebCrypto cryptographic suite (SHA-2/3, BLAKE3, PQC, Argon2, TOTP, BIP-39).
- [edge-rate-limiter](https://github.com/takao-dev/edge-rate-limiter): Zero-dependency sliding-window & token-bucket rate limiter with Zero-PII keyed hashing.
- [edge-secure-token](https://github.com/takao-dev/edge-secure-token): Zero-dependency, timing-safe WebCrypto JWT suite with field-level claims encryption.
- [edge-session-crypto](https://github.com/takao-dev/edge-session-crypto): Stateless encrypted cookie session manager with AES-GCM and key rotation.
- [webcrypto-secure-storage](https://github.com/takao-dev/webcrypto-secure-storage): Tamper-evident authenticated key-value storage with AES-GCM & HMAC.
- [edge-audit-crypto](https://github.com/takao-dev/edge-audit-crypto): Tamper-evident cryptographic append-only audit trail logging.

---

## License

MIT License.
