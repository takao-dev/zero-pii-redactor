# zero-pii-redactor

High-speed, ReDoS-free PII (Personally Identifiable Information) redactor, tokenizer, and pseudonymizer for logs, AI prompts, telemetry, and Edge runtimes. Built with native WebCrypto and zero runtime dependencies.

[![npm version](https://img.shields.io/npm/v/zero-pii-redactor.svg)](https://www.npmjs.com/package/zero-pii-redactor)
[![CI](https://github.com/takao-dev/zero-pii-redactor/actions/workflows/ci.yml/badge.svg)](https://github.com/takao-dev/zero-pii-redactor/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/takao-dev/zero-pii-redactor/branch/main/graph/badge.svg)](https://codecov.io/gh/takao-dev/zero-pii-redactor)
[![CodeQL](https://github.com/takao-dev/zero-pii-redactor/actions/workflows/codeql.yml/badge.svg)](https://github.com/takao-dev/zero-pii-redactor/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)]()
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)]()

---

## Features

- **ReDoS-Free & Bounded $O(N)$ Scanning**: Eliminates catastrophic regex backtracking vulnerabilities by enforcing RFC-bounded linear state machines.
- **Luhn Algorithm Validation**: Verifies credit card numbers via Modulo-10 checksum to eliminate false positives on arbitrary sequences of digits.
- **Deep JSON & Object Sanitization**: Recursively scrubs nested payloads, strings, and sensitive dictionary keys (`password`, `apiKey`, `secret`, `ssn`, etc.).
- **Multiple Redaction Modes**:
  - `'mask'`: Partial character masking (e.g., `a***e@corp.com`, `4***-****-****-0366`).
  - `'replace'`: Replaces matches with semantic tokens (`[REDACTED_EMAIL]`, `[REDACTED_CREDIT_CARD]`).
  - `'pseudonymize'`: Salted deterministic SHA-256 hash for correlation analysis without leaking plaintext.
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
const hash = await pseudonymize('user_12345', 'secret-salt');
// "pii_hash:7f83b165..."

// Reversible encryption
const token = await tokenize('master-key-32-chars-long!!!!!!!!', 'Sensitive Social Security Number');
// "pii_tok_6a1f..._3c8e..."

const original = await detokenize('master-key-32-chars-long!!!!!!!!', token);
// "Sensitive Social Security Number"
```

---

## License

MIT License.
