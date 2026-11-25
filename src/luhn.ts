/**
 * Mathematical checksum validators for financial and identity numbers.
 * JavaScript execution is not guaranteed to be constant-time.
 */

/**
 * Luhn algorithm (mod 10) validator for credit card numbers.
 */
export function isValidLuhn(digits: string): boolean {
  const sanitized = digits.replace(/\D/g, '');
  if (sanitized.length < 13 || sanitized.length > 19) {
    return false;
  }

  let sum = 0;
  let alternate = false;

  for (let i = sanitized.length - 1; i >= 0; i--) {
    let digit = sanitized.charCodeAt(i) - 48; // '0' is 48
    if (digit < 0 || digit > 9) return false;

    if (alternate) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }

    sum += digit;
    alternate = !alternate;
  }

  return sum % 10 === 0;
}

/**
 * Japan MyNumber (Individual Number - 12 digits) Modulo 11 check digit validator.
 * Per Japanese Ministry of Internal Affairs and Communications ordinance.
 */
export function isValidMyNumber(digits: string): boolean {
  const sanitized = digits.replace(/\D/g, '');
  if (sanitized.length !== 12) {
    return false;
  }

  let sum = 0;
  // Position n: from right to left (1 to 11, where 1 is the check digit)
  // Digits: d12, d11, ..., d2, d1
  const checkDigit = sanitized.charCodeAt(11) - 48;

  for (let n = 1; n <= 11; n++) {
    const digit = sanitized.charCodeAt(11 - n) - 48;
    if (digit < 0 || digit > 9) return false;

    const q = n <= 6 ? n + 1 : n - 5;
    sum += digit * q;
  }

  const remainder = sum % 11;
  const expectedCheckDigit = remainder <= 1 ? 0 : 11 - remainder;

  return checkDigit === expectedCheckDigit;
}
