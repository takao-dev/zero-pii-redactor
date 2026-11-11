/**
 * Luhn algorithm (mod 10) validator for credit card numbers.
 * Constant-time and zero-allocation.
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
