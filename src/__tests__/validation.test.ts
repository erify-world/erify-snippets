import { validateEmail, validatePassword } from '../validation';

describe('ERIFY™ Validation', () => {
  describe('validateEmail', () => {
    it('should validate a correct email', () => {
      const result = validateEmail('user@example.com');
      expect(result.isValid).toBe(true);
      expect(result.errors).toHaveLength(0);
      expect(result.data).toBe('user@example.com');
    });

    it('should reject an invalid email', () => {
      const result = validateEmail('invalid-email');
      expect(result.isValid).toBe(false);
      expect(result.errors).toHaveLength(1);
      expect(result.data).toBeUndefined();
    });
  });

  describe('validatePassword', () => {
    it('should validate a strong password', () => {
      const result = validatePassword('SecurePass123!');
      expect(result.isValid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should reject a weak password', () => {
      const result = validatePassword('weak');
      expect(result.isValid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });
  });
});