import authValidator from '../../../src/validators/auth.validator.js';

describe('authValidator', () => {
  describe('validatePasswordChange', () => {
    it('should validate successful password change', () => {
      const result = authValidator.validatePasswordChange('oldPassword123', 'newPassword456');

      expect(result.valid).toBe(true);
    });

    it('should reject missing old password', () => {
      const result = authValidator.validatePasswordChange('', 'newPassword456');

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Old and new password are required');
    });

    it('should reject missing new password', () => {
      const result = authValidator.validatePasswordChange('oldPassword123', '');

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Old and new password are required');
    });

    it('should reject both passwords missing', () => {
      const result = authValidator.validatePasswordChange('', '');

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Old and new password are required');
    });

    it('should reject null old password', () => {
      const result = authValidator.validatePasswordChange(null, 'newPassword456');

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Old and new password are required');
    });

    it('should reject null new password', () => {
      const result = authValidator.validatePasswordChange('oldPassword123', null);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Old and new password are required');
    });

    it('should reject undefined passwords', () => {
      const result = authValidator.validatePasswordChange(undefined, undefined);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Old and new password are required');
    });

    it('should reject when old and new passwords are the same', () => {
      const samePassword = 'password123';
      const result = authValidator.validatePasswordChange(samePassword, samePassword);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('New password must be different from old password');
    });

    it('should handle whitespace-only passwords as valid since they have length', () => {
      const result = authValidator.validatePasswordChange('   ', 'newPassword456');

      // The validator only checks for falsy values, not whitespace
      expect(result.valid).toBe(true);
    });
  });

  describe('isValidPassword', () => {
    describe('valid passwords', () => {
      it('should accept password with letters and numbers', () => {
        const result = authValidator.isValidPassword('password123');

        expect(result.valid).toBe(true);
      });

      it('should accept password with uppercase, lowercase, and numbers', () => {
        const result = authValidator.isValidPassword('Password123');

        expect(result.valid).toBe(true);
      });

      it('should accept password with special characters', () => {
        const result = authValidator.isValidPassword('Pass123!@#');

        expect(result.valid).toBe(true);
      });

      it('should accept minimum length password (6 chars)', () => {
        const result = authValidator.isValidPassword('abc123');

        expect(result.valid).toBe(true);
      });

      it('should accept maximum length password (25 chars)', () => {
        const result = authValidator.isValidPassword('a1bcdefghijklmnopqrstuvwx'); // 25 chars

        expect(result.valid).toBe(true);
      });
    });

    describe('invalid passwords', () => {
      it('should reject non-string password', () => {
        const result = authValidator.isValidPassword(123);

        expect(result.valid).toBe(false);
        expect(result.error).toBe('Password must be a string');
      });

      it('should reject null password', () => {
        const result = authValidator.isValidPassword(null);

        expect(result.valid).toBe(false);
        expect(result.error).toBe('Password must be a string');
      });

      it('should reject undefined password', () => {
        const result = authValidator.isValidPassword(undefined);

        expect(result.valid).toBe(false);
        expect(result.error).toBe('Password must be a string');
      });

      it('should reject array password', () => {
        const result = authValidator.isValidPassword(['password', '123']);

        expect(result.valid).toBe(false);
        expect(result.error).toBe('Password must be a string');
      });

      it('should reject object password', () => {
        const result = authValidator.isValidPassword({ password: 'test123' });

        expect(result.valid).toBe(false);
        expect(result.error).toBe('Password must be a string');
      });

      it('should reject too short password (5 chars)', () => {
        const result = authValidator.isValidPassword('abc12');

        expect(result.valid).toBe(false);
        expect(result.error).toBe('Password must be between 6 and 25 characters');
      });

      it('should reject too long password (26 chars)', () => {
        const result = authValidator.isValidPassword('a1bcdefghijklmnopqrstuvwxy'); // 26 chars

        expect(result.valid).toBe(false);
        expect(result.error).toBe('Password must be between 6 and 25 characters');
      });

      it('should reject empty string', () => {
        const result = authValidator.isValidPassword('');

        expect(result.valid).toBe(false);
        expect(result.error).toBe('Password must be between 6 and 25 characters');
      });

      it('should reject whitespace-only password', () => {
        const result = authValidator.isValidPassword('      '); // 6 spaces

        expect(result.valid).toBe(false);
        expect(result.error).toBe('Password must be between 6 and 25 characters');
      });

      it('should reject password without letters', () => {
        const result = authValidator.isValidPassword('123456');

        expect(result.valid).toBe(false);
        expect(result.error).toBe('Password must contain at least one letter');
      });

      it('should reject password with only special characters and numbers', () => {
        const result = authValidator.isValidPassword('123!@#');

        expect(result.valid).toBe(false);
        expect(result.error).toBe('Password must contain at least one letter');
      });

      it('should reject password without numbers', () => {
        const result = authValidator.isValidPassword('password');

        expect(result.valid).toBe(false);
        expect(result.error).toBe('Password must contain at least one number');
      });

      it('should reject password with only letters and special characters', () => {
        const result = authValidator.isValidPassword('pass!@#');

        expect(result.valid).toBe(false);
        expect(result.error).toBe('Password must contain at least one number');
      });
    });

    describe('edge cases', () => {
      it('should handle password with leading/trailing whitespace', () => {
        const result = authValidator.isValidPassword('  pass123  ');

        // Should trim and validate the trimmed length
        expect(result.valid).toBe(true);
      });

      it('should reject password that becomes too short after trimming', () => {
        const result = authValidator.isValidPassword('  ab1  '); // Only 3 chars after trim

        expect(result.valid).toBe(false);
        expect(result.error).toBe('Password must be between 6 and 25 characters');
      });

      it('should handle unicode characters', () => {
        const result = authValidator.isValidPassword('páss123');

        expect(result.valid).toBe(true);
      });

      it('should handle numbers in different positions', () => {
        const results = [
          authValidator.isValidPassword('1password'),
          authValidator.isValidPassword('pass1word'),
          authValidator.isValidPassword('password1'),
        ];

        results.forEach((result) => {
          expect(result.valid).toBe(true);
        });
      });

      it('should handle letters in different positions', () => {
        const results = [
          authValidator.isValidPassword('a123456'),
          authValidator.isValidPassword('123a456'),
          authValidator.isValidPassword('123456a'),
        ];

        results.forEach((result) => {
          expect(result.valid).toBe(true);
        });
      });
    });
  });
});
