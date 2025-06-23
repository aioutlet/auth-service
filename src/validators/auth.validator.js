import logger from '../utils/logger.js';
// Input validation for auth endpoints placeholder
const authValidator = {
  validatePasswordChange(oldPassword, newPassword) {
    if (!oldPassword || !newPassword) {
      return { valid: false, error: 'Old and new password are required' };
    }
    if (oldPassword === newPassword) {
      return { valid: false, error: 'New password must be different from old password' };
    }
    return { valid: true };
  },
  isValidPassword(password) {
    if (typeof password !== 'string') {
      return { valid: false, error: 'Password must be a string' };
    }
    if (password.trim().length < 6 || password.trim().length > 25) {
      return { valid: false, error: 'Password must be between 6 and 25 characters' };
    }
    if (!/[A-Za-z]/.test(password)) {
      return { valid: false, error: 'Password must contain at least one letter' };
    }
    if (!/\d/.test(password)) {
      return { valid: false, error: 'Password must contain at least one number' };
    }
    return { valid: true };
  },
};

export default authValidator;
