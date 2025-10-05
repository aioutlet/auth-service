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

    const trimmedPassword = password.trim();

    // Check length first (most specific errors)
    if (trimmedPassword.length < 6 || trimmedPassword.length > 25) {
      return { valid: false, error: 'Password must be between 6 and 25 characters' };
    }

    // Check for at least one letter
    if (!/[A-Za-z]/.test(password)) {
      return { valid: false, error: 'Password must contain at least one letter' };
    }

    // Check for at least one number
    if (!/\d/.test(password)) {
      return { valid: false, error: 'Password must contain at least one number' };
    }

    return { valid: true };
  },
};

export default authValidator;
