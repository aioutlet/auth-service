const authValidator = {
  /**
   * Validate registration data - minimal validation only
   * Auth service acts as a proxy; User service owns all business validation
   * @param {Object} data - Registration data
   * @param {string} data.email - User email
   * @param {string} data.password - User password
   * @param {string} data.firstName - User first name
   * @param {string} data.lastName - User last name
   * @returns {Object} Validation result { valid: boolean, error?: string }
   */
  validateRegistration({ email, password, firstName, lastName }) {
    // Only check that required fields are present
    // User service will handle all format/business validation
    if (!email || !password) {
      return { valid: false, error: 'Email and password are required' };
    }

    if (!firstName || !lastName) {
      return { valid: false, error: 'First name and last name are required' };
    }

    return { valid: true };
  },

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
