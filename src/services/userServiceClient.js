import logger from '../observability/logging/index.js';

const USER_SERVICE_URL = process.env.USER_SERVICE_URL; // e.g. http://localhost:5000/users

export async function getUserByEmail(email) {
  const url = `${USER_SERVICE_URL}/findByEmail?email=${encodeURIComponent(email)}`;
  const res = await fetch(url);
  if (!res.ok) {
    return null;
  }
  return await res.json();
}

export async function createUser(userData) {
  const url = `${USER_SERVICE_URL}`; // POST to /users
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(userData),
    });

    if (!res.ok) {
      let errorDetails;
      try {
        errorDetails = await res.json();
      } catch {
        errorDetails = { error: await res.text() };
      }

      logger.error('createUser error', {
        status: res.status,
        url,
        errorDetails,
        userData: { ...userData, password: '[REDACTED]' },
      });

      // Throw error with details so controller can handle it
      const error = new Error(errorDetails.error || errorDetails.message || 'Failed to create user');
      error.statusCode = res.status;
      error.details = errorDetails;
      throw error;
    }

    return await res.json();
  } catch (error) {
    // If it's already our error, rethrow it
    if (error.statusCode) {
      throw error;
    }

    // Otherwise, it's a network/timeout error
    logger.error('createUser network error', {
      error: error.message,
      url,
      userData: { ...userData, password: '[REDACTED]' },
    });

    const netError = new Error(`User service unavailable: ${error.message}`);
    netError.statusCode = 503;
    netError.originalError = error;
    throw netError;
  }
}

export async function deleteUserSelf(token) {
  const res = await fetch(`${USER_SERVICE_URL}`, {
    method: 'DELETE',
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
  return res.status === 204;
}

export async function deleteUserById(id, token) {
  const res = await fetch(`${USER_SERVICE_URL}/${id}`, {
    method: 'DELETE',
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
  return res.status === 204;
}

export async function getUserById(id, token) {
  // Use the admin route for internal/service-to-service lookups
  const url = `${USER_SERVICE_URL.replace(/\/users$/, '')}/admin/users/${id}`;
  const headers = token ? { Authorization: `Bearer ${token}` } : {};
  const res = await fetch(url, { headers });
  if (!res.ok) {
    return null;
  }
  return await res.json();
}
