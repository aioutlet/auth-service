import { invokeService } from './dapr.service.client.js';
import logger from '../core/logger.js';

const DAPR_USER_SERVICE_APP_ID = process.env.DAPR_USER_SERVICE_APP_ID || 'user-service';

export async function getUserByEmail(email) {
  try {
    const response = await invokeService(
      DAPR_USER_SERVICE_APP_ID,
      `api/users/findByEmail?email=${encodeURIComponent(email)}`,
      'GET'
    );
    return response;
  } catch (error) {
    // If 404, user not found - return null
    if (error.message?.includes('404')) {
      return null;
    }
    logger.warn('getUserByEmail failed', null, { error: error.message, email });
    return null;
  }
}

export async function createUser(userData) {
  try {
    const response = await invokeService(DAPR_USER_SERVICE_APP_ID, 'api/users', 'POST', userData);
    return response;
  } catch (error) {
    logger.error('createUser error', null, {
      error: error.message,
      userData: { ...userData, password: '[REDACTED]' },
    });

    // Extract error message
    const errorMessage = error.message || 'Failed to create user';
    const statusCode = error.message?.includes('409') ? 409 : error.message?.includes('400') ? 400 : 503;

    // Throw error with details so controller can handle it
    const err = new Error(errorMessage);
    err.statusCode = statusCode;
    err.details = error;
    throw err;
  }
}

export async function deleteUserSelf(token) {
  try {
    await invokeService(DAPR_USER_SERVICE_APP_ID, 'api/users', 'DELETE', null, {
      headers: { Authorization: `Bearer ${token}` },
    });
    return true;
  } catch (error) {
    logger.error('deleteUserSelf error', null, { error: error.message });
    return false;
  }
}

export async function deleteUserById(id, token) {
  try {
    await invokeService(DAPR_USER_SERVICE_APP_ID, `api/users/${id}`, 'DELETE', null, {
      headers: { Authorization: `Bearer ${token}` },
    });
    return true;
  } catch (error) {
    logger.error('deleteUserById error', null, { error: error.message, userId: id });
    return false;
  }
}

export async function getUserById(id, token) {
  try {
    const response = await invokeService(DAPR_USER_SERVICE_APP_ID, `api/admin/users/${id}`, 'GET', null, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    return response;
  } catch (error) {
    logger.warn('getUserById failed', null, { error: error.message, userId: id });
    return null;
  }
}

export default {
  getUserByEmail,
  createUser,
  deleteUserSelf,
  deleteUserById,
  getUserById,
};
