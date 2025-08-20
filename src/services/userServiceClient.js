import dotenv from 'dotenv';
import logger from '../utils/logger.js';

dotenv.config();

const USER_SERVICE_URL = process.env.USER_SERVICE_URL; // e.g. http://localhost:5000/users

export async function getUserByEmail(email) {
  const url = `${USER_SERVICE_URL}/findByEmail?email=${encodeURIComponent(email)}`;
  const res = await fetch(url);
  if (!res.ok) return null;
  return await res.json();
}

export async function getUserBySocial(provider, id) {
  const url = `${USER_SERVICE_URL}/findBySocial?provider=${provider}&id=${id}`;
  const res = await fetch(url);
  if (!res.ok) {
    const text = await res.text();
    logger.error('getUserBySocial error', { status: res.status, text });
    return null;
  }
  return await res.json();
}

export async function createUser(userData) {
  const url = `${USER_SERVICE_URL}`; // POST to /users
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(userData),
  });
  if (!res.ok) {
    const text = await res.text();
    logger.error('createUser error', { status: res.status, text });
    return null;
  }
  return await res.json();
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
  if (!res.ok) return null;
  return await res.json();
}
