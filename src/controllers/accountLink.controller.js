import asyncHandler from '../middlewares/asyncHandler.js';
import { getUserByEmail, getUserBySocial } from '../services/userServiceClient.js';

export const linkAccount = asyncHandler(async (req, res) => {
  const { provider, id } = req.body;
  const userId = req.user?._id;
  if (!userId || !provider || !id) {
    return res.status(400).json({ error: 'Provider, id, and authentication required' });
  }
  // Check if provider is already linked to another user
  const existing = await getUserBySocial(provider, id);
  if (existing && existing._id !== userId) {
    return res.status(409).json({ error: 'This provider is already linked to another account' });
  }
  // Patch user in user service to add provider
  const resp = await fetch(`${process.env.USER_SERVICE_URL}/users/${userId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ [`social.${provider}`]: { id } }),
  });
  if (!resp.ok) {
    const err = await resp.json();
    return res.status(resp.status).json(err);
  }
  res.json({ message: 'Provider linked successfully' });
});

export const unlinkAccount = asyncHandler(async (req, res) => {
  const { provider } = req.body;
  const userId = req.user?._id;
  if (!userId || !provider) {
    return res.status(400).json({ error: 'Provider and authentication required' });
  }
  // Patch user in user service to remove provider
  const resp = await fetch(`${process.env.USER_SERVICE_URL}/users/${userId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ [`social.${provider}`]: null }),
  });
  if (!resp.ok) {
    const err = await resp.json();
    return res.status(resp.status).json(err);
  }
  res.json({ message: 'Provider unlinked successfully' });
});

export const listLinkedProviders = asyncHandler(async (req, res) => {
  const userId = req.user?._id;
  if (!userId) return res.status(401).json({ error: 'Authentication required' });
  const user = await getUserByEmail(req.user.email);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ linked: user.social || {} });
});
