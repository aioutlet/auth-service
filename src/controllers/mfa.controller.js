import speakeasy from 'speakeasy';
import MFA from '../models/mfa.model.js';
import asyncHandler from '../middlewares/asyncHandler.js';

// Enable MFA: generate secret and return otpauth URL
export const enableMFA = asyncHandler(async (req, res) => {
  const userId = req.user?._id;
  if (!userId) return res.status(401).json({ error: 'Authentication required' });
  const secret = speakeasy.generateSecret({ name: `AIOutlet (${req.user.email})` });
  let mfa = await MFA.findOne({ user: userId });
  if (!mfa) {
    mfa = new MFA({ user: userId, secret: secret.base32, enabled: false });
    await mfa.save();
  } else {
    mfa.secret = secret.base32;
    mfa.enabled = false;
    await mfa.save();
  }
  res.json({ otpauth_url: secret.otpauth_url, base32: secret.base32 });
});

// Verify MFA: user submits TOTP code, enable MFA if valid
export const verifyMFA = asyncHandler(async (req, res) => {
  const userId = req.user?._id;
  const { token } = req.body;
  if (!userId || !token) return res.status(400).json({ error: 'Token and authentication required' });
  const mfa = await MFA.findOne({ user: userId });
  if (!mfa) return res.status(404).json({ error: 'MFA setup not found' });
  const verified = speakeasy.totp.verify({
    secret: mfa.secret,
    encoding: 'base32',
    token,
    window: 1,
  });
  if (!verified) return res.status(400).json({ error: 'Invalid MFA code' });
  mfa.enabled = true;
  await mfa.save();
  res.json({ message: 'MFA enabled successfully' });
});

// Disable MFA
export const disableMFA = asyncHandler(async (req, res) => {
  const userId = req.user?._id;
  if (!userId) return res.status(401).json({ error: 'Authentication required' });
  const mfa = await MFA.findOne({ user: userId });
  if (!mfa || !mfa.enabled) return res.status(400).json({ error: 'MFA is not enabled' });
  mfa.enabled = false;
  await mfa.save();
  res.json({ message: 'MFA disabled successfully' });
});
