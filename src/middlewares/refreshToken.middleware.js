import RefreshToken from '../models/refreshToken.model.js';

export default async function (req, res, next) {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ error: 'No refresh token provided' });
  const tokenDoc = await RefreshToken.findOne({ token: refreshToken });
  if (!tokenDoc || tokenDoc.expiresAt < new Date()) {
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }
  req.refreshTokenDoc = tokenDoc;
  next();
}
