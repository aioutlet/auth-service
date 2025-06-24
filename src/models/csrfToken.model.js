import mongoose from 'mongoose';

const csrfTokenSchema = new mongoose.Schema({
  token: { type: String, required: true, unique: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  expiresAt: { type: Date, required: true },
});

export default mongoose.model('CsrfToken', csrfTokenSchema);
