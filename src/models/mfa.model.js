import mongoose from 'mongoose';

const mfaSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    secret: {
      type: String,
      required: true,
    },
    enabled: {
      type: Boolean,
      default: false,
    },
    recoveryCodes: [String],
  },
  { timestamps: true }
);

const MFA = mongoose.model('MFA', mfaSchema);
export default MFA;
