const mongoose = require('mongoose');

const pendingSignupSchema = new mongoose.Schema({
  fullName: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  passwordHash: {
    type: String,
    required: true
  },
  otp: {
    type: String,
    required: true
  },
  otpExpiresAt: {
    type: Date,
    required: true
  }
}, {
  timestamps: true
});

// Index to auto-delete expired documents (optional, can be handled in code)
pendingSignupSchema.index({ otpExpiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('PendingSignup', pendingSignupSchema);

