const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const PendingSignup = require('../models/PendingSignup');
const { isValidEmail, isValidPassword } = require('../utils/validation');
const { sendOTPEmail } = require('../utils/email');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

// Generate 6-digit OTP
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Generate access token (short-lived)
const generateAccessToken = (user) => {
  return jwt.sign(
    { userId: user._id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '10m' }
  );
};

// Generate refresh token (long-lived)
const generateRefreshToken = (user) => {
  return jwt.sign(
    { userId: user._id, email: user.email },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: '7d' } // 7 days
  );
};

// POST /api/auth/login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    if (!isValidPassword(password)) {
      return res.status(400).json({ error: 'Password must be 8+ characters' });
    }

    // Find user
    const user = await User.findOne({ email: email.toLowerCase() });

    if (!user) {
      // User not found - signal to frontend to show signup alert
      return res.status(404).json({ error: 'USER_NOT_FOUND' });
    }

    // Compare password
    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);

    if (!isPasswordValid) {
      // Don't reveal which is wrong
      return res.status(401).json({ error: 'INVALID_CREDENTIALS' });
    }

    // Generate tokens
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    // Save refresh token to database
    user.refreshToken = refreshToken;
    await user.save();

    res.json({
      user: {
        id: user._id,
        email: user.email,
        fullName: user.fullName
      },
      token: accessToken,
      refreshToken: refreshToken
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/auth/start-signup
router.post('/start-signup', async (req, res) => {
  try {
    const { fullName, email, password } = req.body;

    // Validate input
    if (!fullName || !email || !password) {
      return res.status(400).json({ error: 'Full name, email and password are required' });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    if (!isValidPassword(password)) {
      return res.status(400).json({ error: 'Password must be 8+ characters' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Generate OTP
    const otp = generateOTP();
    const otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Save or update pending signup
    await PendingSignup.findOneAndUpdate(
      { email: email.toLowerCase() },
      {
        fullName: fullName.trim(),
        email: email.toLowerCase(),
        passwordHash,
        otp,
        otpExpiresAt
      },
      { upsert: true, new: true }
    );

    // Send OTP email
    try {
      await sendOTPEmail(email.toLowerCase(), otp);
    } catch (emailError) {
      console.error('Failed to send email:', emailError);
      // In development mode, we still allow signup to continue
      // The OTP will be logged to console
      if (process.env.NODE_ENV === 'production') {
        return res.status(500).json({ error: 'Failed to send OTP email' });
      }
      // In development, continue even if email fails (OTP is logged to console)
    }

    res.json({ message: 'OTP sent to email' });
  } catch (error) {
    console.error('Start signup error:', error);
    if (error.code === 11000) {
      // Duplicate key error (user already exists)
      return res.status(400).json({ error: 'User already exists' });
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/auth/verify-otp
router.post('/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ error: 'Email and OTP are required' });
    }

    // Find pending signup
    const pendingSignup = await PendingSignup.findOne({ email: email.toLowerCase() });

    if (!pendingSignup) {
      return res.status(400).json({ error: 'INVALID_OTP' });
    }

    // Check if OTP matches
    if (pendingSignup.otp !== otp) {
      return res.status(400).json({ error: 'INVALID_OTP' });
    }

    // Check if OTP is expired
    if (new Date() > pendingSignup.otpExpiresAt) {
      await PendingSignup.deleteOne({ email: email.toLowerCase() });
      return res.status(400).json({ error: 'INVALID_OTP' });
    }

    // Create user
    const user = new User({
      fullName: pendingSignup.fullName,
      email: pendingSignup.email,
      passwordHash: pendingSignup.passwordHash
    });

    // Generate tokens
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    // Save refresh token to database
    user.refreshToken = refreshToken;
    await user.save();

    // Delete pending signup
    await PendingSignup.deleteOne({ email: email.toLowerCase() });

    res.json({
      user: {
        id: user._id,
        email: user.email,
        fullName: user.fullName
      },
      token: accessToken,
      refreshToken: refreshToken
    });
  } catch (error) {
    console.error('Verify OTP error:', error);
    if (error.code === 11000) {
      // Duplicate key error (user already exists)
      return res.status(400).json({ error: 'User already exists' });
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/auth/refresh
router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(401).json({ error: 'Refresh token is required' });
    }

    // Verify refresh token
    let decoded;
    try {
      decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    } catch (error) {
      return res.status(401).json({ error: 'Invalid or expired refresh token' });
    }

    // Find user and verify refresh token matches
    const user = await User.findById(decoded.userId);
    if (!user || user.refreshToken !== refreshToken) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }

    // Generate new access token
    const accessToken = generateAccessToken(user);

    res.json({
      token: accessToken
    });
  } catch (error) {
    console.error('Refresh token error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/auth/logout
router.post('/logout', authenticateToken, async (req, res) => {
  try {
    // Clear refresh token from database
    req.user.refreshToken = null;
    await req.user.save();

    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/auth/me
router.get('/me', authenticateToken, async (req, res) => {
  try {
    res.json({
      user: {
        id: req.user._id,
        email: req.user.email,
        fullName: req.user.fullName
      }
    });
  } catch (error) {
    console.error('Get me error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;

