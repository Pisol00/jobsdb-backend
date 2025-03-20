import express from 'express';
import passport from 'passport';
import jwt from 'jsonwebtoken';
import { register, login, getCurrentUser } from '../controllers/auth';
import { forgotPassword, verifyResetToken, resetPassword } from '../controllers/auth';  // เพิ่มการ import controllers สำหรับระบบรีเซ็ตรหัสผ่าน
import { authenticateUser } from '../middleware/auth';

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const JWT_LIFETIME = process.env.JWT_LIFETIME || '1d';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

// Helper function to generate JWT
const generateToken = (user: any) => {
  // @ts-ignore - เพื่อแก้ไขปัญหา TypeScript กับ jwt.sign
  return jwt.sign(
    { id: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: JWT_LIFETIME }
  );
};

// Local auth routes
router.post('/register', register);
router.post('/login', login);
router.get('/me', authenticateUser, getCurrentUser);

// Password reset routes
router.post('/forgot-password', forgotPassword);
router.post('/verify-reset-token', verifyResetToken);
router.post('/reset-password', resetPassword);

// Google OAuth routes
router.get(
  '/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

router.get(
  '/google/callback',
  passport.authenticate('google', { session: false, failureRedirect: `${FRONTEND_URL}/login?error=google_failed` }),
  (req, res) => {
    // สร้าง JWT token
    const token = generateToken(req.user);
    
    // ส่งกลับไปยัง frontend พร้อม token
    res.redirect(`${FRONTEND_URL}/oauth-callback?token=${token}`);
  }
);

export default router;