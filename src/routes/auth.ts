// src/routes/auth.ts
import express from 'express';
import passport from 'passport';
<<<<<<< Updated upstream
import jwt from 'jsonwebtoken';
import { register, login, getCurrentUser } from '../controllers/auth';
import { forgotPassword, verifyResetToken, resetPassword } from '../controllers/auth';  // เพิ่มการ import controllers สำหรับระบบรีเซ็ตรหัสผ่าน
=======
import { 
  register,
  login,
  getCurrentUser,
  forgotPassword,
  verifyResetToken,
  resetPassword,
  verifyOTP,
  toggleTwoFactor,
  verifyTempToken
} from '../controllers/auth';
>>>>>>> Stashed changes
import { authenticateUser } from '../middleware/auth';
import { CONFIG } from '../config/env';
import { generateToken } from '../utils/jwt';

const router = express.Router();
<<<<<<< Updated upstream
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
=======
const FRONTEND_URL = CONFIG.FRONTEND_URL;
>>>>>>> Stashed changes

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
<<<<<<< Updated upstream
  passport.authenticate('google', { session: false, failureRedirect: `${FRONTEND_URL}/login?error=google_failed` }),
  (req, res) => {
    // สร้าง JWT token
    const token = generateToken(req.user);
    
    // ส่งกลับไปยัง frontend พร้อม token
    res.redirect(`${FRONTEND_URL}/oauth-callback?token=${token}`);
=======
  (req, res, next) => {
    passport.authenticate('google', { session: false }, (err, user, info) => {
      // จัดการกรณีที่มีข้อผิดพลาด
      if (err) {
        console.error('❌ Google auth error:', err);
        return res.redirect(`${FRONTEND_URL}/auth/login?error=google_failed`);
      }
      
      // กรณีที่ไม่มี user (เช่น อีเมลนี้มีบัญชี local อยู่แล้ว)
      if (!user) {
        if (info && info.errorCode === 'EMAIL_EXISTS_AS_LOCAL') {
          // มีอีเมลนี้ในระบบแบบ local account แล้ว
          return res.redirect(`${FRONTEND_URL}/auth/login?error=email_exists&email=${encodeURIComponent(info.email)}`);
        }
        
        return res.redirect(`${FRONTEND_URL}/auth/login?error=google_failed`);
      }
      
      // สร้าง JWT token (กำหนด rememberMe เป็น true เพื่อให้ token มีอายุยาวนาน)
      const token = generateToken(user, true);
      
      // ส่งกลับไปยัง frontend พร้อม token
      res.redirect(`${FRONTEND_URL}/oauth-callback?token=${token}`);
    })(req, res, next);
>>>>>>> Stashed changes
  }
);

export default router;