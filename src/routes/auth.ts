// src/routes/auth.ts
import express from 'express';
import passport from 'passport';
import { 
  register,
  login,
  getCurrentUser,
  forgotPassword,
  verifyResetToken,
  resetPassword,
  verifyOTP,
  toggleTwoFactor,
  verifyTempToken,
  verifyEmailToken,
  verifyEmailWithOTP,
  resendEmailVerification
} from '../controllers/auth';
import { authenticateUser } from '../middleware/auth';
import { CONFIG } from '../config/env';
import { generateToken } from '../utils/jwt';
import { resetFailedLoginAttempts } from '../utils/security'; // เพิ่มการนำเข้าฟังก์ชัน

const router = express.Router();
const FRONTEND_URL = CONFIG.FRONTEND_URL;

// Local auth routes
router.post('/register', register);
router.post('/login', login);
router.get('/me', authenticateUser, getCurrentUser);

// Password reset routes
router.post('/forgot-password', forgotPassword);
router.post('/verify-reset-token', verifyResetToken);
router.post('/reset-password', resetPassword);

// 2FA routes
router.post('/verify-otp', verifyOTP);
router.post('/toggle-two-factor', authenticateUser, toggleTwoFactor);
router.post('/verify-temp-token', verifyTempToken);

// Email verification routes
router.post('/verify-email-token', verifyEmailToken);
router.post('/verify-email', verifyEmailWithOTP);
router.post('/resend-email-verification', resendEmailVerification);

// Google OAuth routes
router.get(
  '/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

router.get(
  '/google/callback',
  (req, res, next) => {
    passport.authenticate('google', { session: false }, async (err, user, info) => {
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
      
      try {
        // รีเซ็ตการนับความพยายามล็อกอินที่ล้มเหลว เมื่อล็อกอินผ่าน OAuth สำเร็จ
        await resetFailedLoginAttempts(
          user.email,
          req.ip || req.socket.remoteAddress || 'unknown',
          req.headers['user-agent'] || 'oauth-login'
        );

        // สร้าง JWT token (กำหนด rememberMe เป็น true เพื่อให้ token มีอายุยาวนาน)
        const token = generateToken(user, true);
        
        // ส่งกลับไปยัง frontend พร้อม token
        res.redirect(`${FRONTEND_URL}/oauth-callback/${token}`);
      } catch (error) {
        console.error('❌ Error in OAuth callback:', error);
        res.redirect(`${FRONTEND_URL}/auth/login?error=google_failed`);
      }
    })(req, res, next);
  }
);

export default router;