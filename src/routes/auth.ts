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
  verifyTempToken
} from '../controllers/auth'; // แก้ไขเส้นทาง import
import { authenticateUser } from '../middleware/auth';
import { CONFIG } from '../config/env';
import { generateToken } from '../utils/jwt';
import { logMessage, LogLevel } from '../utils/errorLogger';
import { asyncHandler } from '../middleware/asyncHandler';

// สร้าง router
const router = express.Router();
const FRONTEND_URL = CONFIG.FRONTEND_URL;

/**
 * เส้นทางสำหรับการยืนยันตัวตนแบบปกติ (Local Authentication)
 */

// ลงทะเบียนผู้ใช้ใหม่
router.post('/register', register);

// เข้าสู่ระบบด้วย username/email และรหัสผ่าน
router.post('/login', login);

// ดึงข้อมูลผู้ใช้ปัจจุบัน (ต้องเข้าสู่ระบบแล้ว)
router.get('/me', authenticateUser, getCurrentUser);

/**
 * เส้นทางสำหรับการรีเซ็ตรหัสผ่าน
 */

// ขอรีเซ็ตรหัสผ่าน (ส่งอีเมล)
router.post('/forgot-password', forgotPassword);

// ตรวจสอบความถูกต้องของ token รีเซ็ตรหัสผ่าน
router.post('/verify-reset-token', verifyResetToken);

// ดำเนินการรีเซ็ตรหัสผ่าน
router.post('/reset-password', resetPassword);

/**
 * เส้นทางสำหรับการยืนยันตัวตนแบบสองชั้น (2FA)
 */

// ยืนยัน OTP
router.post('/verify-otp', verifyOTP);

// เปิด/ปิดการใช้งาน 2FA (ต้องเข้าสู่ระบบแล้ว)
router.post('/toggle-two-factor', authenticateUser, toggleTwoFactor);

// ตรวจสอบความถูกต้องของ token ชั่วคราว
router.post('/verify-temp-token', verifyTempToken);

/**
 * เส้นทางสำหรับการยืนยันตัวตนผ่าน Google OAuth
 */

// เริ่มกระบวนการ OAuth กับ Google
router.get(
  '/google',
  (req, res, next) => {
    logMessage(LogLevel.INFO, 'Google OAuth authentication initiated', null, {
      ip: req.ip || req.socket.remoteAddress,
      userAgent: req.headers['user-agent']
    });
    
    next();
  },
  passport.authenticate('google', { 
    scope: ['profile', 'email'],
    // ตัวเลือกเพิ่มเติม (uncomment ตามต้องการ)
    // prompt: 'select_account', // บังคับให้เลือกบัญชี Google ทุกครั้ง
    // accessType: 'offline',     // ขอ refresh token
  })
);

// Callback จาก Google OAuth
router.get(
  '/google/callback',
  asyncHandler(async (req, res, next) => {
    try {
      // ใช้ Promise แบบ explicit เพื่อให้ใช้ async/await ได้
      const authResult = await new Promise((resolve, reject) => {
        passport.authenticate('google', { session: false }, (err, user, info) => {
          if (err) {
            reject(err);
            return;
          }
          resolve({ user, info });
        })(req, res, next);
      });
      
      const { user, info } = authResult as { user: any, info: any };
      
      // บันทึก context สำหรับ logging
      const context = {
        ip: req.ip || req.socket.remoteAddress,
        userAgent: req.headers['user-agent'],
        userId: user?.id,
        email: info?.email
      };
      
      // จัดการกรณีที่มีข้อผิดพลาด
      if (!user) {
        if (info && info.errorCode === 'EMAIL_EXISTS_AS_LOCAL') {
          // มีอีเมลนี้ในระบบแบบ local account แล้ว
          logMessage(LogLevel.WARN, 'Google OAuth - Email exists as local account', null, context);
          
          return res.redirect(`${FRONTEND_URL}/auth/login?error=email_exists&email=${encodeURIComponent(info.email)}`);
        }
        
        logMessage(LogLevel.ERROR, 'Google OAuth - Authentication failed', null, context);
        return res.redirect(`${FRONTEND_URL}/auth/login?error=google_failed`);
      }
      
      // ผู้ใช้ยืนยันตัวตนสำเร็จ
      logMessage(LogLevel.INFO, 'Google OAuth - Authentication successful', null, {
        ...context,
        userId: user.id
      });
      
      // สร้าง JWT token (กำหนด rememberMe เป็น true เพื่อให้ token มีอายุยาวนาน)
      const token = generateToken(user, true);
      
      // ส่งกลับไปยัง frontend พร้อม token
      return res.redirect(`${FRONTEND_URL}/oauth-callback?token=${token}`);
    } catch (error) {
      logMessage(
        LogLevel.ERROR, 
        'Unexpected error in Google OAuth callback', 
        error as Error, 
        {
          ip: req.ip,
          userAgent: req.headers['user-agent']
        }
      );
      
      return res.redirect(`${FRONTEND_URL}/auth/login?error=server_error`);
    }
  })
);

/**
 * เส้นทางเพิ่มเติม (สามารถเพิ่มได้ในอนาคต)
 */

// ตรวจสอบสถานะเซิร์ฟเวอร์
router.get('/status', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Auth service is running',
    serverTime: new Date().toISOString()
  });
});

// ออกจากระบบ (ทำงานฝั่ง client โดยลบ token)
router.post('/logout', authenticateUser, (req, res) => {
  // ถึงแม้ JWT จะไม่สามารถเพิกถอนได้ แต่เราสามารถบันทึกการออกจากระบบได้
  logMessage(LogLevel.INFO, 'User logged out', null, {
    userId: req.user?.id,
    ip: req.ip,
    userAgent: req.headers['user-agent']
  });
  
  res.status(200).json({
    success: true,
    message: 'ออกจากระบบสำเร็จ'
  });
});

export default router;