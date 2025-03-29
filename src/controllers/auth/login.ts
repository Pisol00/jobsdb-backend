// src/controllers/auth/login.ts
import { Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import prisma from '../../utils/prisma';
import { comparePassword, checkTrustedDevice, checkBruteForceProtection, recordLoginAttempt, generateOTP } from '../../utils/security';
import { generateToken, generateTempToken } from '../../utils/jwt';
import { sendOTPEmail } from '../../utils/email';
import { formatUserResponse } from './index';
import { CONFIG } from '../../config/env';
import { ApiError } from '../../middleware/errorHandler';
import { asyncHandler } from '../../middleware/asyncHandler';
import { LoginRequest } from '../../types/auth';
import { logMessage, LogLevel, logAndCreateApiError } from '../../utils/errorLogger';

/**
 * ล็อกอินผู้ใช้พร้อมการป้องกัน Brute Force
 */
export const login = asyncHandler(async (req: Request, res: Response) => {
  const { usernameOrEmail, password, deviceId } = req.body as LoginRequest;

  // ตรวจสอบข้อมูลที่จำเป็น
  if (!usernameOrEmail || !password) {
    throw new ApiError(400, "กรุณากรอกข้อมูลให้ครบถ้วน", "MISSING_CREDENTIALS");
  }
  
  // สร้าง deviceId ถ้าไม่มีการส่งมา
  const clientDeviceId = deviceId || uuidv4();
  
  // บันทึกข้อมูลเพื่อการ logging
  const context = {
    ip: req.ip,
    userAgent: req.headers['user-agent'],
    deviceId: clientDeviceId,
    usernameOrEmail
  };
  
  // ตรวจสอบการป้องกัน Brute Force
  try {
    const bruteForceCheck = await checkBruteForceProtection(usernameOrEmail, req);
    if (bruteForceCheck.isLocked) {
      logMessage(LogLevel.WARN, `Login attempt blocked due to brute force protection`, null, context);
      
      return res.status(429).json({
        success: false,
        message: bruteForceCheck.message,
        code: "ACCOUNT_LOCKED",
        lockoutRemaining: bruteForceCheck.remainingTime
      });
    }
  } catch (error) {
    // เกิดข้อผิดพลาดในการตรวจสอบ brute force แต่ไม่ควรหยุดการทำงาน
    logMessage(LogLevel.ERROR, "Error checking brute force protection", error as Error, context);
    // ดำเนินการต่อแม้จะเกิดข้อผิดพลาด
  }

  // ตรวจสอบจำนวนครั้งที่ล็อกอินผิดในช่วงเวลาที่กำหนด
  const checkFrom = new Date(Date.now() - CONFIG.SECURITY.ATTEMPT_WINDOW);
  
  // สร้างเงื่อนไขการค้นหา
  const whereConditions = [
    {
      ipAddress: req.ip || req.socket.remoteAddress || 'unknown',
      isSuccess: false,
      createdAt: { gte: checkFrom }
    },
    {
      usernameOrEmail,
      isSuccess: false, 
      createdAt: { gte: checkFrom }
    }
  ];
  
  // เพิ่มเงื่อนไข deviceId ถ้ามีค่า
  if (clientDeviceId) {
    whereConditions.push({
      deviceId: clientDeviceId,
      isSuccess: false,
      createdAt: { gte: checkFrom }
    });
  }
  
  // นับจำนวนครั้งที่ล็อกอินผิด
  let failedAttempts = 0;
  try {
    failedAttempts = await prisma.loginAttempt.count({
      where: {
        OR: whereConditions
      }
    });
  } catch (error) {
    logMessage(LogLevel.ERROR, "Error counting failed login attempts", error as Error, context);
    // ดำเนินการต่อแม้จะเกิดข้อผิดพลาด โดยใช้ค่าเริ่มต้น
  }

  // ค้นหาผู้ใช้ตาม email หรือ username
  const isEmail = usernameOrEmail.includes("@");
  let user;
  try {
    user = await prisma.user.findFirst({
      where: isEmail
        ? { email: usernameOrEmail }
        : { username: usernameOrEmail },
    });
  } catch (error) {
    throw logAndCreateApiError(
      500, 
      "เกิดข้อผิดพลาดในการค้นหาผู้ใช้", 
      error as Error, 
      context
    );
  }

  if (!user) {
    // บันทึกความพยายามล็อกอินผิด
    try {
      await recordLoginAttempt(usernameOrEmail, false, req);
    } catch (error) {
      logMessage(LogLevel.ERROR, "Error recording failed login attempt", error as Error, context);
      // ดำเนินการต่อแม้จะเกิดข้อผิดพลาด
    }
    
    // คำนวณจำนวนครั้งที่เหลือ (หลังจากบันทึกความพยายามล็อกอินครั้งนี้แล้ว)
    const attemptsLeft = CONFIG.SECURITY.MAX_LOGIN_ATTEMPTS - (failedAttempts + 1);
    
    return res.status(401).json({
      success: false,
      message: `ชื่อผู้ใช้/อีเมล หรือรหัสผ่านไม่ถูกต้อง (เหลือโอกาสอีก ${attemptsLeft > 0 ? attemptsLeft : 0} ครั้ง)`,
      code: "INVALID_CREDENTIALS"
    });
  }

  // อัพเดทข้อมูลสำหรับ logging
  Object.assign(context, { userId: user.id });

  // ตรวจสอบถ้าผู้ใช้ลงทะเบียนผ่าน OAuth
  if (!user.password) {
    // บันทึกความพยายามล็อกอินผิด
    try {
      await recordLoginAttempt(usernameOrEmail, false, req, user.id);
    } catch (error) {
      logMessage(LogLevel.ERROR, "Error recording failed login attempt for OAuth user", error as Error, context);
      // ดำเนินการต่อแม้จะเกิดข้อผิดพลาด
    }
    
    // คำนวณจำนวนครั้งที่เหลือ
    const attemptsLeft = CONFIG.SECURITY.MAX_LOGIN_ATTEMPTS - (failedAttempts + 1);
    
    return res.status(401).json({
      success: false,
      message: `บัญชีนี้ใช้การเข้าสู่ระบบด้วย Google กรุณาใช้ปุ่ม "เข้าสู่ระบบด้วย Google" (เหลือโอกาสอีก ${attemptsLeft > 0 ? attemptsLeft : 0} ครั้ง)`,
      code: "OAUTH_ACCOUNT"
    });
  }

  // ตรวจสอบรหัสผ่าน
  let isPasswordCorrect = false;
  try {
    isPasswordCorrect = await comparePassword(password, user.password);
  } catch (error) {
    throw logAndCreateApiError(
      500, 
      "เกิดข้อผิดพลาดในการตรวจสอบรหัสผ่าน", 
      error as Error, 
      context
    );
  }

  if (!isPasswordCorrect) {
    // บันทึกความพยายามล็อกอินผิด
    try {
      await recordLoginAttempt(usernameOrEmail, false, req, user.id);
    } catch (error) {
      logMessage(LogLevel.ERROR, "Error recording failed login attempt with wrong password", error as Error, context);
      // ดำเนินการต่อแม้จะเกิดข้อผิดพลาด
    }
    
    // คำนวณจำนวนครั้งที่เหลือ
    const attemptsLeft = CONFIG.SECURITY.MAX_LOGIN_ATTEMPTS - (failedAttempts + 1);
    
    // ถ้าเกินจำนวนครั้งที่กำหนด ให้ล็อค
    if (attemptsLeft <= 0) {
      logMessage(LogLevel.WARN, `Account locked due to too many failed login attempts`, null, context);
      
      return res.status(429).json({
        success: false,
        message: "บัญชีถูกล็อคชั่วคราว 5 นาที เนื่องจากคุณล็อกอินผิดหลายครั้งเกินไป",
        code: "ACCOUNT_LOCKED",
        lockoutRemaining: CONFIG.SECURITY.LOCKOUT_DURATION / 1000
      });
    }
    
    return res.status(401).json({
      success: false,
      message: `ชื่อผู้ใช้/อีเมล หรือรหัสผ่านไม่ถูกต้อง (เหลือโอกาสอีก ${attemptsLeft} ครั้ง)`,
      code: "INVALID_CREDENTIALS"
    });
  }

  // บันทึกความพยายามล็อกอินสำเร็จ
  try {
    await recordLoginAttempt(usernameOrEmail, true, req, user.id);
  } catch (error) {
    logMessage(LogLevel.ERROR, "Error recording successful login attempt", error as Error, context);
    // ดำเนินการต่อแม้จะเกิดข้อผิดพลาด
  }
  
  logMessage(LogLevel.INFO, `User logged in successfully`, null, context);

  // จัดการ 2FA ถ้าเปิดใช้งาน
  if (user.twoFactorEnabled) {
    // ตรวจสอบว่าอุปกรณ์เป็นที่น่าเชื่อถือหรือไม่
    let isTrustedDevice = false;
    try {
      isTrustedDevice = await checkTrustedDevice(user.id, clientDeviceId);
    } catch (error) {
      logMessage(LogLevel.ERROR, "Error checking trusted device", error as Error, context);
      // ดำเนินการต่อแม้จะเกิดข้อผิดพลาด โดยถือว่าไม่ใช่อุปกรณ์ที่น่าเชื่อถือ
    }

    if (isTrustedDevice) {
      // ข้ามการยืนยัน 2FA สำหรับอุปกรณ์ที่น่าเชื่อถือ
      logMessage(LogLevel.INFO, `Skipping 2FA for trusted device`, null, context);
      
      const token = generateToken(user, req.body.rememberMe);
      return res.status(200).json({
        success: true,
        token,
        user: formatUserResponse(user),
      });
    }

    // ดำเนินการยืนยัน 2FA
    try {
      const otp = generateOTP();
      const otpExpires = new Date(Date.now() + CONFIG.OTP_EXPIRY);
      const tempToken = generateTempToken(user, clientDeviceId);

      // บันทึก OTP ลงฐานข้อมูล
      await prisma.user.update({
        where: { id: user.id },
        data: {
          twoFactorOTP: otp,
          twoFactorExpires: otpExpires,
          lastTempToken: tempToken,
        },
      });

      // ส่ง OTP ทางอีเมล
      const emailSent = await sendOTPEmail(user.email, otp, tempToken, user.fullName || undefined);
      
      if (!emailSent) {
        logMessage(LogLevel.ERROR, `Failed to send OTP email for 2FA`, null, context);
      } else {
        logMessage(LogLevel.INFO, `OTP sent for 2FA`, null, context);
      }

      return res.status(200).json({
        success: true,
        requireTwoFactor: true,
        tempToken,
        expiresAt: otpExpires.getTime(),
        message: "รหัส OTP ได้ถูกส่งไปยังอีเมลของคุณ",
      });
    } catch (error) {
      throw logAndCreateApiError(
        500, 
        "เกิดข้อผิดพลาดในการสร้างรหัส OTP", 
        error as Error, 
        context
      );
    }
  }

  // ล็อกอินปกติ (ไม่มี 2FA)
  const token = generateToken(user, req.body.rememberMe);
  res.status(200).json({
    success: true,
    token,
    user: formatUserResponse(user),
  });
});