// src/controllers/auth/login.ts
import { Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import prisma from '../../utils/prisma';
import { comparePassword, checkTrustedDevice, checkBruteForceProtection, recordLoginAttempt, generateOTP, resetFailedLoginAttempts } from '../../utils/security';
import { generateToken, generateTempToken } from '../../utils/jwt';
import { sendOTPEmail } from '../../utils/email';
import { formatUserResponse } from './index';
import { CONFIG } from '../../config/env';
import { ApiError } from '../../middleware/errorHandler';
import { asyncHandler } from '../../middleware/asyncHandler';
import { LoginRequest } from '../../types/auth';
import { logMessage, LogLevel } from '../../utils/errorLogger';
import { createEmailVerification } from './emailVerification';

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
  const bruteForceCheck = await checkBruteForceProtection(usernameOrEmail, req)
    .catch(error => {
      logMessage(LogLevel.ERROR, "Error checking brute force protection", error as Error, context);
      // คืนค่าเริ่มต้นในกรณีที่เกิดข้อผิดพลาด
      return { isLocked: false };
    });
    
  if (bruteForceCheck.isLocked) {
    logMessage(LogLevel.WARN, `Login attempt blocked due to brute force protection`, null, context);
    
    return res.status(429).json({
      success: false,
      message: bruteForceCheck.message,
      code: "ACCOUNT_LOCKED",
      lockoutRemaining: bruteForceCheck.remainingTime
    });
  }
  
  // ค้นหาผู้ใช้ตาม email หรือ username
  const isEmail = usernameOrEmail.includes("@");
  const user = await prisma.user.findFirst({
    where: isEmail
      ? { email: usernameOrEmail }
      : { username: usernameOrEmail },
  });

  if (!user) {
    // บันทึกความพยายามล็อกอินผิด
    await recordLoginAttempt(usernameOrEmail, false, req)
      .catch(error => {
        logMessage(LogLevel.ERROR, "Error recording failed login attempt", error as Error, context);
      });
    
    return res.status(401).json({
      success: false,
      message: `ชื่อผู้ใช้/อีเมล หรือรหัสผ่านไม่ถูกต้อง ${bruteForceCheck.message || ''}`,
      code: "INVALID_CREDENTIALS"
    });
  }

  // อัพเดทข้อมูลสำหรับ logging
  context.userId = user.id;

  // ตรวจสอบถ้าผู้ใช้ลงทะเบียนผ่าน OAuth
  if (!user.password) {
    // บันทึกความพยายามล็อกอินผิด
    await recordLoginAttempt(usernameOrEmail, false, req, user.id)
      .catch(error => {
        logMessage(LogLevel.ERROR, "Error recording failed login attempt for OAuth user", error as Error, context);
      });
    
    return res.status(401).json({
      success: false,
      message: `บัญชีนี้ใช้การเข้าสู่ระบบด้วย Google กรุณาใช้ปุ่ม "เข้าสู่ระบบด้วย Google" ${bruteForceCheck.message || ''}`,
      code: "OAUTH_ACCOUNT"
    });
  }

  // ตรวจสอบรหัสผ่าน
  const isPasswordCorrect = await comparePassword(password, user.password);

  if (!isPasswordCorrect) {
    // บันทึกความพยายามล็อกอินผิด
    await recordLoginAttempt(usernameOrEmail, false, req, user.id)
      .catch(error => {
        logMessage(LogLevel.ERROR, "Error recording failed login attempt with wrong password", error as Error, context);
      });
    
    // ตรวจสอบอีกครั้งหลังจากบันทึกความพยายามล็อกอินที่ล้มเหลว
    // เนื่องจากการบันทึกล่าสุดอาจทำให้เกินจำนวนครั้งที่อนุญาต
    const updatedCheck = await checkBruteForceProtection(usernameOrEmail, req)
      .catch(error => {
        logMessage(LogLevel.ERROR, "Error checking brute force protection after failed login", error as Error, context);
        return { isLocked: false };
      });
      
    if (updatedCheck.isLocked) {
      logMessage(LogLevel.WARN, `Account locked after failed login attempt`, null, context);
      
      return res.status(429).json({
        success: false,
        message: updatedCheck.message,
        code: "ACCOUNT_LOCKED",
        lockoutRemaining: updatedCheck.remainingTime
      });
    }
    
    return res.status(401).json({
      success: false,
      message: `ชื่อผู้ใช้/อีเมล หรือรหัสผ่านไม่ถูกต้อง ${updatedCheck.message || ''}`,
      code: "INVALID_CREDENTIALS"
    });
  }

  // รีเซ็ตการนับความพยายามล็อกอินที่ล้มเหลวเมื่อล็อกอินสำเร็จ
  await resetFailedLoginAttempts(
    usernameOrEmail, 
    req.ip || req.socket.remoteAddress || 'unknown', 
    clientDeviceId
  );

  // ตรวจสอบว่าอีเมลได้รับการยืนยันหรือไม่
  if (!user.isEmailVerified) {
    // ส่ง OTP ใหม่สำหรับการยืนยันอีเมล
    const { verifyToken } = await createEmailVerification(user.id);
    
    return res.status(403).json({
      success: false,
      message: "บัญชีของคุณยังไม่ได้ยืนยันอีเมล กรุณาตรวจสอบอีเมลของคุณหรือขอรหัสยืนยันใหม่",
      code: "EMAIL_NOT_VERIFIED",
      requireEmailVerification: true,
      tempToken: verifyToken,
      user: formatUserResponse(user)
    });
  }

  // บันทึกความพยายามล็อกอินสำเร็จ
  await recordLoginAttempt(usernameOrEmail, true, req, user.id)
    .catch(error => {
      logMessage(LogLevel.ERROR, "Error recording successful login attempt", error as Error, context);
    });
  
  logMessage(LogLevel.INFO, `User logged in successfully`, null, context);

  // จัดการ 2FA ถ้าเปิดใช้งาน
  if (user.twoFactorEnabled) {
    // ตรวจสอบว่าอุปกรณ์เป็นที่น่าเชื่อถือหรือไม่
    const isTrustedDevice = await checkTrustedDevice(user.id, clientDeviceId)
      .catch(error => {
        logMessage(LogLevel.ERROR, "Error checking trusted device", error as Error, context);
        return false; // กรณีเกิดข้อผิดพลาด ให้ถือว่าไม่ใช่อุปกรณ์ที่เชื่อถือได้
      });

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
    const emailSent = await sendOTPEmail(user.email, otp, tempToken, user.fullName || undefined)
      .catch(error => {
        logMessage(LogLevel.ERROR, `Error sending OTP email for 2FA`, error, context);
        return false;
      });
    
    if (!emailSent) {
      logMessage(LogLevel.ERROR, `Failed to send OTP email for 2FA`, null, context);
      // แม้ไม่สามารถส่งอีเมลได้ เราจะยังคงดำเนินการต่อเพื่อให้ผู้ใช้สามารถล็อกอินได้
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
  }

  // ล็อกอินปกติ (ไม่มี 2FA)
  const token = generateToken(user, req.body.rememberMe);
  res.status(200).json({
    success: true,
    token,
    user: formatUserResponse(user),
  });
});