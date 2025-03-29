// src/controllers/auth/twoFactor.ts
import { Request, Response } from 'express';
import prisma from '../../utils/prisma';
import { verifyToken, generateToken, generateTempToken } from '../../utils/jwt';
import { saveTrustedDevice, constantTimeCompare, generateOTP } from '../../utils/security';
import { formatUserResponse } from './index';
import { VerifyOTPRequest } from '../../types/auth';
import { asyncHandler } from '../../middleware/asyncHandler';
import { ApiError } from '../../middleware/errorHandler';
import { logMessage, LogLevel, logAndCreateApiError } from '../../utils/errorLogger';
import { CONFIG } from '../../config/env';
import { sendOTPEmail } from '../../utils/email';

/**
 * เปิด/ปิดการยืนยันตัวตนแบบสองขั้นตอน (2FA)
 * 
 * @route POST /api/auth/toggle-two-factor
 */
export const toggleTwoFactor = asyncHandler(async (req: Request, res: Response) => {
  const user = req.user;
  const { enable } = req.body;

  // บันทึกข้อมูลสำหรับการ logging
  const context = {
    ip: req.ip || req.socket.remoteAddress,
    userAgent: req.headers['user-agent'],
    userId: user?.id,
    action: enable ? 'enable_2fa' : 'disable_2fa'
  };

  if (typeof enable !== "boolean") {
    logMessage(LogLevel.WARN, "Invalid 2FA toggle request", null, context);
    throw new ApiError(400, "กรุณาระบุสถานะการเปิด/ปิดการใช้งาน 2FA", "INVALID_TOGGLE_VALUE");
  }

  if (!user) {
    throw new ApiError(401, "ไม่พบข้อมูลผู้ใช้", "UNAUTHORIZED");
  }

  try {
    // ตรวจสอบว่าผู้ใช้มีบัญชีแบบ local หรือไม่
    if (user.provider && user.provider !== "local" && enable) {
      logMessage(LogLevel.WARN, "OAuth user attempting to enable 2FA", null, context);
      
      return res.status(400).json({
        success: false,
        message: `บัญชี ${user.provider} ไม่รองรับการยืนยันตัวตนแบบสองขั้นตอน`,
        code: "OAUTH_NOT_SUPPORTED"
      });
    }

    // อัพเดทสถานะ 2FA
    await prisma.user.update({
      where: { id: user.id },
      data: {
        twoFactorEnabled: enable,
      },
    });

    // ล้างข้อมูลอุปกรณ์ที่น่าเชื่อถือถ้าปิดใช้งาน 2FA
    if (!enable) {
      await prisma.trustedDevice.deleteMany({
        where: { userId: user.id },
      });
      
      // ล้าง OTP และ token ที่เกี่ยวข้อง
      await prisma.user.update({
        where: { id: user.id },
        data: {
          twoFactorOTP: null,
          twoFactorExpires: null,
          lastTempToken: null
        }
      });
      
      logMessage(LogLevel.INFO, "User disabled 2FA and cleared trusted devices", null, context);
    } else {
      logMessage(LogLevel.INFO, "User enabled 2FA", null, context);
    }

    return res.status(200).json({
      success: true,
      message: enable
        ? "เปิดใช้งานการยืนยันตัวตนแบบสองขั้นตอนเรียบร้อยแล้ว"
        : "ปิดใช้งานการยืนยันตัวตนแบบสองขั้นตอนเรียบร้อยแล้ว",
      twoFactorEnabled: enable,
    });
  } catch (error) {
    throw logAndCreateApiError(
      500, 
      "เกิดข้อผิดพลาดในการตั้งค่า 2FA", 
      error as Error, 
      context
    );
  }
});

/**
 * ตรวจสอบ OTP สำหรับ 2FA
 * 
 * @route POST /api/auth/verify-otp
 */
export const verifyOTP = asyncHandler(async (req: Request, res: Response) => {
  const { otp, tempToken, rememberDevice = false } = req.body as VerifyOTPRequest;

  // บันทึกข้อมูลสำหรับการ logging
  const context = {
    ip: req.ip || req.socket.remoteAddress,
    userAgent: req.headers['user-agent'],
    // ไม่บันทึก OTP และ tempToken เพื่อความปลอดภัย
  };

  if (!otp || !tempToken) {
    logMessage(LogLevel.WARN, "OTP verification with missing data", null, context);
    throw new ApiError(400, "กรุณากรอกข้อมูลให้ครบถ้วน", "MISSING_DATA");
  }

  try {
    // ตรวจสอบและถอดรหัส token ชั่วคราว
    const decoded = verifyToken(tempToken);
    if (!decoded || !decoded.temp) {
      logMessage(LogLevel.WARN, "Invalid or expired temporary token for OTP verification", null, context);
      
      return res.status(400).json({
        success: false,
        message: "Token ไม่ถูกต้องหรือหมดอายุแล้ว กรุณาเข้าสู่ระบบใหม่",
        code: "INVALID_TOKEN"
      });
    }

    // อัพเดท context ด้วยข้อมูลจาก token
    Object.assign(context, { 
      userId: decoded.id,
      email: decoded.email,
      deviceId: decoded.deviceId
    });

    // ค้นหาผู้ใช้
    const user = await prisma.user.findUnique({
      where: { id: decoded.id },
    });

    if (!user) {
      logMessage(LogLevel.WARN, "User not found for OTP verification", null, context);
      
      return res.status(400).json({
        success: false,
        message: "ไม่พบผู้ใช้งาน กรุณาเข้าสู่ระบบใหม่",
        code: "USER_NOT_FOUND"
      });
    }

    // ตรวจสอบ OTP - ปรับปรุงเพื่อป้องกัน timing attack
    if (
      !user.twoFactorOTP ||
      !user.twoFactorExpires ||
      user.twoFactorExpires < new Date() ||
      !constantTimeCompare(user.twoFactorOTP, otp)
    ) {
      logMessage(LogLevel.WARN, "Invalid or expired OTP", null, context);
      
      return res.status(400).json({
        success: false,
        message: "รหัส OTP ไม่ถูกต้องหรือหมดอายุแล้ว",
        code: "INVALID_OTP"
      });
    }

    // ตรวจสอบว่านี่เป็น token ชั่วคราวล่าสุดหรือไม่
    if (!user.lastTempToken || !constantTimeCompare(user.lastTempToken, tempToken)) {
      logMessage(LogLevel.WARN, "Outdated temporary token for OTP verification", null, context);
      
      return res.status(400).json({
        success: false,
        message: "ลิงก์ยืนยันนี้ไม่สามารถใช้งานได้แล้ว กรุณาเข้าสู่ระบบอีกครั้ง",
        code: "OUTDATED_TOKEN"
      });
    }

    // ล้าง OTP หลังจากใช้งาน
    await prisma.user.update({
      where: { id: user.id },
      data: {
        twoFactorOTP: null,
        twoFactorExpires: null,
        lastTempToken: null
      },
    });

    // จดจำอุปกรณ์ถ้ามีการร้องขอและมี deviceId
    if (rememberDevice && decoded.deviceId) {
      await saveTrustedDevice(user.id, decoded.deviceId);
      logMessage(LogLevel.INFO, "Device marked as trusted after successful 2FA", null, context);
    }

    // สร้าง token สำหรับการเข้าสู่ระบบ
    const token = generateToken(user);
    
    logMessage(LogLevel.INFO, "OTP verified successfully", null, context);

    res.status(200).json({
      success: true,
      token,
      user: formatUserResponse(user),
    });
  } catch (error) {
    throw logAndCreateApiError(
      500, 
      "เกิดข้อผิดพลาดในการยืนยัน OTP", 
      error as Error, 
      context
    );
  }
});

/**
 * ตรวจสอบความถูกต้องของ token ชั่วคราว
 * 
 * @route POST /api/auth/verify-temp-token
 */
export const verifyTempToken = asyncHandler(async (req: Request, res: Response) => {
  const { token } = req.body;
  
  // บันทึกข้อมูลสำหรับการ logging
  const context = {
    ip: req.ip || req.socket.remoteAddress,
    userAgent: req.headers['user-agent'],
    // ไม่บันทึก token เพื่อความปลอดภัย
  };
  
  if (!token) {
    logMessage(LogLevel.WARN, "Temporary token verification without token", null, context);
    throw new ApiError(400, "ไม่พบ Token", "MISSING_TOKEN");
  }
  
  try {
    // ตรวจสอบ token
    const decoded = verifyToken(token);
    if (!decoded || !decoded.temp) {
      logMessage(LogLevel.WARN, "Invalid or expired temporary token", null, context);
      
      return res.status(200).json({
        success: false,
        message: 'Token ไม่ถูกต้องหรือหมดอายุแล้ว',
        code: "INVALID_TOKEN"
      });
    }

    // อัพเดท context ด้วยข้อมูลจาก token
    Object.assign(context, { 
      userId: decoded.id,
      email: decoded.email
    });
    
    // ค้นหาผู้ใช้
    const user = await prisma.user.findUnique({
      where: { id: decoded.id },
    });
    
    // ตรวจสอบว่านี่เป็น token ชั่วคราวล่าสุดหรือไม่
    if (!user || !user.lastTempToken || !constantTimeCompare(user.lastTempToken, token)) {
      logMessage(LogLevel.WARN, "Outdated or invalid temporary token", null, context);
      
      return res.status(200).json({
        success: false,
        message: 'ลิงก์ยืนยันนี้ไม่สามารถใช้งานได้แล้ว',
        code: "OUTDATED_TOKEN"
      });
    }
    
    // ตรวจสอบว่า OTP ยังไม่หมดอายุ
    if (!user.twoFactorExpires || user.twoFactorExpires < new Date()) {
      logMessage(LogLevel.WARN, "OTP has expired for valid temporary token", null, context);
      
      return res.status(200).json({
        success: false,
        message: 'รหัส OTP หมดอายุแล้ว กรุณาขอรหัสใหม่',
        code: "EXPIRED_OTP"
      });
    }
    
    logMessage(LogLevel.INFO, "Temporary token verified successfully", null, context);
    
    return res.status(200).json({
      success: true,
      message: 'Token ถูกต้อง',
      expiresAt: user.twoFactorExpires.getTime()
    });
  } catch (error) {
    throw logAndCreateApiError(
      500, 
      "เกิดข้อผิดพลาดในการตรวจสอบ Token", 
      error as Error, 
      context
    );
  }
});

/**
 * สร้างรหัส OTP ใหม่และส่งทางอีเมล
 * 
 * @route POST /api/auth/regenerate-otp
 */
export const regenerateOTP = asyncHandler(async (req: Request, res: Response) => {
  const { tempToken } = req.body;
  
  // บันทึกข้อมูลสำหรับการ logging
  const context = {
    ip: req.ip || req.socket.remoteAddress,
    userAgent: req.headers['user-agent'],
    // ไม่บันทึก tempToken เพื่อความปลอดภัย
  };
  
  if (!tempToken) {
    logMessage(LogLevel.WARN, "OTP regeneration request without token", null, context);
    throw new ApiError(400, "ไม่พบ Token", "MISSING_TOKEN");
  }
  
  try {
    // ตรวจสอบและถอดรหัส token ชั่วคราว
    const decoded = verifyToken(tempToken);
    if (!decoded || !decoded.temp) {
      logMessage(LogLevel.WARN, "Invalid token for OTP regeneration", null, context);
      
      return res.status(400).json({
        success: false,
        message: "Token ไม่ถูกต้องหรือหมดอายุแล้ว กรุณาเข้าสู่ระบบใหม่",
        code: "INVALID_TOKEN"
      });
    }
    
    // อัพเดท context ด้วยข้อมูลจาก token
    Object.assign(context, { 
      userId: decoded.id,
      email: decoded.email,
      deviceId: decoded.deviceId
    });
    
    // ค้นหาผู้ใช้
    const user = await prisma.user.findUnique({
      where: { id: decoded.id },
    });
    
    if (!user) {
      logMessage(LogLevel.WARN, "User not found for OTP regeneration", null, context);
      
      return res.status(400).json({
        success: false,
        message: "ไม่พบผู้ใช้งาน กรุณาเข้าสู่ระบบใหม่",
        code: "USER_NOT_FOUND"
      });
    }
    
    // ตรวจสอบการเปิดใช้งาน 2FA
    if (!user.twoFactorEnabled) {
      logMessage(LogLevel.WARN, "OTP regeneration for user without 2FA enabled", null, context);
      
      return res.status(400).json({
        success: false,
        message: "ผู้ใช้นี้ไม่ได้เปิดใช้งานการยืนยันตัวตนแบบสองขั้นตอน",
        code: "2FA_NOT_ENABLED"
      });
    }
    
    // ตรวจสอบเวลาล่าสุดที่ขอ OTP (ป้องกันการส่งซ้ำบ่อยเกินไป)
    const lastRequestTime = user.twoFactorExpires 
      ? new Date(user.twoFactorExpires.getTime() - CONFIG.OTP_EXPIRY).getTime() 
      : 0;
    
    const currentTime = Date.now();
    const timeElapsed = currentTime - lastRequestTime;
    
    // ถ้าเวลาผ่านไปน้อยกว่า 1 นาที ให้รอ
    if (timeElapsed < 60 * 1000) { // 1 นาที
      logMessage(LogLevel.WARN, "OTP regeneration throttled", null, context);
      
      return res.status(429).json({
        success: false,
        message: "กรุณารอสักครู่ก่อนขอรหัส OTP ใหม่",
        code: "THROTTLED",
        retryAfter: Math.ceil((60 * 1000 - timeElapsed) / 1000) // เวลาที่ต้องรอ (วินาที)
      });
    }
    
    // สร้าง OTP ใหม่
    const otp = generateOTP();
    const otpExpires = new Date(Date.now() + CONFIG.OTP_EXPIRY);
    const newTempToken = generateTempToken(user, decoded.deviceId);
    
    // บันทึก OTP ลงฐานข้อมูล
    await prisma.user.update({
      where: { id: user.id },
      data: {
        twoFactorOTP: otp,
        twoFactorExpires: otpExpires,
        lastTempToken: newTempToken,
      },
    });
    
    // ส่ง OTP ทางอีเมล
    const emailSent = await sendOTPEmail(user.email, otp, newTempToken, user.fullName || undefined);
    
    if (!emailSent) {
      logMessage(LogLevel.ERROR, "Failed to send regenerated OTP email", null, context);
      
      // ล้าง OTP ที่สร้างไว้
      await prisma.user.update({
        where: { id: user.id },
        data: {
          twoFactorOTP: null,
          twoFactorExpires: null,
          lastTempToken: null,
        },
      });
      
      throw new ApiError(500, "ไม่สามารถส่งอีเมลรหัส OTP ได้ กรุณาลองใหม่อีกครั้ง", "EMAIL_SEND_FAILED");
    }
    
    logMessage(LogLevel.INFO, "OTP regenerated and sent successfully", null, context);
    
    return res.status(200).json({
      success: true,
      message: "ส่งรหัส OTP ใหม่ไปยังอีเมลของคุณแล้ว",
      tempToken: newTempToken,
      expiresAt: otpExpires.getTime(),
      email: user.email.replace(/(.{2})(.*)(?=@)/, (_, start, rest) => start + '*'.repeat(rest.length)) // ปกปิดบางส่วนของอีเมล
    });
  } catch (error) {
    if (error instanceof ApiError) {
      throw error;
    }
    
    throw logAndCreateApiError(
      500, 
      "เกิดข้อผิดพลาดในการสร้างรหัส OTP ใหม่", 
      error as Error, 
      context
    );
  }
});