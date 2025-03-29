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
import { LoginRequest } from '../../types/auth';

/**
 * ล็อกอินผู้ใช้พร้อมการป้องกัน Brute Force
 */
export const login = async (req: Request, res: Response) => {
  try {
    const { usernameOrEmail, password, deviceId } = req.body as LoginRequest;

    if (!usernameOrEmail || !password) {
      return res.status(400).json({
        success: false,
        message: "กรุณากรอกข้อมูลให้ครบถ้วน",
      });
    }
    
    // สร้าง deviceId ถ้าไม่มีการส่งมา
    const clientDeviceId = deviceId || uuidv4();
    
    // ตรวจสอบการป้องกัน Brute Force
    const bruteForceCheck = await checkBruteForceProtection(usernameOrEmail, req);
    if (bruteForceCheck.isLocked) {
      return res.status(429).json({
        success: false,
        message: bruteForceCheck.message,
        lockoutRemaining: bruteForceCheck.remainingTime
      });
    }

    // ตรวจสอบจำนวนครั้งที่ล็อกอินผิดในช่วงเวลาที่กำหนด
    const checkFrom = new Date(Date.now() - CONFIG.SECURITY.ATTEMPT_WINDOW);
    
    // สร้างเงื่อนไขการค้นหา (แก้ไขเพื่อป้องกัน deviceId undefined)
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
    
    const failedAttempts = await prisma.loginAttempt.count({
      where: {
        OR: whereConditions
      }
    });

    // ค้นหาผู้ใช้ตาม email หรือ username
    const isEmail = usernameOrEmail.includes("@");
    const user = await prisma.user.findFirst({
      where: isEmail
        ? { email: usernameOrEmail }
        : { username: usernameOrEmail },
    });

    if (!user) {
      // บันทึกความพยายามล็อกอินผิด
      await recordLoginAttempt(usernameOrEmail, false, req);
      
      // คำนวณจำนวนครั้งที่เหลือ (หลังจากบันทึกความพยายามล็อกอินครั้งนี้แล้ว)
      const attemptsLeft = CONFIG.SECURITY.MAX_LOGIN_ATTEMPTS - (failedAttempts + 1);
      
      return res.status(401).json({
        success: false,
        message: `ชื่อผู้ใช้/อีเมล หรือรหัสผ่านไม่ถูกต้อง (เหลือโอกาสอีก ${attemptsLeft > 0 ? attemptsLeft : 0} ครั้ง)`,
      });
    }

    // ตรวจสอบถ้าผู้ใช้ลงทะเบียนผ่าน OAuth
    if (!user.password) {
      // บันทึกความพยายามล็อกอินผิด
      await recordLoginAttempt(usernameOrEmail, false, req, user.id);
      
      // คำนวณจำนวนครั้งที่เหลือ
      const attemptsLeft = CONFIG.SECURITY.MAX_LOGIN_ATTEMPTS - (failedAttempts + 1);
      
      return res.status(401).json({
        success: false,
        message: `บัญชีนี้ใช้การเข้าสู่ระบบด้วย Google กรุณาใช้ปุ่ม "เข้าสู่ระบบด้วย Google" (เหลือโอกาสอีก ${attemptsLeft > 0 ? attemptsLeft : 0} ครั้ง)`,
      });
    }

    // ตรวจสอบรหัสผ่าน
    const isPasswordCorrect = await comparePassword(password, user.password);
    if (!isPasswordCorrect) {
      // บันทึกความพยายามล็อกอินผิด
      await recordLoginAttempt(usernameOrEmail, false, req, user.id);
      
      // คำนวณจำนวนครั้งที่เหลือ
      const attemptsLeft = CONFIG.SECURITY.MAX_LOGIN_ATTEMPTS - (failedAttempts + 1);
      
      // ถ้าเกินจำนวนครั้งที่กำหนด ให้ล็อค
      if (attemptsLeft <= 0) {
        return res.status(429).json({
          success: false,
          message: "บัญชีถูกล็อคชั่วคราว 5 นาที เนื่องจากคุณล็อกอินผิดหลายครั้งเกินไป",
          lockoutRemaining: CONFIG.SECURITY.LOCKOUT_DURATION / 1000
        });
      }
      
      return res.status(401).json({
        success: false,
        message: `ชื่อผู้ใช้/อีเมล หรือรหัสผ่านไม่ถูกต้อง (เหลือโอกาสอีก ${attemptsLeft} ครั้ง)`,
      });
    }

    // บันทึกความพยายามล็อกอินสำเร็จ
    await recordLoginAttempt(usernameOrEmail, true, req, user.id);

    // จัดการ 2FA ถ้าเปิดใช้งาน
    if (user.twoFactorEnabled) {
      // ตรวจสอบว่าอุปกรณ์เป็นที่น่าเชื่อถือหรือไม่
      const isTrustedDevice = await checkTrustedDevice(user.id, clientDeviceId);

      if (isTrustedDevice) {
        // ข้ามการยืนยัน 2FA สำหรับอุปกรณ์ที่น่าเชื่อถือ
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
      await sendOTPEmail(user.email, otp, tempToken, user.fullName || undefined);

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
  } catch (error) {
    console.error("❌ Login error:", error);
    
    if (error instanceof ApiError) {
      return res.status(error.statusCode).json({
        success: false,
        message: error.message,
      });
    }
    
    res.status(500).json({
      success: false,
      message: "เกิดข้อผิดพลาด กรุณาลองใหม่อีกครั้ง",
    });
  }
};