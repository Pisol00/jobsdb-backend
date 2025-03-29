// src/utils/security.ts
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { CONFIG } from '../config/env';
import prisma from './prisma';
import { Request } from 'express';
import { logMessage, LogLevel } from './errorLogger';

/**
 * สร้าง OTP แบบสุ่ม 6 หลัก
 */
export const generateOTP = (): string => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

/**
 * เข้ารหัสข้อความด้วย SHA-256
 */
export const hashString = (str: string): string => {
  return crypto.createHash('sha256').update(str).digest('hex');
};

/**
 * สร้าง salt และเข้ารหัสรหัสผ่าน
 */
export const hashPassword = async (password: string): Promise<string> => {
  try {
    const salt = await bcrypt.genSalt(10);
    return await bcrypt.hash(password, salt);
  } catch (error) {
    logMessage(LogLevel.ERROR, "Error hashing password", error as Error);
    throw new Error("ไม่สามารถเข้ารหัสรหัสผ่านได้ กรุณาลองใหม่อีกครั้ง");
  }
};

/**
 * เปรียบเทียบรหัสผ่านที่ให้มากับรหัสผ่านที่เข้ารหัสแล้ว
 */
export const comparePassword = async (
  password: string,
  hashedPassword: string
): Promise<boolean> => {
  try {
    return await bcrypt.compare(password, hashedPassword);
  } catch (error) {
    logMessage(LogLevel.ERROR, "Error comparing passwords", error as Error);
    throw new Error("เกิดข้อผิดพลาดในการตรวจสอบรหัสผ่าน");
  }
};

/**
 * ตรวจสอบว่าอุปกรณ์เป็นที่น่าเชื่อถือสำหรับผู้ใช้หรือไม่
 */
export const checkTrustedDevice = async (userId: string, deviceId: string): Promise<boolean> => {
  try {
    // ถ้าไม่มี deviceId ให้ถือว่าไม่ใช่อุปกรณ์ที่น่าเชื่อถือ
    if (!deviceId) {
      return false;
    }
    
    const trustedDevice = await prisma.trustedDevice.findFirst({
      where: {
        userId,
        deviceId,
        expiresAt: {
          gt: new Date(),
        },
      },
    });

    return !!trustedDevice;
  } catch (error) {
    logMessage(LogLevel.ERROR, "Error checking trusted device", error as Error, { userId, deviceId });
    return false; // เกิดข้อผิดพลาด ถือว่าไม่ใช่อุปกรณ์ที่น่าเชื่อถือ
  }
};

/**
 * บันทึกอุปกรณ์เป็นที่น่าเชื่อถือสำหรับผู้ใช้
 */
export const saveTrustedDevice = async (userId: string, deviceId: string) => {
  try {
    // ถ้าไม่มี deviceId ให้ return เลย
    if (!deviceId) {
      return null;
    }
    
    const expiresAt = new Date(Date.now() + CONFIG.TRUSTED_DEVICE_EXPIRY);

    const existingDevice = await prisma.trustedDevice.findFirst({
      where: {
        userId,
        deviceId,
      },
    });

    if (existingDevice) {
      return await prisma.trustedDevice.update({
        where: { id: existingDevice.id },
        data: { expiresAt },
      });
    } else {
      return await prisma.trustedDevice.create({
        data: {
          userId,
          deviceId,
          expiresAt,
        },
      });
    }
  } catch (error) {
    logMessage(LogLevel.ERROR, "Error saving trusted device", error as Error, { userId, deviceId });
    throw new Error("ไม่สามารถบันทึกอุปกรณ์ที่น่าเชื่อถือได้");
  }
};

/**
 * บันทึกความพยายามในการล็อกอิน
 */
export const recordLoginAttempt = async (
  usernameOrEmail: string,
  isSuccess: boolean,
  req: Request,
  userId?: string
): Promise<void> => {
  try {
    const ipAddress = req.ip || req.socket.remoteAddress || 'unknown';
    const userAgent = req.headers['user-agent'] || 'unknown';
    const deviceId = req.body.deviceId;

    await prisma.loginAttempt.create({
      data: {
        ipAddress,
        usernameOrEmail,
        isSuccess,
        deviceId,
        userAgent,
        userId,
      },
    });
  } catch (error) {
    logMessage(LogLevel.ERROR, 'Error recording login attempt', error as Error, {
      usernameOrEmail, isSuccess, userId, ip: req.ip
    });
    // ไม่ throw error เพื่อให้ทำงานต่อได้แม้จะบันทึกความพยายามล็อกอินไม่สำเร็จ
  }
};

/**
 * ตรวจสอบการป้องกัน Brute Force (ปรับปรุงใหม่!)
 * ตรวจสอบว่าบัญชีหรือ IP ถูกล็อคเนื่องจากมีการล็อกอินล้มเหลวเกินจำนวนที่กำหนดหรือไม่
 * โดยจะนับเฉพาะความพยายามล็อกอินที่ล้มเหลวหลังจากล็อกอินสำเร็จล่าสุด
 */
export const checkBruteForceProtection = async (
  usernameOrEmail: string,
  req: Request
): Promise<{ isLocked: boolean; message?: string; remainingTime?: number }> => {
  try {
    const ipAddress = req.ip || req.socket.remoteAddress || 'unknown';
    const deviceId = req.body.deviceId;
    
    // ตรวจสอบช่วงเวลาสำหรับการนับความพยายามล็อกอินที่ล้มเหลว
    const checkFrom = new Date(Date.now() - CONFIG.SECURITY.ATTEMPT_WINDOW);
    
    // ค้นหาการล็อกอินสำเร็จล่าสุด
    const lastSuccessfulAttempt = await prisma.loginAttempt.findFirst({
      where: {
        OR: [
          { ipAddress, isSuccess: true },
          { usernameOrEmail, isSuccess: true },
          ...(deviceId ? [{ deviceId, isSuccess: true }] : [])
        ],
      },
      orderBy: { createdAt: 'desc' },
    });

    // กำหนดเวลาเริ่มต้นสำหรับการตรวจสอบ - หากมีการล็อกอินสำเร็จล่าสุด ให้นับหลังจากนั้น
    // ไม่เช่นนั้นให้ใช้ช่วงเวลาตามที่กำหนด
    const startCountFrom = lastSuccessfulAttempt 
      ? lastSuccessfulAttempt.createdAt 
      : checkFrom;

    // ค้นหาความพยายามล็อกอินล้มเหลวล่าสุด (เพื่อคำนวณระยะเวลาที่ล็อค)
    const lastFailedAttempt = await prisma.loginAttempt.findFirst({
      where: {
        OR: [
          { ipAddress, isSuccess: false, createdAt: { gt: startCountFrom } },
          { usernameOrEmail, isSuccess: false, createdAt: { gt: startCountFrom } },
          ...(deviceId ? [{ deviceId, isSuccess: false, createdAt: { gt: startCountFrom } }] : [])
        ],
      },
      orderBy: { createdAt: 'desc' },
    });

    // ถ้าไม่มีการล็อกอินล้มเหลวหลังล็อกอินสำเร็จล่าสุด
    if (!lastFailedAttempt) {
      return { isLocked: false };
    }

    // นับจำนวนการล็อกอินที่ล้มเหลวหลังจากล็อกอินสำเร็จล่าสุด
    const failedAttemptsCount = await prisma.loginAttempt.count({
      where: {
        OR: [
          { ipAddress, isSuccess: false, createdAt: { gte: startCountFrom } },
          { usernameOrEmail, isSuccess: false, createdAt: { gte: startCountFrom } },
          ...(deviceId ? [{ deviceId, isSuccess: false, createdAt: { gte: startCountFrom } }] : [])
        ],
      },
    });

    // ถ้าจำนวนครั้งไม่เกินที่กำหนด บัญชีไม่ถูกล็อค
    if (failedAttemptsCount < CONFIG.SECURITY.MAX_LOGIN_ATTEMPTS) {
      // คำนวณจำนวนครั้งที่เหลือก่อนถูกล็อค
      const attemptsLeft = CONFIG.SECURITY.MAX_LOGIN_ATTEMPTS - failedAttemptsCount;
      return { 
        isLocked: false,
        message: `เหลือโอกาสอีก ${attemptsLeft} ครั้ง`
      };
    }

    // คำนวณระยะเวลาที่บัญชีถูกล็อค
    const lockoutTime = new Date(lastFailedAttempt.createdAt.getTime() + CONFIG.SECURITY.LOCKOUT_DURATION);
    const now = new Date();

    // ถ้าปัจจุบันอยู่ในช่วงเวลาที่ถูกล็อค
    if (now < lockoutTime) {
      const remainingMs = lockoutTime.getTime() - now.getTime();
      const remainingSeconds = Math.ceil(remainingMs / 1000);
      const minutes = Math.floor(remainingSeconds / 60);
      const seconds = remainingSeconds % 60;

      return {
        isLocked: true,
        message: `บัญชีถูกล็อคชั่วคราว กรุณาลองใหม่ในอีก ${minutes}:${seconds.toString().padStart(2, '0')} นาที`,
        remainingTime: remainingSeconds
      };
    }

    // หากพ้นระยะเวลาล็อคแล้ว อนุญาตให้ล็อกอินใหม่ได้
    return { isLocked: false };
  } catch (error) {
    // บันทึก log error และให้ล็อกอินได้ (เพื่อหลีกเลี่ยงการปิดกั้นผู้ใช้เมื่อระบบมีปัญหา)
    logMessage(LogLevel.ERROR, 'Error checking brute force protection', error as Error, {
      usernameOrEmail, ip: req.ip
    });
    return { isLocked: false };
  }
};

/**
 * รีเซ็ตการนับความพยายามล็อกอินที่ล้มเหลวหลังจากล็อกอินสำเร็จ (ปรับปรุงใหม่!)
 * 
 * @param usernameOrEmail อีเมลหรือชื่อผู้ใช้
 * @param ipAddress IP address
 * @param deviceId รหัสอุปกรณ์ (ถ้ามี)
 */
export const resetFailedLoginAttempts = async (
  usernameOrEmail: string,
  ipAddress: string,
  deviceId?: string
): Promise<void> => {
  try {
    // บันทึกการล็อกอินสำเร็จ - สิ่งนี้จะใช้เป็นจุดเริ่มต้นใหม่สำหรับการนับความพยายามล็อกอินที่ล้มเหลว
    await prisma.loginAttempt.create({
      data: {
        ipAddress,
        usernameOrEmail,
        isSuccess: true,
        deviceId,
      },
    });

    // หาผู้ใช้จากชื่อผู้ใช้หรืออีเมล
    const isEmail = usernameOrEmail.includes("@");
    const user = await prisma.user.findFirst({
      where: isEmail
        ? { email: usernameOrEmail }
        : { username: usernameOrEmail },
      select: { id: true }
    });

    // ถ้าพบผู้ใช้ ทำเครื่องหมายว่าล็อกอินสำเร็จสำหรับทุกความพยายามที่บันทึกในช่วงการตรวจสอบ
    if (user) {
      // อัปเดตฟิลด์ userId ของความพยายามล็อกอินที่ล้มเหลวทุกรายการในช่วงเวลาที่กำหนด
      // เพื่อเชื่อมโยงกับผู้ใช้ให้ถูกต้อง (เป็นประโยชน์ในการวิเคราะห์ความปลอดภัย)
      const checkFrom = new Date(Date.now() - CONFIG.SECURITY.ATTEMPT_WINDOW);
      await prisma.loginAttempt.updateMany({
        where: {
          OR: [
            { usernameOrEmail, userId: null, createdAt: { gte: checkFrom } },
            { ipAddress, userId: null, createdAt: { gte: checkFrom } },
            ...(deviceId ? [{ deviceId, userId: null, createdAt: { gte: checkFrom } }] : [])
          ]
        },
        data: {
          userId: user.id
        }
      });
    }

    logMessage(LogLevel.INFO, `Reset failed login attempts for ${usernameOrEmail}`, null, {
      usernameOrEmail, ipAddress, deviceId
    });
  } catch (error) {
    logMessage(LogLevel.ERROR, `Failed to reset login attempts for ${usernameOrEmail}`, error as Error, {
      usernameOrEmail, ipAddress, deviceId
    });
    // ไม่ throw error เพื่อให้การล็อกอินสำเร็จแม้จะมีข้อผิดพลาดในฟังก์ชันนี้
  }
};