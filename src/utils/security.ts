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
 * ตรวจสอบการป้องกัน Brute Force
 */
export const checkBruteForceProtection = async (
  usernameOrEmail: string,
  req: Request
): Promise<{ isLocked: boolean; message?: string; remainingTime?: number }> => {
  try {
    const ipAddress = req.ip || req.socket.remoteAddress || 'unknown';
    const deviceId = req.body.deviceId;
    
    // คำนวณช่วงเวลาที่จะตรวจสอบ
    const checkFrom = new Date(Date.now() - CONFIG.SECURITY.ATTEMPT_WINDOW);
    
    // สร้างเงื่อนไขสำหรับการค้นหา
    const whereConditions = [
      {
        ipAddress,
        isSuccess: false,
        createdAt: { gte: checkFrom }
      },
      {
        usernameOrEmail,
        isSuccess: false, 
        createdAt: { gte: checkFrom }
      }
    ];
    
    // เพิ่มเงื่อนไข deviceId หากมีค่า
    if (deviceId) {
      whereConditions.push({
        deviceId,
        isSuccess: false,
        createdAt: { gte: checkFrom }
      });
    }
    
    // ตรวจสอบจำนวนครั้งที่ล็อกอินผิดในช่วงเวลาที่กำหนด
    const failedAttempts = await prisma.loginAttempt.count({
      where: {
        OR: whereConditions
      }
    });
    
    // ถ้าไม่เกินจำนวนครั้งที่กำหนด
    if (failedAttempts < CONFIG.SECURITY.MAX_LOGIN_ATTEMPTS) {
      return { isLocked: false };
    }
    
    // สร้างเงื่อนไขสำหรับการค้นหาล็อกอินสำเร็จและล้มเหลวล่าสุด
    const successConditions = [];
    const failedConditions = [];
    
    // เพิ่มเงื่อนไข IP
    successConditions.push({ ipAddress, isSuccess: true });
    failedConditions.push({ ipAddress, isSuccess: false });
    
    // เพิ่มเงื่อนไข usernameOrEmail
    successConditions.push({ usernameOrEmail, isSuccess: true });
    failedConditions.push({ usernameOrEmail, isSuccess: false });
    
    // เพิ่มเงื่อนไข deviceId หากมีค่า
    if (deviceId) {
      successConditions.push({ deviceId, isSuccess: true });
      failedConditions.push({ deviceId, isSuccess: false });
    }
    
    // ตรวจสอบการล็อกอินสำเร็จล่าสุด
    const lastSuccessfulLogin = await prisma.loginAttempt.findFirst({
      where: {
        OR: successConditions
      },
      orderBy: { createdAt: 'desc' }
    });
    
    // ตรวจสอบการล็อกอินผิดล่าสุด
    const lastFailedLogin = await prisma.loginAttempt.findFirst({
      where: {
        OR: failedConditions
      },
      orderBy: { createdAt: 'desc' }
    });
    
    // ถ้าไม่มีข้อมูลการล็อกอินผิดล่าสุด
    if (!lastFailedLogin) {
      return { isLocked: false };
    }
    
    // ถ้ามีการล็อกอินสำเร็จหลังจากการล็อกอินผิดล่าสุด
    if (lastSuccessfulLogin && lastSuccessfulLogin.createdAt > lastFailedLogin.createdAt) {
      return { isLocked: false };
    }
    
    // ตรวจสอบว่ายังอยู่ในช่วงเวลาล็อคหรือไม่
    const lockoutTime = new Date(lastFailedLogin.createdAt.getTime() + CONFIG.SECURITY.LOCKOUT_DURATION);
    const now = new Date();
    
    if (now < lockoutTime) {
      // คำนวณเวลาที่เหลือในการล็อค (เป็นวินาที)
      const remainingTime = Math.ceil((lockoutTime.getTime() - now.getTime()) / 1000);
      return {
        isLocked: true,
        message: `บัญชีถูกล็อคชั่วคราว กรุณาลองใหม่ในอีก ${Math.floor(remainingTime / 60)}:${(remainingTime % 60).toString().padStart(2, '0')} นาที`,
        remainingTime
      };
    }
    
    return { isLocked: false };
  } catch (error) {
    logMessage(LogLevel.ERROR, 'Error checking brute force protection', error as Error, {
      usernameOrEmail, ip: req.ip
    });
    return { isLocked: false }; // ถ้าเกิดข้อผิดพลาด ให้อนุญาตให้ล็อกอินได้
  }
};