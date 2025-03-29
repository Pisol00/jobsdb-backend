// src/utils/security.ts
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { CONFIG } from '../config/env';
import prisma from './prisma';
import { Request } from 'express';

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
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(password, salt);
};

/**
 * เปรียบเทียบรหัสผ่านที่ให้มากับรหัสผ่านที่เข้ารหัสแล้ว
 */
export const comparePassword = async (
  password: string,
  hashedPassword: string
): Promise<boolean> => {
  return bcrypt.compare(password, hashedPassword);
};

/**
 * เปรียบเทียบสตริงแบบเวลาคงที่เพื่อป้องกัน timing attack
 * @param a สตริงแรก (เช่น OTP ที่ถูกต้อง)
 * @param b สตริงที่สอง (เช่น OTP ที่ผู้ใช้ป้อน)
 * @returns true ถ้าสตริงเหมือนกัน, false ถ้าต่างกัน
 */
export const constantTimeCompare = (a: string, b: string): boolean => {
  // ถ้าความยาวไม่เท่ากัน ให้ถือว่าไม่ตรงกัน แต่ยังคงทำการเปรียบเทียบเพื่อให้ใช้เวลาคงที่
  if (a.length !== b.length) {
    // ใช้ความยาวสูงสุดเพื่อให้การเปรียบเทียบใช้เวลานานเท่ากัน
    const maxLength = Math.max(a.length, b.length);
    
    // สร้างสตริงเทียบสำหรับสตริงที่สั้นกว่า
    let paddedA = a;
    let paddedB = b;
    
    if (a.length < maxLength) {
      paddedA = a.padEnd(maxLength, '\0');
    } else {
      paddedB = b.padEnd(maxLength, '\0');
    }
    
    // ตั้งค่าเริ่มต้นสำหรับผลลัพธ์
    let result = 0;
    
    // เปรียบเทียบทีละตัวอักษร
    for (let i = 0; i < maxLength; i++) {
      result |= paddedA.charCodeAt(i) ^ paddedB.charCodeAt(i);
    }
    
    return result === 0;
  }
  
  // ถ้าความยาวเท่ากัน
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  
  return result === 0;
};

/**
 * ตรวจสอบว่าอุปกรณ์เป็นที่น่าเชื่อถือสำหรับผู้ใช้หรือไม่
 */
export const checkTrustedDevice = async (userId: string, deviceId: string): Promise<boolean> => {
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
};

/**
 * บันทึกอุปกรณ์เป็นที่น่าเชื่อถือสำหรับผู้ใช้
 */
export const saveTrustedDevice = async (userId: string, deviceId: string) => {
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
    return prisma.trustedDevice.update({
      where: { id: existingDevice.id },
      data: { expiresAt },
    });
  } else {
    return prisma.trustedDevice.create({
      data: {
        userId,
        deviceId,
        expiresAt,
      },
    });
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
) => {
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
    console.error('❌ Error recording login attempt:', error);
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
    console.error('❌ Error checking brute force protection:', error);
    return { isLocked: false }; // ถ้าเกิดข้อผิดพลาด ให้อนุญาตให้ล็อกอินได้
  }
};