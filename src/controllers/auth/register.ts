// src/controllers/auth/register.ts
import { Request, Response } from 'express';
import prisma from '../../utils/prisma';
import { hashPassword } from '../../utils/security';
import { validateUsername, validatePassword, validateEmail } from '../../utils/validation';
import { generateToken } from '../../utils/jwt';
import { formatUserResponse } from './index';
import { RegisterRequest } from '../../types/auth';
import { asyncHandler } from '../../middleware/asyncHandler';
import { ApiError } from '../../middleware/errorHandler';
import { logMessage, LogLevel, logAndCreateApiError } from '../../utils/errorLogger';
import { sendEmail, createWelcomeEmailTemplate } from '../../utils/email';
import { CONFIG } from '../../config/env';

/**
 * ลงทะเบียนผู้ใช้ใหม่
 * 
 * @route POST /api/auth/register
 * @param {RegisterRequest} req.body - ข้อมูลการลงทะเบียน
 * @returns {Object} ข้อมูลผู้ใช้และ token
 */
export const register = asyncHandler(async (req: Request, res: Response) => {
  const { username, email, password, fullName = "" } = req.body as RegisterRequest;

  // บันทึกข้อมูลสำหรับการ logging
  const context = {
    ip: req.ip || req.socket.remoteAddress || 'unknown',
    userAgent: req.headers['user-agent'],
    email,
    username
  };

  // ตรวจสอบข้อมูลที่จำเป็น
  if (!username || !email || !password) {
    logMessage(LogLevel.WARN, "Registration attempt with missing required fields", null, context);
    throw new ApiError(400, "กรุณากรอกข้อมูลให้ครบถ้วน", "MISSING_FIELDS");
  }

  try {
    // 1. ตรวจสอบ username
    const usernameValidation = validateUsername(username);
    if (!usernameValidation.isValid) {
      logMessage(LogLevel.WARN, "Username validation failed during registration", null, {
        ...context,
        reason: usernameValidation.message
      });
      
      return res.status(400).json({
        success: false,
        message: usernameValidation.message,
        field: "username",
        code: "INVALID_USERNAME"
      });
    }

    // 2. ตรวจสอบ email
    const emailValidation = validateEmail(email);
    if (!emailValidation.isValid) {
      logMessage(LogLevel.WARN, "Email validation failed during registration", null, {
        ...context,
        reason: emailValidation.message
      });
      
      return res.status(400).json({
        success: false,
        message: emailValidation.message,
        field: "email",
        code: "INVALID_EMAIL"
      });
    }

    // 3. ตรวจสอบรหัสผ่าน
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.isValid) {
      logMessage(LogLevel.WARN, "Password validation failed during registration", null, {
        ...context,
        reason: passwordValidation.message
      });
      
      return res.status(400).json({
        success: false,
        message: passwordValidation.message,
        field: "password",
        code: "INVALID_PASSWORD"
      });
    }

    // ตรวจสอบว่า username มีอยู่แล้วหรือไม่
    const existingUsername = await prisma.user.findUnique({ where: { username } });
    if (existingUsername) {
      logMessage(LogLevel.WARN, "Registration attempt with existing username", null, context);
      
      return res.status(400).json({
        success: false,
        message: "Username นี้มีผู้ใช้งานแล้ว",
        field: "username",
        code: "USERNAME_EXISTS"
      });
    }

    // ตรวจสอบว่า email มีอยู่แล้วหรือไม่
    const existingEmail = await prisma.user.findUnique({ where: { email } });
    if (existingEmail) {
      logMessage(LogLevel.WARN, "Registration attempt with existing email", null, context);
      
      return res.status(400).json({
        success: false,
        message: "อีเมลนี้มีผู้ใช้งานแล้ว",
        field: "email",
        code: "EMAIL_EXISTS"
      });
    }

    // เข้ารหัสรหัสผ่าน
    const hashedPassword = await hashPassword(password);

    // สร้างผู้ใช้ใหม่
    const user = await prisma.user.create({
      data: {
        username,
        fullName,
        email,
        password: hashedPassword,
        provider: "local",
        twoFactorEnabled: false,
      },
    });

    // อัพเดท context ด้วย userId
    Object.assign(context, { userId: user.id });
    logMessage(LogLevel.INFO, "User registered successfully", null, context);

    // สร้าง token
    const token = generateToken(user);

    // ส่งอีเมลต้อนรับ (ไม่ต้องรอการส่งอีเมลเสร็จ)
    try {
      const welcomeEmailHTML = createWelcomeEmailTemplate(user.fullName, user.username);
      sendEmail(user.email, "ยินดีต้อนรับสู่ JobsDB!", welcomeEmailHTML)
        .then(sent => {
          if (sent) {
            logMessage(LogLevel.INFO, "Welcome email sent successfully", null, context);
          } else {
            logMessage(LogLevel.WARN, "Failed to send welcome email", null, context);
          }
        })
        .catch(error => {
          logMessage(LogLevel.ERROR, "Error sending welcome email", error as Error, context);
        });
    } catch (emailError) {
      // เพียงบันทึก log แต่ไม่ขัดขวางการลงทะเบียน
      logMessage(LogLevel.ERROR, "Error preparing welcome email", emailError as Error, context);
    }

    // ส่งข้อมูลผู้ใช้กลับไป
    res.status(201).json({
      success: true,
      message: "ลงทะเบียนผู้ใช้งานเรียบร้อยแล้ว",
      token,
      user: formatUserResponse(user),
    });
  } catch (error) {
    throw logAndCreateApiError(
      500, 
      "เกิดข้อผิดพลาดในการลงทะเบียน กรุณาลองใหม่อีกครั้ง", 
      error as Error, 
      context
    );
  }
});

/**
 * ตรวจสอบว่า username หรือ email มีอยู่ในระบบแล้วหรือไม่
 * 
 * @route POST /api/auth/check-availability
 * @param {Object} req.body - ข้อมูลที่ส่งมา
 * @param {string} [req.body.username] - Username ที่ต้องการตรวจสอบ
 * @param {string} [req.body.email] - Email ที่ต้องการตรวจสอบ
 */
export const checkAvailability = asyncHandler(async (req: Request, res: Response) => {
  const { username, email } = req.body;
  
  // บันทึกข้อมูลสำหรับการ logging
  const context = {
    ip: req.ip || req.socket.remoteAddress || 'unknown',
    userAgent: req.headers['user-agent'],
    username,
    email
  };

  if (!username && !email) {
    logMessage(LogLevel.WARN, "Availability check without username or email", null, context);
    throw new ApiError(400, "กรุณาระบุ username หรือ email", "MISSING_FIELDS");
  }

  try {
    const result: { 
      username?: { exists: boolean; valid: boolean; message?: string; },
      email?: { exists: boolean; valid: boolean; message?: string; }
    } = {};

    // ตรวจสอบ username
    if (username) {
      // ตรวจสอบความถูกต้องของ username
      const usernameValidation = validateUsername(username);
      
      if (!usernameValidation.isValid) {
        result.username = { 
          exists: false, 
          valid: false, 
          message: usernameValidation.message 
        };
      } else {
        // ตรวจสอบว่ามีในระบบหรือไม่
        const existingUsername = await prisma.user.findUnique({ where: { username } });
        result.username = { 
          exists: !!existingUsername, 
          valid: true 
        };
      }
    }

    // ตรวจสอบ email
    if (email) {
      // ตรวจสอบความถูกต้องของ email
      const emailValidation = validateEmail(email);
      
      if (!emailValidation.isValid) {
        result.email = { 
          exists: false, 
          valid: false, 
          message: emailValidation.message 
        };
      } else {
        // ตรวจสอบว่ามีในระบบหรือไม่
        const existingEmail = await prisma.user.findUnique({ where: { email } });
        result.email = { 
          exists: !!existingEmail, 
          valid: true 
        };
      }
    }

    logMessage(LogLevel.INFO, "Availability check completed", null, {
      ...context,
      result
    });

    res.status(200).json({
      success: true,
      result
    });
  } catch (error) {
    throw logAndCreateApiError(
      500, 
      "เกิดข้อผิดพลาดในการตรวจสอบข้อมูล", 
      error as Error, 
      context
    );
  }
});

/**
 * สร้าง username จากชื่อผู้ใช้ที่ให้มา
 * ใช้สำหรับการลงทะเบียนผ่าน OAuth ที่ไม่มี username
 * 
 * @param baseName ชื่อเริ่มต้นสำหรับสร้าง username
 * @returns Promise<string> username ที่ไม่ซ้ำกับในระบบ
 */
export const generateUsername = async (baseName: string): Promise<string> => {
  try {
    // ลบอักขระที่ไม่ได้รับอนุญาตและแทนที่ช่องว่างด้วย underscore
    let username = baseName
      .toLowerCase()
      .replace(/[^a-z0-9_]/g, '')
      .replace(/\s+/g, '_');
    
    // ตัด username ให้สั้นลงหากยาวเกินไป
    if (username.length > 15) {
      username = username.substring(0, 15);
    }
    
    // เพิ่มความยาวหากสั้นเกินไป
    if (username.length < 3) {
      username = username + 'user';
    }
    
    // ตรวจสอบว่า username นี้มีอยู่แล้วหรือไม่
    const existingUser = await prisma.user.findUnique({
      where: { username },
    });
    
    if (!existingUser) {
      return username;
    }
    
    // หากมีอยู่แล้ว ให้เพิ่มตัวเลขต่อท้าย
    let counter = 1;
    let newUsername = `${username}${counter}`;
    
    // วนลูปจนกว่าจะพบ username ที่ไม่ซ้ำ
    while (true) {
      const existingUser = await prisma.user.findUnique({
        where: { username: newUsername },
      });
      
      if (!existingUser) {
        return newUsername;
      }
      
      counter++;
      newUsername = `${username}${counter}`;
      
      // ป้องกันการวนลูปไม่รู้จบ
      if (counter > 1000) {
        // ถ้าวนลูปมากเกินไป ให้เพิ่ม timestamp เพื่อให้มั่นใจว่าไม่ซ้ำ
        const timestamp = Date.now().toString().slice(-6);
        return `${username}_${timestamp}`;
      }
    }
  } catch (error) {
    console.error("❌ Error generating username:", error);
    // สร้าง username แบบ fallback ในกรณีที่เกิดข้อผิดพลาด
    const randomSuffix = Math.floor(Math.random() * 10000).toString().padStart(4, '0');
    return `user_${randomSuffix}`;
  }
};