// src/controllers/auth/register.ts
import { Request, Response } from 'express';
import prisma from '../../utils/prisma';
import { hashPassword } from '../../utils/security';
import { validateUsername, validatePassword, validateEmail } from '../../utils/validation';
import { generateToken } from '../../utils/jwt';
import { formatUserResponse } from './index';
import { RegisterRequest } from '../../types/auth';

/**
 * ลงทะเบียนผู้ใช้ใหม่
 */
export const register = async (req: Request, res: Response) => {
  try {
    const { username, email, password, fullName = "" } = req.body as RegisterRequest;

    // ตรวจสอบความถูกต้องของข้อมูล
    // 1. ตรวจสอบ username
    const usernameValidation = validateUsername(username);
    if (!usernameValidation.isValid) {
      return res.status(400).json({
        success: false,
        message: usernameValidation.message,
      });
    }

    // 2. ตรวจสอบ email
    const emailValidation = validateEmail(email);
    if (!emailValidation.isValid) {
      return res.status(400).json({
        success: false,
        message: emailValidation.message,
      });
    }

    // 3. ตรวจสอบรหัสผ่าน
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.isValid) {
      return res.status(400).json({
        success: false,
        message: passwordValidation.message,
      });
    }

    // ตรวจสอบว่า username มีอยู่แล้วหรือไม่
    const existingUsername = await prisma.user.findUnique({ where: { username } });
    if (existingUsername) {
      return res.status(400).json({
        success: false,
        message: "Username นี้มีผู้ใช้งานแล้ว",
      });
    }

    // ตรวจสอบว่า email มีอยู่แล้วหรือไม่
    const existingEmail = await prisma.user.findUnique({ where: { email } });
    if (existingEmail) {
      return res.status(400).json({
        success: false,
        message: "อีเมลนี้มีผู้ใช้งานแล้ว",
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

    // สร้าง token
    const token = generateToken(user);

    res.status(201).json({
      success: true,
      message: "ลงทะเบียนผู้ใช้งานเรียบร้อยแล้ว",
      token,
      user: formatUserResponse(user),
    });
  } catch (error) {
    console.error("❌ Registration error:", error);
    res.status(500).json({
      success: false,
      message: "เกิดข้อผิดพลาด กรุณาลองใหม่อีกครั้ง",
    });
  }
};

/**
 * สร้าง username จากชื่อผู้ใช้ที่ให้มา
 * ใช้สำหรับการลงทะเบียนผ่าน OAuth ที่ไม่มี username
 */
export const generateUsername = async (baseName: string): Promise<string> => {
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
  
  while (true) {
    const existingUser = await prisma.user.findUnique({
      where: { username: newUsername },
    });
    
    if (!existingUser) {
      return newUsername;
    }
    
    counter++;
    newUsername = `${username}${counter}`;
  }
};