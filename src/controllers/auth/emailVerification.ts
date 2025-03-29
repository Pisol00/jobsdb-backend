// src/controllers/auth/emailVerification.ts
import { Request, Response } from 'express';
import crypto from 'crypto';
import prisma from '../../utils/prisma';
import { generateToken } from '../../utils/jwt';
import { sendEmailVerification } from '../../utils/email';
import { generateOTP } from '../../utils/security';
import { CONFIG } from '../../config/env';
import { formatUserResponse } from './index';
import { asyncHandler } from '../../middleware/asyncHandler';
import { logMessage, LogLevel } from '../../utils/errorLogger';

/**
 * สร้างและส่ง OTP สำหรับยืนยันอีเมล
 */
export const createEmailVerification = async (userId: string): Promise<{
  otp: string;
  verifyToken: string;
  success: boolean;
}> => {
  try {
    // ค้นหาผู้ใช้
    const user = await prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      return {
        otp: '',
        verifyToken: '',
        success: false,
      };
    }

    // สร้าง OTP และ Token
    const otp = generateOTP();
    const verifyToken = crypto.randomBytes(32).toString('hex');
    const verifyTokenHashed = crypto.createHash('sha256').update(verifyToken).digest('hex');
    const verifyExpires = new Date(Date.now() + CONFIG.OTP_EXPIRY);

    // บันทึกข้อมูลยืนยันอีเมลในฐานข้อมูล
    await prisma.user.update({
      where: { id: userId },
      data: {
        twoFactorOTP: otp,
        emailVerifyToken: verifyTokenHashed,
        emailVerifyExpires: verifyExpires,
      },
    });

    // ส่งอีเมลยืนยัน
    const emailSent = await sendEmailVerification(
      user.email,
      otp,
      verifyToken,
      user.fullName || undefined
    );

    return {
      otp,
      verifyToken,
      success: emailSent,
    };
  } catch (error) {
    logMessage(
      LogLevel.ERROR,
      `Error creating email verification for user ${userId}`,
      error as Error
    );
    return {
      otp: '',
      verifyToken: '',
      success: false,
    };
  }
};

/**
 * ตรวจสอบความถูกต้องของ token ยืนยันอีเมล
 */
export const verifyEmailToken = asyncHandler(async (req: Request, res: Response) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({
      success: false,
      message: 'ไม่พบ Token',
    });
  }

  // เข้ารหัส token สำหรับการตรวจสอบ
  const verifyTokenHashed = crypto.createHash('sha256').update(token).digest('hex');

  // ค้นหาผู้ใช้ที่มี token นี้
  const user = await prisma.user.findFirst({
    where: {
      emailVerifyToken: verifyTokenHashed,
      emailVerifyExpires: {
        gt: new Date(),
      },
    },
  });

  if (!user) {
    return res.status(400).json({
      success: false,
      message: 'Token ไม่ถูกต้องหรือหมดอายุแล้ว',
    });
  }

  res.status(200).json({
    success: true,
    message: 'Token ถูกต้อง',
  });
});

/**
 * ยืนยันอีเมลด้วย OTP
 */
export const verifyEmailWithOTP = asyncHandler(async (req: Request, res: Response) => {
  const { otp, token } = req.body;

  if (!otp) {
    return res.status(400).json({
      success: false,
      message: 'กรุณากรอกรหัส OTP',
    });
  }

  // กรณีมีการส่ง token มาด้วย
  let user;
  if (token) {
    // เข้ารหัส token สำหรับการตรวจสอบ
    const verifyTokenHashed = crypto.createHash('sha256').update(token).digest('hex');

    // ค้นหาผู้ใช้ที่มี token นี้
    user = await prisma.user.findFirst({
      where: {
        emailVerifyToken: verifyTokenHashed,
        emailVerifyExpires: {
          gt: new Date(),
        },
      },
    });
  } else {
    // กรณีไม่มี token ให้ค้นหาจาก OTP
    user = await prisma.user.findFirst({
      where: {
        twoFactorOTP: otp,
        emailVerifyExpires: {
          gt: new Date(),
        },
      },
    });
  }

  if (!user) {
    return res.status(400).json({
      success: false,
      message: 'รหัส OTP ไม่ถูกต้องหรือหมดอายุแล้ว',
    });
  }

  // ตรวจสอบว่า OTP ถูกต้อง (กรณีมี token)
  if (token && user.twoFactorOTP !== otp) {
    return res.status(400).json({
      success: false,
      message: 'รหัส OTP ไม่ถูกต้อง',
    });
  }

  // อัปเดตสถานะการยืนยันอีเมล
  await prisma.user.update({
    where: { id: user.id },
    data: {
      isEmailVerified: true,
      emailVerifyToken: null,
      emailVerifyExpires: null,
      twoFactorOTP: null,
    },
  });

  // สร้าง token สำหรับเข้าสู่ระบบ
  const jwtToken = generateToken(user);

  res.status(200).json({
    success: true,
    message: 'ยืนยันอีเมลสำเร็จ',
    token: jwtToken,
    user: formatUserResponse(user),
  });
});

/**
 * ส่ง OTP ยืนยันอีเมลใหม่
 */
export const resendEmailVerification = asyncHandler(async (req: Request, res: Response) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({
      success: false,
      message: 'กรุณาระบุอีเมล',
    });
  }

  // ค้นหาผู้ใช้จากอีเมล
  const user = await prisma.user.findUnique({
    where: { email },
  });

  if (!user) {
    return res.status(404).json({
      success: false,
      message: 'ไม่พบผู้ใช้จากอีเมลนี้',
    });
  }

  // ตรวจสอบว่าอีเมลยืนยันแล้วหรือไม่
  if (user.isEmailVerified) {
    return res.status(400).json({
      success: false,
      message: 'อีเมลนี้ได้รับการยืนยันแล้ว',
    });
  }

  // สร้าง OTP และส่งอีเมลยืนยันใหม่
  const { success } = await createEmailVerification(user.id);

  if (success) {
    res.status(200).json({
      success: true,
      message: 'ส่งอีเมลยืนยันใหม่เรียบร้อยแล้ว',
    });
  } else {
    res.status(500).json({
      success: false,
      message: 'ไม่สามารถส่งอีเมลยืนยันได้ กรุณาลองใหม่อีกครั้ง',
    });
  }
});