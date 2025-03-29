// src/controllers/auth/password.ts
import { Request, Response } from 'express';
import crypto from 'crypto';
import prisma from '../../../utils/prisma';
import { hashPassword } from '../../../utils/security';
import { validatePassword } from '../../../utils/validation';
import { sendEmail, createPasswordResetEmailTemplate } from '../../../utils/email';
import { CONFIG } from '../../env';
import { ResetPasswordRequest } from '../../../types/auth';

/**
 * เริ่มกระบวนการลืมรหัสผ่าน
 */
export const forgotPassword = async (req: Request, res: Response) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: "กรุณากรอกอีเมล",
      });
    }

    // ค้นหาผู้ใช้ตามอีเมล
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "ไม่พบบัญชีผู้ใช้ที่ใช้อีเมลนี้",
      });
    }

    // ตรวจสอบว่าผู้ใช้ลงทะเบียนผ่าน OAuth หรือไม่
    if (user.provider && user.provider !== "local") {
      return res.status(400).json({
        success: false,
        message: `บัญชีนี้ลงทะเบียนด้วย ${user.provider} กรุณาใช้บริการ ${user.provider} ในการเข้าสู่ระบบ`,
      });
    }

    // สร้าง token สำหรับรีเซ็ตรหัสผ่าน
    const resetToken = crypto.randomBytes(32).toString("hex");
    const resetTokenHashed = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex");

    // กำหนดเวลาหมดอายุของ token (10 นาที)
    const resetTokenExpires = new Date(Date.now() + CONFIG.OTP_EXPIRY);

    // บันทึก token ลงฐานข้อมูล
    await prisma.user.update({
      where: { id: user.id },
      data: {
        resetPasswordToken: resetTokenHashed,
        resetPasswordExpires: resetTokenExpires,
      },
    });

    // สร้าง URL สำหรับรีเซ็ตรหัสผ่าน
    const resetURL = `${CONFIG.FRONTEND_URL}/auth/reset-password?token=${resetToken}`;
    
    // ส่งอีเมล
    const emailHTML = createPasswordResetEmailTemplate(user, resetURL);
    const emailSent = await sendEmail(
      user.email,
      "รีเซ็ตรหัสผ่าน JobsDB ของคุณ",
      emailHTML
    );

    if (emailSent) {
      res.status(200).json({
        success: true,
        message: "ส่งลิงก์รีเซ็ตรหัสผ่านไปยังอีเมลของคุณแล้ว",
      });
    } else {
      res.status(500).json({
        success: false,
        message: "ไม่สามารถส่งอีเมลได้ กรุณาลองใหม่อีกครั้ง",
      });
    }
  } catch (error) {
    console.error("❌ Forgot password error:", error);
    res.status(500).json({
      success: false,
      message: "เกิดข้อผิดพลาด กรุณาลองใหม่อีกครั้ง",
    });
  }
};

/**
 * ตรวจสอบความถูกต้องของ token รีเซ็ตรหัสผ่าน
 */
export const verifyResetToken = async (req: Request, res: Response) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({
        success: false,
        message: "ไม่พบ Token",
      });
    }

    // เข้ารหัส token สำหรับการตรวจสอบ
    const resetTokenHashed = crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

    // ค้นหาผู้ใช้ที่มี token นี้
    const user = await prisma.user.findFirst({
      where: {
        resetPasswordToken: resetTokenHashed,
        resetPasswordExpires: {
          gt: new Date(),
        },
      },
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Token ไม่ถูกต้องหรือหมดอายุแล้ว",
      });
    }

    res.status(200).json({
      success: true,
      message: "Token ถูกต้อง",
    });
  } catch (error) {
    console.error("❌ Verify reset token error:", error);
    res.status(500).json({
      success: false,
      message: "เกิดข้อผิดพลาด กรุณาลองใหม่อีกครั้ง",
    });
  }
};

/**
 * รีเซ็ตรหัสผ่านของผู้ใช้
 */
export const resetPassword = async (req: Request, res: Response) => {
  try {
    const { token, password } = req.body as ResetPasswordRequest;

    if (!token || !password) {
      return res.status(400).json({
        success: false,
        message: "กรุณากรอกข้อมูลให้ครบถ้วน",
      });
    }

    // ตรวจสอบรหัสผ่าน
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.isValid) {
      return res.status(400).json({
        success: false,
        message: passwordValidation.message,
      });
    }

    // เข้ารหัส token สำหรับการตรวจสอบ
    const resetTokenHashed = crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

    // ค้นหาผู้ใช้ที่มี token นี้
    const user = await prisma.user.findFirst({
      where: {
        resetPasswordToken: resetTokenHashed,
        resetPasswordExpires: {
          gt: new Date(),
        },
      },
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Token ไม่ถูกต้องหรือหมดอายุแล้ว",
      });
    }

    // เข้ารหัสรหัสผ่านใหม่
    const hashedPassword = await hashPassword(password);

    // อัพเดทรหัสผ่านและล้าง token รีเซ็ตรหัสผ่าน
    await prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashedPassword,
        resetPasswordToken: null,
        resetPasswordExpires: null,
      },
    });

    res.status(200).json({
      success: true,
      message: "รีเซ็ตรหัสผ่านสำเร็จ",
    });
  } catch (error) {
    console.error("❌ Reset password error:", error);
    res.status(500).json({
      success: false,
      message: "เกิดข้อผิดพลาด กรุณาลองใหม่อีกครั้ง",
    });
  }
};