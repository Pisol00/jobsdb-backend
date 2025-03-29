// src/controllers/auth/password.ts
import { Request, Response } from 'express';
import crypto from 'crypto';
import prisma from '../../utils/prisma';
import { hashPassword, constantTimeCompare } from '../../utils/security';
import { validatePassword } from '../../utils/validation';
import { sendEmail, createPasswordResetEmailTemplate } from '../../utils/email';
import { CONFIG } from '../../config/env';
import { ResetPasswordRequest } from '../../types/auth';
import { logMessage, LogLevel, logAndCreateApiError } from '../../utils/errorLogger';
import { asyncHandler } from '../../middleware/asyncHandler';
import { ApiError } from '../../middleware/errorHandler';

/**
 * เริ่มกระบวนการลืมรหัสผ่าน - ส่งอีเมลพร้อมลิงก์สำหรับรีเซ็ตรหัสผ่าน
 * 
 * @route POST /api/auth/forgot-password
 * @param {Object} req.body - ข้อมูลที่ส่งมา
 * @param {string} req.body.email - อีเมลของผู้ใช้ที่ต้องการรีเซ็ตรหัสผ่าน
 */
export const forgotPassword = asyncHandler(async (req: Request, res: Response) => {
  const { email } = req.body;

  // บันทึกข้อมูลสำหรับการบันทึก log
  const context = {
    ip: req.ip || req.socket.remoteAddress,
    userAgent: req.headers['user-agent'],
    email
  };

  if (!email) {
    logMessage(LogLevel.WARN, "Forgot password attempt without email", null, context);
    throw new ApiError(400, "กรุณากรอกอีเมล", "MISSING_EMAIL");
  }

  try {
    // ค้นหาผู้ใช้ตามอีเมล
    const user = await prisma.user.findUnique({ where: { email } });

    // ไม่เปิดเผยว่ามีอีเมลในระบบหรือไม่ เพื่อความปลอดภัย
    if (!user) {
      // บันทึก log แต่ส่งข้อความเหมือนกับกรณีที่พบผู้ใช้
      logMessage(LogLevel.INFO, "Forgot password requested for non-existent email", null, context);
      
      return res.status(200).json({
        success: true,
        message: "หากอีเมลนี้มีอยู่ในระบบ เราได้ส่งลิงก์รีเซ็ตรหัสผ่านไปยังอีเมลแล้ว",
      });
    }

    // เพิ่มข้อมูล userId ใน context
    Object.assign(context, { userId: user.id });

    // ตรวจสอบว่าผู้ใช้ลงทะเบียนผ่าน OAuth หรือไม่
    if (user.provider && user.provider !== "local") {
      logMessage(LogLevel.WARN, "Forgot password requested for OAuth account", null, context);
      
      return res.status(400).json({
        success: false,
        message: `บัญชีนี้ลงทะเบียนด้วย ${user.provider} กรุณาใช้บริการ ${user.provider} ในการเข้าสู่ระบบ`,
        code: "OAUTH_ACCOUNT",
        provider: user.provider
      });
    }

    // ตรวจสอบว่าได้ขอรีเซ็ตรหัสผ่านไปเมื่อไม่นานนี้หรือไม่
    // ป้องกันการส่งอีเมลซ้ำๆ ในระยะเวลาสั้นๆ
    if (user.resetPasswordExpires && user.resetPasswordExpires > new Date(Date.now() - 1 * 60 * 1000)) { // 1 นาที
      logMessage(LogLevel.WARN, "Forgot password request throttled", null, context);
      
      return res.status(429).json({
        success: false,
        message: "กรุณารอสักครู่ก่อนขอรีเซ็ตรหัสผ่านอีกครั้ง",
        code: "REQUEST_THROTTLED"
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
      logMessage(LogLevel.INFO, "Password reset email sent successfully", null, context);
      
      return res.status(200).json({
        success: true,
        message: "ส่งลิงก์รีเซ็ตรหัสผ่านไปยังอีเมลของคุณแล้ว",
        expiresAt: resetTokenExpires.getTime()
      });
    } else {
      // ล้าง token ในกรณีที่ส่งอีเมลไม่สำเร็จ
      await prisma.user.update({
        where: { id: user.id },
        data: {
          resetPasswordToken: null,
          resetPasswordExpires: null,
        },
      });
      
      logMessage(LogLevel.ERROR, "Failed to send password reset email", null, context);
      
      throw new ApiError(500, "ไม่สามารถส่งอีเมลได้ กรุณาลองใหม่อีกครั้ง", "EMAIL_SEND_FAILED");
    }
  } catch (error) {
    // ตรวจสอบว่าเป็น ApiError ที่สร้างไว้แล้วหรือไม่
    if (error instanceof ApiError) {
      throw error;
    }
    
    // สร้าง ApiError ใหม่และบันทึก log
    throw logAndCreateApiError(
      500, 
      "เกิดข้อผิดพลาด กรุณาลองใหม่อีกครั้ง", 
      error as Error, 
      context
    );
  }
});

/**
 * ตรวจสอบความถูกต้องของ token รีเซ็ตรหัสผ่าน
 * 
 * @route POST /api/auth/verify-reset-token
 * @param {Object} req.body - ข้อมูลที่ส่งมา
 * @param {string} req.body.token - Token สำหรับรีเซ็ตรหัสผ่าน
 */
export const verifyResetToken = asyncHandler(async (req: Request, res: Response) => {
  const { token } = req.body;
  
  // บันทึกข้อมูลสำหรับการบันทึก log
  const context = {
    ip: req.ip || req.socket.remoteAddress,
    userAgent: req.headers['user-agent'],
    // ไม่บันทึก token เพื่อความปลอดภัย
  };

  if (!token) {
    logMessage(LogLevel.WARN, "Reset token verification without token", null, context);
    throw new ApiError(400, "ไม่พบ Token", "MISSING_TOKEN");
  }

  try {
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
      logMessage(LogLevel.WARN, "Invalid or expired reset token", null, context);
      
      return res.status(400).json({
        success: false,
        message: "Token ไม่ถูกต้องหรือหมดอายุแล้ว",
        code: "INVALID_TOKEN"
      });
    }

    // เพิ่มข้อมูล userId ใน context
    Object.assign(context, { userId: user.id });
    logMessage(LogLevel.INFO, "Reset token verified successfully", null, context);

    return res.status(200).json({
      success: true,
      message: "Token ถูกต้อง",
      expiresAt: user.resetPasswordExpires?.getTime(),
      email: user.email.replace(/(.{2})(.*)(?=@)/, (_, start, rest) => start + '*'.repeat(rest.length)) // ปกปิดบางส่วนของอีเมล
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
 * รีเซ็ตรหัสผ่านของผู้ใช้
 * 
 * @route POST /api/auth/reset-password
 * @param {ResetPasswordRequest} req.body - ข้อมูลที่ส่งมา
 * @param {string} req.body.token - Token สำหรับรีเซ็ตรหัสผ่าน
 * @param {string} req.body.password - รหัสผ่านใหม่
 */
export const resetPassword = asyncHandler(async (req: Request, res: Response) => {
  const { token, password } = req.body as ResetPasswordRequest;
  
  // บันทึกข้อมูลสำหรับการบันทึก log
  const context = {
    ip: req.ip || req.socket.remoteAddress,
    userAgent: req.headers['user-agent'],
    // ไม่บันทึก token และรหัสผ่านเพื่อความปลอดภัย
  };

  if (!token || !password) {
    logMessage(LogLevel.WARN, "Reset password with missing data", null, context);
    throw new ApiError(400, "กรุณากรอกข้อมูลให้ครบถ้วน", "MISSING_DATA");
  }

  try {
    // ตรวจสอบรหัสผ่าน
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.isValid) {
      logMessage(LogLevel.WARN, "Password validation failed in reset password", null, context);
      
      return res.status(400).json({
        success: false,
        message: passwordValidation.message,
        code: "INVALID_PASSWORD"
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
      logMessage(LogLevel.WARN, "Reset password with invalid or expired token", null, context);
      
      return res.status(400).json({
        success: false,
        message: "Token ไม่ถูกต้องหรือหมดอายุแล้ว",
        code: "INVALID_TOKEN"
      });
    }

    // เพิ่มข้อมูล userId ใน context
    Object.assign(context, { userId: user.id });

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

    logMessage(LogLevel.INFO, "Password reset successfully", null, context);

    // ล้างอุปกรณ์ที่เชื่อถือทั้งหมดเมื่อรีเซ็ตรหัสผ่าน (เพื่อความปลอดภัย)
    try {
      await prisma.trustedDevice.deleteMany({
        where: { userId: user.id },
      });
      
      logMessage(LogLevel.INFO, "Trusted devices cleared after password reset", null, context);
    } catch (error) {
      // เพียงบันทึก log แต่ไม่ต้องหยุดการทำงาน
      logMessage(LogLevel.ERROR, "Error clearing trusted devices", error as Error, context);
    }

    return res.status(200).json({
      success: true,
      message: "รีเซ็ตรหัสผ่านสำเร็จ",
    });
  } catch (error) {
    throw logAndCreateApiError(
      500, 
      "เกิดข้อผิดพลาดในการรีเซ็ตรหัสผ่าน", 
      error as Error, 
      context
    );
  }
});

/**
 * เปลี่ยนรหัสผ่านโดยผู้ใช้ที่เข้าสู่ระบบแล้ว
 * 
 * @route POST /api/auth/change-password
 * @param {Object} req.body - ข้อมูลที่ส่งมา
 * @param {string} req.body.currentPassword - รหัสผ่านปัจจุบัน
 * @param {string} req.body.newPassword - รหัสผ่านใหม่
 */
export const changePassword = asyncHandler(async (req: Request, res: Response) => {
  const { currentPassword, newPassword } = req.body;
  const user = req.user;
  
  // บันทึกข้อมูลสำหรับการบันทึก log
  const context = {
    ip: req.ip || req.socket.remoteAddress,
    userAgent: req.headers['user-agent'],
    userId: user?.id
  };

  if (!user) {
    throw new ApiError(401, "กรุณาเข้าสู่ระบบ", "UNAUTHORIZED");
  }

  if (!currentPassword || !newPassword) {
    throw new ApiError(400, "กรุณากรอกข้อมูลให้ครบถ้วน", "MISSING_DATA");
  }

  try {
    // ตรวจสอบว่าบัญชีใช้การยืนยันตัวตนแบบปกติหรือไม่
    if (user.provider && user.provider !== "local") {
      logMessage(LogLevel.WARN, "Change password attempt for OAuth account", null, context);
      
      return res.status(400).json({
        success: false,
        message: `บัญชีนี้ลงทะเบียนด้วย ${user.provider} ไม่สามารถเปลี่ยนรหัสผ่านได้`,
        code: "OAUTH_ACCOUNT"
      });
    }

    // ตรวจสอบว่ามีรหัสผ่านหรือไม่
    if (!user.password) {
      logMessage(LogLevel.ERROR, "User without password trying to change password", null, context);
      
      return res.status(400).json({
        success: false,
        message: "ไม่สามารถเปลี่ยนรหัสผ่านได้ กรุณาติดต่อผู้ดูแลระบบ",
        code: "NO_PASSWORD"
      });
    }

    // ตรวจสอบรหัสผ่านปัจจุบัน
    const isPasswordCorrect = await comparePassword(currentPassword, user.password);
    
    if (!isPasswordCorrect) {
      logMessage(LogLevel.WARN, "Incorrect current password during change password", null, context);
      
      return res.status(400).json({
        success: false,
        message: "รหัสผ่านปัจจุบันไม่ถูกต้อง",
        code: "INCORRECT_PASSWORD"
      });
    }

    // ตรวจสอบความถูกต้องของรหัสผ่านใหม่
    const passwordValidation = validatePassword(newPassword);
    if (!passwordValidation.isValid) {
      logMessage(LogLevel.WARN, "New password validation failed", null, context);
      
      return res.status(400).json({
        success: false,
        message: passwordValidation.message,
        code: "INVALID_PASSWORD"
      });
    }

    // เข้ารหัสรหัสผ่านใหม่
    const hashedPassword = await hashPassword(newPassword);

    // อัปเดตรหัสผ่าน
    await prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashedPassword,
      },
    });

    logMessage(LogLevel.INFO, "Password changed successfully", null, context);

    // ล้างอุปกรณ์ที่เชื่อถือทั้งหมดเมื่อเปลี่ยนรหัสผ่าน (เพื่อความปลอดภัย)
    try {
      await prisma.trustedDevice.deleteMany({
        where: { userId: user.id },
      });
      
      logMessage(LogLevel.INFO, "Trusted devices cleared after password change", null, context);
    } catch (error) {
      // เพียงบันทึก log แต่ไม่ต้องหยุดการทำงาน
      logMessage(LogLevel.ERROR, "Error clearing trusted devices", error as Error, context);
    }

    return res.status(200).json({
      success: true,
      message: "เปลี่ยนรหัสผ่านสำเร็จ",
    });
  } catch (error) {
    throw logAndCreateApiError(
      500, 
      "เกิดข้อผิดพลาดในการเปลี่ยนรหัสผ่าน", 
      error as Error, 
      context
    );
  }
});