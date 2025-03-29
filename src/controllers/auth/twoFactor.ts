// src/controllers/auth/twoFactor.ts
import { Request, Response } from 'express';
import prisma from '../../utils/prisma';
import { verifyToken, generateToken } from '../../utils/jwt';
import { saveTrustedDevice } from '../../utils/security';
import { formatUserResponse } from './index';
import { VerifyOTPRequest } from '../../types/auth';

/**
 * เปิด/ปิดการยืนยันตัวตนแบบสองขั้นตอน
 */
export const toggleTwoFactor = async (req: Request, res: Response) => {
  try {
    const user = req.user;
    const { enable } = req.body;

    if (typeof enable !== "boolean") {
      return res.status(400).json({
        success: false,
        message: "กรุณาระบุสถานะการเปิด/ปิดการใช้งาน 2FA",
      });
    }

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "ไม่พบข้อมูลผู้ใช้",
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
    }

    return res.status(200).json({
      success: true,
      message: enable
        ? "เปิดใช้งานการยืนยันตัวตนแบบสองขั้นตอนเรียบร้อยแล้ว"
        : "ปิดใช้งานการยืนยันตัวตนแบบสองขั้นตอนเรียบร้อยแล้ว",
      twoFactorEnabled: enable,
    });
  } catch (error) {
    console.error("❌ Toggle 2FA error:", error);
    res.status(500).json({
      success: false,
      message: "เกิดข้อผิดพลาด กรุณาลองใหม่อีกครั้ง",
    });
  }
};

/**
 * ตรวจสอบ OTP สำหรับ 2FA
 */
export const verifyOTP = async (req: Request, res: Response) => {
  try {
    const { otp, tempToken, rememberDevice = false } = req.body as VerifyOTPRequest;

    if (!otp || !tempToken) {
      return res.status(400).json({
        success: false,
        message: "กรุณากรอกข้อมูลให้ครบถ้วน",
      });
    }

    // ตรวจสอบและถอดรหัส token ชั่วคราว
    const decoded = verifyToken(tempToken);
    if (!decoded || !decoded.temp) {
      return res.status(400).json({
        success: false,
        message: "Token ไม่ถูกต้องหรือหมดอายุแล้ว",
      });
    }

    // ค้นหาผู้ใช้
    const user = await prisma.user.findUnique({
      where: { id: decoded.id },
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "ไม่พบผู้ใช้งาน",
      });
    }

    // ตรวจสอบ OTP
    if (
      user.twoFactorOTP !== otp ||
      !user.twoFactorExpires ||
      user.twoFactorExpires < new Date()
    ) {
      return res.status(400).json({
        success: false,
        message: "รหัส OTP ไม่ถูกต้องหรือหมดอายุแล้ว",
      });
    }

    // ตรวจสอบว่านี่เป็น token ชั่วคราวล่าสุดหรือไม่
    if (user.lastTempToken !== tempToken) {
      return res.status(400).json({
        success: false,
        message: "ลิงก์ยืนยันนี้ไม่สามารถใช้งานได้แล้ว กรุณาเข้าสู่ระบบอีกครั้ง",
      });
    }

    // ล้าง OTP หลังจากใช้งาน
    await prisma.user.update({
      where: { id: user.id },
      data: {
        twoFactorOTP: null,
        twoFactorExpires: null,
      },
    });

    // จดจำอุปกรณ์ถ้ามีการร้องขอและมี deviceId
    if (rememberDevice && decoded.deviceId) {
      await saveTrustedDevice(user.id, decoded.deviceId);
    }

    // สร้าง token สำหรับการเข้าสู่ระบบ
    const token = generateToken(user);

    res.status(200).json({
      success: true,
      token,
      user: formatUserResponse(user),
    });
  } catch (error) {
    console.error("❌ Verify OTP error:", error);
    res.status(500).json({
      success: false,
      message: "เกิดข้อผิดพลาด กรุณาลองใหม่อีกครั้ง",
    });
  }
};

/**
 * ตรวจสอบความถูกต้องของ token ชั่วคราว
 */
export const verifyTempToken = async (req: Request, res: Response) => {
  try {
    const { token } = req.body;
    
    if (!token) {
      return res.status(400).json({
        success: false,
        message: 'ไม่พบ Token',
      });
    }
    
    // ตรวจสอบ token
    const decoded = verifyToken(token);
    if (!decoded || !decoded.temp) {
      return res.status(400).json({
        success: false,
        message: 'Token ไม่ถูกต้องหรือหมดอายุแล้ว',
      });
    }
    
    // ค้นหาผู้ใช้
    const user = await prisma.user.findUnique({
      where: { id: decoded.id },
    });
    
    // ตรวจสอบว่านี่เป็น token ชั่วคราวล่าสุดหรือไม่
    if (!user || user.lastTempToken !== token) {
      return res.status(200).json({
        success: false,
        message: 'ลิงก์ยืนยันนี้ไม่สามารถใช้งานได้แล้ว',
      });
    }
    
    return res.status(200).json({
      success: true,
      message: 'Token ถูกต้อง',
    });
  } catch (error) {
    console.error('❌ Verify temp token error:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาด กรุณาลองใหม่อีกครั้ง',
    });
  }
};