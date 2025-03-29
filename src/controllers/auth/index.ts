// src/controllers/auth/index.ts

// นำเข้าและส่งออกฟังก์ชันจากไฟล์อื่นๆ
export * from './register';
export * from './login';
export * from './password';
export * from './twoFactor';

// ฟังก์ชั่นอื่นๆ ที่ไม่ได้แยกไฟล์
import { Request, Response } from 'express';
import { FormattedUser } from '../../types/auth';

/**
 * ฟอร์แมตผู้ใช้สำหรับการตอบกลับ (ลบข้อมูลที่ละเอียดอ่อน)
 */
export const formatUserResponse = (user: any): FormattedUser => {
  return {
    id: user.id,
    username: user.username,
    fullName: user.fullName,
    email: user.email,
    profileImage: user.profileImage,
    twoFactorEnabled: user.twoFactorEnabled
  };
};

/**
 * ดึงข้อมูลผู้ใช้ปัจจุบัน
 */
export const getCurrentUser = async (req: Request, res: Response) => {
  try {
    const user = req.user;
    
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'ไม่พบข้อมูลผู้ใช้',
      });
    }
    
    res.status(200).json({
      success: true,
      user: formatUserResponse(user),
    });
  } catch (error) {
    console.error("❌ Get current user error:", error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาด กรุณาลองใหม่อีกครั้ง',
    });
  }
};