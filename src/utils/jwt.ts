// src/utils/jwt.ts
import jwt from 'jsonwebtoken';
import { CONFIG } from '../config/env';

// กำหนดประเภทข้อมูลสำหรับ user
export interface UserData {
  id: string;
  email: string;
  username?: string;
  fullName?: string | null;
  profileImage?: string | null;
  twoFactorEnabled?: boolean;
}

// กำหนดประเภทข้อมูลสำหรับ payload ของ token
export interface TokenPayload {
  id: string;
  email: string;
  temp?: boolean;
  deviceId?: string;
}

/**
 * สร้าง JWT token สำหรับผู้ใช้ที่ยืนยันตัวตนแล้ว
 */
export const generateToken = (user: UserData, rememberMe: boolean = false): string => {
  const payload: TokenPayload = { 
    id: user.id, 
    email: user.email 
  };
  
  return jwt.sign(
    payload, 
    CONFIG.JWT.SECRET, 
    { expiresIn: rememberMe ? CONFIG.JWT.EXTENDED_LIFETIME : CONFIG.JWT.LIFETIME }
  );
};

/**
 * สร้าง token ชั่วคราวสำหรับการยืนยัน 2FA
 */
export const generateTempToken = (user: UserData, deviceId?: string): string => {
  const payload: TokenPayload = {
    id: user.id,
    email: user.email,
    temp: true,
    deviceId
  };
  
  return jwt.sign(payload, CONFIG.JWT.SECRET, { 
    expiresIn: CONFIG.JWT.TEMP_LIFETIME 
  });
};

/**
 * ตรวจสอบความถูกต้องของ token
 */
export const verifyToken = (token: string): TokenPayload | null => {
  try {
    return jwt.verify(token, CONFIG.JWT.SECRET) as TokenPayload;
  } catch (error) {
    return null;
  }
};