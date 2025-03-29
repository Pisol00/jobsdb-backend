// src/types/auth.ts
import { User } from '@prisma/client';
import { Request } from 'express';

/**
 * ข้อมูลผู้ใช้ที่จัดรูปแบบแล้วสำหรับส่งกลับให้ client
 */
export interface FormattedUser {
  id: string;
  username: string | null;
  fullName: string | null;
  email: string;
  profileImage: string | null;
  twoFactorEnabled: boolean;
  isEmailVerified?: boolean;
}

/**
 * สถานะการล็อกอิน
 */
export interface LoginStatus {
  isLocked: boolean;
  message?: string;
  remainingTime?: number;
  attemptsLeft?: number;
}

/**
 * ข้อมูลสำหรับ request การลงทะเบียน
 */
export interface RegisterRequest {
  username: string;
  email: string;
  password: string;
  fullName?: string;
}

/**
 * ข้อมูลสำหรับ request การล็อกอิน
 */
export interface LoginRequest {
  usernameOrEmail: string;
  password: string;
  deviceId?: string;
  rememberMe?: boolean;
}

/**
 * ข้อมูลสำหรับ request การยืนยัน OTP
 */
export interface VerifyOTPRequest {
  otp: string;
  tempToken: string;
  rememberDevice?: boolean;
}

/**
 * ข้อมูลสำหรับ request การยืนยันอีเมล
 */
export interface VerifyEmailRequest {
  otp: string;
  token?: string;
}

/**
 * ข้อมูลสำหรับ request การรีเซ็ตรหัสผ่าน
 */
export interface ResetPasswordRequest {
  token: string;
  password: string;
}

/**
 * ข้อมูลสำหรับ response ที่สำเร็จ
 */
export interface SuccessResponse {
  success: true;
  message: string;
  [key: string]: any;
}

/**
 * ข้อมูลสำหรับ response ที่ไม่สำเร็จ
 */
export interface ErrorResponse {
  success: false;
  message: string;
  [key: string]: any;
}

/**
 * ข้อมูลสำหรับ response ทั้งหมด
 */
export type ApiResponse = SuccessResponse | ErrorResponse;

/**
 * ขยาย Express Request เพื่อรวมข้อมูลผู้ใช้
 */
export interface AuthRequest extends Request {
  user?: User;
}