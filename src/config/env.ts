// src/config/env.ts
import dotenv from 'dotenv';
import { z } from 'zod';

// โหลดตัวแปรสภาพแวดล้อมจากไฟล์ .env
dotenv.config();

// กำหนดโครงสร้างและการตรวจสอบตัวแปรสภาพแวดล้อม
const envSchema = z.object({
  // Server
  PORT: z.string().default('5000'),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),

  // Database
  DATABASE_URL: z.string(),

  // JWT
  JWT_SECRET: z.string().min(1, 'JWT Secret is required'),
  JWT_LIFETIME: z.string().default('1d'),
  JWT_EXTENDED_LIFETIME: z.string().default('30d'),

  // Frontend
  FRONTEND_URL: z.string().url().default('http://localhost:3000'),

  // Google OAuth
  GOOGLE_CLIENT_ID: z.string().min(1, 'Google Client ID is required'),
  GOOGLE_CLIENT_SECRET: z.string().min(1, 'Google Client Secret is required'),
  GOOGLE_CALLBACK_URL: z.string().url(),

  // Email
  EMAIL_HOST: z.string().default('smtp.gmail.com'),
  EMAIL_PORT: z.string().default('587'),
  EMAIL_USER: z.string().min(1, 'Email User is required'),
  EMAIL_PASS: z.string().min(1, 'Email Password is required'),
  EMAIL_FROM: z.string().email().default('noreply@jobsdb.com'),
  
  // Account cleanup settings
  ACCOUNT_CLEANUP_ENABLED: z.string().default('true'),
  ACCOUNT_CLEANUP_DAYS_WARNING: z.string().default('3'),
  ACCOUNT_CLEANUP_DAYS_DELETION: z.string().default('7'),
});

// พยายามแปลงและตรวจสอบตัวแปรสภาพแวดล้อม
const _env = envSchema.safeParse(process.env);

// จัดการกรณีที่การตรวจสอบล้มเหลว
if (!_env.success) {
  console.error('❌ Invalid environment variables:', _env.error.format());
  throw new Error('Invalid environment variables');
}

// ส่งออกตัวแปรสภาพแวดล้อมที่ผ่านการตรวจสอบแล้ว
export const env = _env.data;

// กำหนดค่าคงที่สำหรับการตั้งค่าในแอปพลิเคชัน
export const CONFIG = {
  JWT: {
    SECRET: env.JWT_SECRET,
    LIFETIME: env.JWT_LIFETIME,
    EXTENDED_LIFETIME: env.JWT_EXTENDED_LIFETIME,
    TEMP_LIFETIME: '10m'
  },
  EMAIL: {
    HOST: env.EMAIL_HOST,
    PORT: parseInt(env.EMAIL_PORT, 10),
    USER: env.EMAIL_USER,
    PASS: env.EMAIL_PASS,
    FROM: env.EMAIL_FROM
  },
  FRONTEND_URL: env.FRONTEND_URL,
  OTP_EXPIRY: 10 * 60 * 1000, // 10 นาที (มิลลิวินาที)
  TRUSTED_DEVICE_EXPIRY: 60 * 60 * 1000, // 1 ชั่วโมง (มิลลิวินาที)
  SECURITY: {
    MAX_LOGIN_ATTEMPTS: 5, // จำนวนครั้งสูงสุดที่อนุญาตให้ล็อกอินผิด
    LOCKOUT_DURATION: 5 * 60 * 1000, // ระยะเวลาที่ล็อค (5 นาที)
    ATTEMPT_WINDOW: 30 * 60 * 1000, // ช่วงเวลาที่จะนับจำนวนครั้งที่ล็อกอินผิด (30 นาที)
  },
  ACCOUNT_CLEANUP: {
    ENABLED: env.ACCOUNT_CLEANUP_ENABLED === 'true',
    DAYS_BEFORE_WARNING: parseInt(env.ACCOUNT_CLEANUP_DAYS_WARNING, 10),
    DAYS_BEFORE_DELETION: parseInt(env.ACCOUNT_CLEANUP_DAYS_DELETION, 10)
  }
};