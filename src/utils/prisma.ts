// src/utils/prisma.ts
import { PrismaClient } from '@prisma/client';
import { env } from '../config/env';
import { logMessage, LogLevel } from './errorLogger';

// ตัวเลือกสำหรับการสร้าง PrismaClient
const prismaOptions = {
  log: env.NODE_ENV === 'development' 
    ? [
        { level: 'query', emit: 'event' },
        { level: 'error', emit: 'stdout' },
        { level: 'info', emit: 'stdout' },
        { level: 'warn', emit: 'stdout' },
      ]
    : undefined, // ไม่ต้องบันทึก logs ใน production เพื่อประสิทธิภาพ
};

// สร้าง PrismaClient instance
const prisma = new PrismaClient(prismaOptions);

// ตั้งค่า query logging สำหรับโหมด development
if (env.NODE_ENV === 'development') {
  prisma.$on('query', (e) => {
    console.log('Query: ' + e.query);
    console.log('Duration: ' + e.duration + 'ms');
  });
}

/**
 * ตรวจสอบการเชื่อมต่อฐานข้อมูล
 * @returns Promise<boolean> สถานะการเชื่อมต่อ (true = สำเร็จ, false = ล้มเหลว)
 */
export const testConnection = async (): Promise<boolean> => {
  try {
    // ใช้คำสั่งง่ายๆ เพื่อทดสอบการเชื่อมต่อ
    await prisma.$connect();
    
    // ทดสอบการ query อย่างง่าย
    const result = await prisma.$executeRaw`SELECT 1`;
    
    logMessage(
      LogLevel.INFO, 
      'Database connected successfully', 
      null, 
      { dbUrl: maskConnectionString(env.DATABASE_URL) }
    );
    
    return true;
  } catch (error) {
    logMessage(
      LogLevel.ERROR, 
      'Database connection error', 
      error as Error, 
      { dbUrl: maskConnectionString(env.DATABASE_URL) }
    );
    
    return false;
  }
};

/**
 * ซ่อนข้อมูลสำคัญในสตริงการเชื่อมต่อฐานข้อมูล
 * เพื่อความปลอดภัยในการบันทึก logs
 */
function maskConnectionString(connectionString: string): string {
  try {
    // สร้าง URL object จากสตริงการเชื่อมต่อ
    const url = new URL(connectionString);
    
    // ซ่อนรหัสผ่าน
    if (url.password) {
      url.password = '********';
    }
    
    // คืนค่าสตริงที่ถูกซ่อนข้อมูลแล้ว
    return url.toString();
  } catch (error) {
    // ถ้าไม่สามารถแปลงเป็น URL ได้ ให้ซ่อนทั้งสตริง
    return 'DATABASE_URL=<masked>';
  }
}

/**
 * ฟังก์ชัน wrapper สำหรับจัดการ transactions
 * ช่วยให้การใช้งาน transaction ง่ายขึ้นและมีการจัดการข้อผิดพลาดที่ดีขึ้น
 */
export async function withTransaction<T>(
  callback: (tx: typeof prisma) => Promise<T>
): Promise<T> {
  return await prisma.$transaction(async (tx) => {
    return await callback(tx);
  });
}

export default prisma;