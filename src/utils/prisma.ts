// src/utils/prisma.ts
import { PrismaClient } from '@prisma/client';

// สร้าง PrismaClient instance
const prisma = new PrismaClient();

// ตรวจสอบการเชื่อมต่อฐานข้อมูล
export const testConnection = async () => {
  try {
    await prisma.$connect();
    console.log('✅ Database connected successfully');
    return true;
  } catch (error) {
    console.error('❌ Database connection error:', error);
    return false;
  }
};

export default prisma;