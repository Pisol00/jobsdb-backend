// src/scripts/test-account-cleanup.ts
import { cleanupUnverifiedAccounts } from '../utils/accountCleanup';
import { logMessage, LogLevel } from '../utils/errorLogger';
import prisma from '../utils/prisma';

const testAccountCleanup = async () => {
  try {
    logMessage(LogLevel.INFO, '🧪 Running test for account cleanup');
    
    // ทดสอบส่งอีเมลแจ้งเตือนสำหรับบัญชีที่ยังไม่ยืนยันเก่ากว่า 1 วัน
    const result = await cleanupUnverifiedAccounts(1, 2, true);
    
    logMessage(
      LogLevel.INFO,
      `🧪 Test completed: ${result.deletedCount} accounts deleted, ${result.warningEmailsSent} warning emails sent`
    );
  } catch (error) {
    logMessage(LogLevel.ERROR, '🧪 Test failed', error as Error);
  } finally {
    await prisma.$disconnect();
  }
};

// เริ่มการทดสอบ
testAccountCleanup();