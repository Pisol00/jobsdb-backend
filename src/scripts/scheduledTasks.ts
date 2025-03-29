// src/scripts/scheduledTasks.ts
import { CronJob } from 'cron';
import { cleanupUnverifiedAccounts } from '../utils/accountCleanup';
import { testConnection } from '../utils/prisma';
import { logMessage, LogLevel } from '../utils/errorLogger';
import { CONFIG } from '../config/env';

/**
 * สร้าง Cron job สำหรับล้างบัญชีที่ไม่ได้ยืนยันอัตโนมัติ
 * ค่าเริ่มต้น: ทำงานทุกวันเวลา 03:00 น.
 */
export const setupAccountCleanupJob = (
  cronTime: string = '0 3 * * *',
  daysBeforeWarning: number = CONFIG.ACCOUNT_CLEANUP.DAYS_BEFORE_WARNING,
  daysBeforeDeletion: number = CONFIG.ACCOUNT_CLEANUP.DAYS_BEFORE_DELETION,
  sendWarningEmails: boolean = true
): CronJob => {
  const job = new CronJob(
    cronTime,
    async () => {
      try {
        logMessage(LogLevel.INFO, 'Starting scheduled account cleanup job');
        
        // ตรวจสอบการเชื่อมต่อฐานข้อมูล
        const dbConnected = await testConnection();
        if (!dbConnected) {
          logMessage(LogLevel.ERROR, 'Database connection failed, skipping cleanup job');
          return;
        }
        
        // ตรวจสอบว่าการล้างบัญชีเปิดใช้งานหรือไม่
        if (!CONFIG.ACCOUNT_CLEANUP.ENABLED) {
          logMessage(LogLevel.INFO, 'Account cleanup is disabled in config, skipping');
          return;
        }
        
        // ดำเนินการล้างบัญชี
        const result = await cleanupUnverifiedAccounts(
          daysBeforeWarning,
          daysBeforeDeletion,
          sendWarningEmails
        );
        
        logMessage(
          LogLevel.INFO,
          `Account cleanup completed: ${result.deletedCount} accounts deleted, ${result.warningEmailsSent} warning emails sent`
        );
      } catch (error) {
        logMessage(
          LogLevel.ERROR,
          'Error during scheduled account cleanup',
          error as Error
        );
      }
    },
    null, // onComplete
    false, // start
    'Asia/Bangkok' // timezone
  );
  
  return job;
};

/**
 * เริ่มต้นงานที่ตั้งเวลาไว้ทั้งหมด
 */
export const startAllScheduledTasks = (): void => {
  try {
    // สร้างและเริ่มงานล้างบัญชี
    const cleanupJob = setupAccountCleanupJob();
    cleanupJob.start();
    
    logMessage(
      LogLevel.INFO,
      `Account cleanup job scheduled to run at: ${cleanupJob.cronTime.toString()}`
    );
    
    // เพิ่มงานตั้งเวลาอื่นๆ ที่นี่...
    
  } catch (error) {
    logMessage(
      LogLevel.ERROR,
      'Failed to start scheduled tasks',
      error as Error
    );
  }
};

// เมื่อรันไฟล์นี้โดยตรง จะเริ่มต้นงานตั้งเวลาทั้งหมด
if (require.main === module) {
  startAllScheduledTasks();
}