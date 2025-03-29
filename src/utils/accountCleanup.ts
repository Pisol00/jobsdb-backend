// src/utils/accountCleanup.ts
import prisma from './prisma';
import { CONFIG } from '../config/env';
import { sendAccountDeletionWarningEmail } from './email';
import { logMessage, LogLevel } from './errorLogger';

/**
 * ล้างบัญชีที่ไม่ได้ยืนยันอีเมลและเกินระยะเวลาที่กำหนด
 * @param daysBeforeWarning จำนวนวันหลังจากสร้างบัญชีก่อนที่จะส่งอีเมลแจ้งเตือน
 * @param daysBeforeDeletion จำนวนวันหลังจากสร้างบัญชีก่อนที่จะลบบัญชี
 * @param sendWarningEmails เปิดใช้การส่งอีเมลแจ้งเตือน
 * @returns จำนวนบัญชีที่ถูกลบและจำนวนอีเมลแจ้งเตือนที่ส่ง
 */
export const cleanupUnverifiedAccounts = async (
  daysBeforeWarning: number = CONFIG.ACCOUNT_CLEANUP.DAYS_BEFORE_WARNING,
  daysBeforeDeletion: number = CONFIG.ACCOUNT_CLEANUP.DAYS_BEFORE_DELETION,
  sendWarningEmails: boolean = true
): Promise<{ deletedCount: number; warningEmailsSent: number }> => {
  try {
    // คำนวณวันที่สำหรับการแจ้งเตือนและการลบ
    const warningDate = new Date();
    warningDate.setDate(warningDate.getDate() - daysBeforeWarning);
    
    const deletionDate = new Date();
    deletionDate.setDate(deletionDate.getDate() - daysBeforeDeletion);
    
    let warningEmailsSent = 0;
    
    // ค้นหาและส่งอีเมลแจ้งเตือนบัญชีที่ใกล้ถูกลบ
    if (sendWarningEmails) {
      // ค้นหาบัญชีที่ยังไม่ยืนยันและอยู่ในช่วงที่ควรส่งคำเตือน
      const accountsToWarn = await prisma.user.findMany({
        where: {
          isEmailVerified: false,
          createdAt: {
            lte: warningDate,
            gt: deletionDate
          },
          // ตรวจสอบเงื่อนไขการส่งอีเมลแจ้งเตือน:
          // 1. จำนวนอีเมลที่ส่งไปแล้วไม่เกินจำนวนสูงสุดที่กำหนด
          warningEmailCount: { 
            lt: CONFIG.ACCOUNT_CLEANUP.WARNING_EMAIL_MAX_COUNT 
          },
          // 2. ยังไม่เคยส่งอีเมลหรือส่งไปนานกว่าช่วงเวลาที่กำหนดแล้ว
          OR: [
            { lastWarningEmailSentAt: null },
            {
              lastWarningEmailSentAt: {
                lt: new Date(Date.now() - CONFIG.ACCOUNT_CLEANUP.WARNING_EMAIL_INTERVAL)
              }
            }
          ]
        }
      });
      
      logMessage(
        LogLevel.INFO,
        `Found ${accountsToWarn.length} accounts to send warning emails`,
        null
      );
      
      // ส่งอีเมลแจ้งเตือน
      for (const user of accountsToWarn) {
        try {
          const remainingDays = daysBeforeDeletion - daysBeforeWarning;
          const emailSent = await sendAccountDeletionWarningEmail(
            user.email,
            user.fullName || user.username,
            remainingDays
          );
          
          if (emailSent) {
            warningEmailsSent++;
            
            // บันทึกเวลาการส่งอีเมลล่าสุดและเพิ่มจำนวนอีเมลที่ส่งแล้ว
            await prisma.user.update({
              where: { id: user.id },
              data: { 
                lastWarningEmailSentAt: new Date(),
                warningEmailCount: { increment: 1 }
              }
            });
            
            logMessage(
              LogLevel.INFO,
              `Sent warning email to ${user.email} for unverified account (${user.warningEmailCount + 1}/${CONFIG.ACCOUNT_CLEANUP.WARNING_EMAIL_MAX_COUNT})`,
              null,
              { userId: user.id }
            );
          }
        } catch (error) {
          logMessage(
            LogLevel.ERROR,
            `Failed to send warning email to ${user.email}`,
            error as Error,
            { userId: user.id }
          );
        }
      }
    }
    
    // ลบบัญชีที่ไม่ได้ยืนยันและเก่ากว่าระยะเวลาที่กำหนด
    const deleteResult = await prisma.user.deleteMany({
      where: {
        isEmailVerified: false,
        createdAt: { lt: deletionDate }
      }
    });
    
    logMessage(
      LogLevel.INFO,
      `Cleaned up ${deleteResult.count} unverified accounts older than ${daysBeforeDeletion} days`,
      null
    );
    
    return {
      deletedCount: deleteResult.count,
      warningEmailsSent
    };
  } catch (error) {
    logMessage(
      LogLevel.ERROR,
      'Error during unverified accounts cleanup',
      error as Error
    );
    
    throw error;
  }
};