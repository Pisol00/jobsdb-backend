// src/utils/cleanup.ts
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
  daysBeforeWarning: number = 3,
  daysBeforeDeletion: number = 7,
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
      const accountsToWarn = await prisma.user.findMany({
        where: {
          isEmailVerified: false,
          createdAt: {
            lte: warningDate,
            gt: deletionDate
          },
          // ตรวจสอบว่าไม่เคยส่งอีเมลแจ้งเตือนในวันนี้
          // (ควรเพิ่มฟิลด์ lastWarningEmailSentAt ในฐานข้อมูล)
          // lastWarningEmailSentAt: {
          //   lt: new Date(new Date().setHours(0, 0, 0, 0))
          // }
        }
      });
      
      // ส่งอีเมลแจ้งเตือน
      for (const user of accountsToWarn) {
        try {
          const emailSent = await sendAccountDeletionWarningEmail(
            user.email,
            user.fullName || user.username,
            daysBeforeDeletion - daysBeforeWarning
          );
          
          if (emailSent) {
            warningEmailsSent++;
            
            // บันทึกเวลาการส่งอีเมลล่าสุด (ต้องเพิ่มฟิลด์นี้ในฐานข้อมูล)
            // await prisma.user.update({
            //   where: { id: user.id },
            //   data: { lastWarningEmailSentAt: new Date() }
            // });
            
            logMessage(
              LogLevel.INFO,
              `Sent warning email to ${user.email} for unverified account`,
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