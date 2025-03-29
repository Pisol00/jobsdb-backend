// src/config/email.ts
import nodemailer from 'nodemailer';
import { CONFIG } from './env';

/**
 * สร้าง nodemailer transporter
 */
export const createEmailTransporter = () => {
  return nodemailer.createTransport({
    host: CONFIG.EMAIL.HOST,
    port: CONFIG.EMAIL.PORT,
    secure: CONFIG.EMAIL.PORT === 465,
    auth: {
      user: CONFIG.EMAIL.USER,
      pass: CONFIG.EMAIL.PASS,
    },
  });
};

/**
 * ฟังก์ชันสำหรับทดสอบการเชื่อมต่อกับเซิร์ฟเวอร์อีเมล
 */
export const testEmailConnection = async (): Promise<boolean> => {
  try {
    const transporter = createEmailTransporter();
    const testResult = await transporter.verify();
    if (testResult) {
      console.log('✅ Email server connection successful');
      return true;
    } else {
      console.error('❌ Email server connection failed');
      return false;
    }
  } catch (error) {
    console.error('❌ Email server connection error:', error);
    return false;
  }
};

/**
 * เทมเพลตอีเมลสำหรับแจ้งเตือนการล็อกอินที่น่าสงสัย
 */
export const createLoginAlertEmailTemplate = (
  fullName: string | null,
  ipAddress: string,
  deviceInfo: string,
  date: Date,
  location?: string
): string => {
  return `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
      <div style="text-align: center; margin-bottom: 20px;">
        <h1 style="color: #3b82f6;">JobsDB</h1>
        <p style="color: #666;">แจ้งเตือนการเข้าสู่ระบบใหม่</p>
      </div>
      <div style="padding: 20px; background-color: #f9fafb; border-radius: 5px;">
        <p>สวัสดี ${fullName || 'คุณ'},</p>
        <p>เราตรวจพบการเข้าสู่ระบบใหม่เข้าบัญชีของคุณ:</p>
        
        <div style="margin: 20px 0; padding: 15px; background-color: #e0f2fe; border-radius: 5px; font-family: monospace;">
          <p><strong>เวลา:</strong> ${date.toLocaleString('th-TH')}</p>
          <p><strong>IP Address:</strong> ${ipAddress}</p>
          <p><strong>อุปกรณ์:</strong> ${deviceInfo}</p>
          ${location ? `<p><strong>ตำแหน่ง:</strong> ${location}</p>` : ''}
        </div>
        
        <p>หากคุณไม่ได้เข้าสู่ระบบด้วยตนเอง กรุณาเปลี่ยนรหัสผ่านทันที:</p>
        
        <div style="text-align: center; margin: 30px 0;">
          <a href="${CONFIG.FRONTEND_URL}/auth/reset-password" style="background-color: #ef4444; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold;">
            เปลี่ยนรหัสผ่านทันที
          </a>
        </div>
        
        <p>หากคุณต้องการความช่วยเหลือเพิ่มเติม กรุณาติดต่อทีมสนับสนุนของเรา</p>
      </div>
      <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #e0e0e0; text-align: center; color: #666; font-size: 12px;">
        <p>© ${new Date().getFullYear()} JobsDB. All rights reserved.</p>
      </div>
    </div>
  `;
};

/**
 * เทมเพลตอีเมลสำหรับแจ้งต้อนรับผู้ใช้ใหม่
 */
export const createWelcomeEmailTemplate = (
  fullName: string | null,
  username: string
): string => {
  return `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
      <div style="text-align: center; margin-bottom: 20px;">
        <h1 style="color: #3b82f6;">JobsDB</h1>
        <p style="color: #666;">ยินดีต้อนรับสู่ JobsDB</p>
      </div>
      <div style="padding: 20px; background-color: #f9fafb; border-radius: 5px;">
        <p>สวัสดี ${fullName || username},</p>
        <p>ขอบคุณที่ลงทะเบียนกับ JobsDB แพลตฟอร์มหางานที่ใหญ่ที่สุดในภูมิภาค</p>
        
        <p>คุณสามารถเริ่มต้นใช้งานได้ทันทีด้วยการ:</p>
        <ul style="margin: 20px 0;">
          <li>สร้างและปรับแต่งประวัติของคุณ</li>
          <li>ค้นหางานที่ตรงกับความต้องการของคุณ</li>
          <li>ติดตามบริษัทที่คุณสนใจ</li>
          <li>ตั้งค่าการแจ้งเตือนเมื่อมีงานที่เหมาะกับคุณ</li>
        </ul>
        
        <div style="text-align: center; margin: 30px 0;">
          <a href="${CONFIG.FRONTEND_URL}" style="background-color: #3b82f6; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold;">
            เริ่มต้นใช้งาน
          </a>
        </div>
        
        <p>หากมีคำถามหรือต้องการความช่วยเหลือ คุณสามารถติดต่อทีมสนับสนุนของเราได้ตลอดเวลา</p>
        <p>ขอให้โชคดีในการหางาน!</p>
      </div>
      <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #e0e0e0; text-align: center; color: #666; font-size: 12px;">
        <p>© ${new Date().getFullYear()} JobsDB. All rights reserved.</p>
        <p>เปลี่ยนการตั้งค่าการแจ้งเตือนของคุณได้ <a href="${CONFIG.FRONTEND_URL}/settings/notifications" style="color: #3b82f6;">ที่นี่</a></p>
      </div>
    </div>
  `;
};