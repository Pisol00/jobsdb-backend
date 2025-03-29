// src/utils/email.ts
import { CONFIG } from '../config/env';
import { UserData } from './jwt';
import { createEmailTransporter } from '../config/email';
import { createWelcomeEmailTemplate } from '../config/email';

/**
 * ส่งอีเมล
 */
export const sendEmail = async (to: string, subject: string, html: string): Promise<boolean> => {
  try {
    const transporter = createEmailTransporter();
    
    const info = await transporter.sendMail({
      from: `"JobsDB" <${CONFIG.EMAIL.FROM}>`,
      to,
      subject,
      html,
    });

    console.log("✅ Email sent: %s", info.messageId);
    return true;
  } catch (error) {
    console.error("❌ Email sending error:", error);
    return false;
  }
};

/**
 * สร้างเทมเพลตอีเมลสำหรับส่ง OTP
 */
export const createOTPEmailTemplate = (
  otp: string,
  tempToken: string,
  fullName: string = ""
): string => {
  // ตรวจสอบว่า tempToken มีค่าหรือไม่
  if (!tempToken) {
    console.warn("⚠️ Warning: tempToken is undefined or empty in createOTPEmailTemplate");
    tempToken = "invalid-token";
  }
  
  const expiresAt = Date.now() + CONFIG.OTP_EXPIRY;
  const verifyOtpUrl = `${CONFIG.FRONTEND_URL}/auth/verify-otp/${tempToken}?expiresAt=${expiresAt}`;

  return `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
      <div style="text-align: center; margin-bottom: 20px;">
        <h1 style="color: #3b82f6;">JobsDB</h1>
        <p style="color: #666;">รหัสยืนยันตัวตนแบบสองขั้นตอน (2FA)</p>
      </div>
      <div style="padding: 20px; background-color: #f9fafb; border-radius: 5px;">
        <p>สวัสดี ${fullName || "คุณ"},</p>
        <p>นี่คือรหัส OTP สำหรับการยืนยันตัวตนของคุณ:</p>
        <div style="text-align: center; margin: 30px 0;">
          <div style="font-size: 28px; letter-spacing: 8px; font-weight: bold; color: #3b82f6; background-color: #e0f2fe; padding: 15px; border-radius: 5px;">${otp}</div>
        </div>
        <p>รหัสนี้จะหมดอายุใน 10 นาที</p>
        
        <div style="text-align: center; margin: 30px 0;">
          <a href="${verifyOtpUrl}" style="background-color: #3b82f6; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold;">
            คลิกที่นี่เพื่อเข้าสู่หน้ายืนยัน
          </a>
        </div>
        
        <p>หากคุณไม่ได้พยายามเข้าสู่ระบบ โปรดเพิกเฉยต่อข้อความนี้หรือติดต่อฝ่ายสนับสนุน</p>
      </div>
      <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #e0e0e0; text-align: center; color: #666; font-size: 12px;">
        <p>© ${new Date().getFullYear()} JobsDB. All rights reserved.</p>
      </div>
    </div>
  `;
};

/**
 * สร้างเทมเพลตอีเมลสำหรับการรีเซ็ตรหัสผ่าน
 */
export const createPasswordResetEmailTemplate = (user: UserData, resetURL: string): string => {
  return `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
      <div style="text-align: center; margin-bottom: 20px;">
        <h1 style="color: #3b82f6;">JobsDB</h1>
        <p style="color: #666;">ระบบรีเซ็ตรหัสผ่าน</p>
      </div>
      <div style="padding: 20px; background-color: #f9fafb; border-radius: 5px;">
        <p>สวัสดี ${user.fullName || user.username},</p>
        <p>เราได้รับคำขอรีเซ็ตรหัสผ่านของคุณ คลิกปุ่มด้านล่างเพื่อตั้งรหัสผ่านใหม่:</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="${resetURL}" style="background-color: #3b82f6; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold;">รีเซ็ตรหัสผ่าน</a>
        </div>
        <p>ลิงก์นี้จะหมดอายุใน 10 นาที</p>
        <p>หากคุณไม่ได้ขอรีเซ็ตรหัสผ่าน โปรดเพิกเฉยต่อข้อความนี้หรือติดต่อฝ่ายสนับสนุน</p>
      </div>
      <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #e0e0e0; text-align: center; color: #666; font-size: 12px;">
        <p>© ${new Date().getFullYear()} JobsDB. All rights reserved.</p>
      </div>
    </div>
  `;
};

/**
 * ส่ง OTP ผ่านทางอีเมล
 */
export const sendOTPEmail = async (
  email: string,
  otp: string,
  tempToken: string,
  fullName: string = ""
): Promise<boolean> => {
  // ตรวจสอบว่า tempToken มีค่าหรือไม่
  if (!tempToken) {
    console.error("⚠️ Warning: tempToken is undefined or empty in sendOTPEmail");
    tempToken = "invalid-token";
  }

  const emailHTML = createOTPEmailTemplate(otp, tempToken, fullName);
  return await sendEmail(email, "รหัสยืนยันตัวตนแบบสองขั้นตอน JobsDB", emailHTML);
};

/**
 * ส่งอีเมลต้อนรับหลังจากลงทะเบียน
 */
export const sendWelcomeEmail = async (
  email: string,
  fullName: string | null,
  username: string
): Promise<boolean> => {
  const emailHTML = createWelcomeEmailTemplate(fullName, username);
  return await sendEmail(email, "ยินดีต้อนรับสู่ JobsDB", emailHTML);
};

/**
 * สร้างเทมเพลตอีเมลสำหรับการยืนยันอีเมล
 */
export const createEmailVerificationTemplate = (
  otp: string,
  verifyToken: string,
  fullName: string = ""
): string => {
  const verifyUrl = `${CONFIG.FRONTEND_URL}/auth/verify-email?token=${verifyToken}`;
  
  return `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
      <div style="text-align: center; margin-bottom: 20px;">
        <h1 style="color: #3b82f6;">JobsDB</h1>
        <p style="color: #666;">ยืนยันอีเมลของคุณ</p>
      </div>
      <div style="padding: 20px; background-color: #f9fafb; border-radius: 5px;">
        <p>สวัสดี ${fullName || "คุณ"},</p>
        <p>ขอบคุณที่ลงทะเบียนกับ JobsDB กรุณายืนยันอีเมลของคุณเพื่อเปิดใช้งานบัญชี</p>
        
        <div style="text-align: center; margin: 30px 0;">
          <div style="background-color: #e0f2fe; padding: 15px; border-radius: 5px; margin-bottom: 20px;">
            <p style="margin: 0; font-weight: bold;">รหัสยืนยันอีเมลของคุณคือ:</p>
            <div style="font-size: 28px; letter-spacing: 8px; font-weight: bold; color: #3b82f6; margin-top: 10px;">${otp}</div>
          </div>
          
          <p style="margin-bottom: 20px;">หรือคลิกที่ปุ่มด้านล่างเพื่อยืนยันอีเมลของคุณ:</p>
          
          <a href="${verifyUrl}" style="background-color: #3b82f6; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">
            ยืนยันอีเมลของฉัน
          </a>
        </div>
        
        <p>รหัสและลิงก์จะหมดอายุใน 10 นาที</p>
        <p>หากคุณไม่ได้สมัครสมาชิกกับเรา โปรดเพิกเฉยต่อข้อความนี้</p>
      </div>
      <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #e0e0e0; text-align: center; color: #666; font-size: 12px;">
        <p>© ${new Date().getFullYear()} JobsDB. All rights reserved.</p>
      </div>
    </div>
  `;
};

/**
 * ส่งอีเมลยืนยันอีเมล
 */
export const sendEmailVerification = async (
  email: string,
  otp: string,
  verifyToken: string,
  fullName: string = ""
): Promise<boolean> => {
  const emailHTML = createEmailVerificationTemplate(otp, verifyToken, fullName);
  return await sendEmail(email, "ยืนยันอีเมลของคุณ - JobsDB", emailHTML);
};

/**
 * สร้างเทมเพลตอีเมลแจ้งเตือนก่อนลบบัญชี
 */
export const createAccountDeletionWarningTemplate = (
  fullName: string = "",
  daysRemaining: number = 3
): string => {
  return `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
      <div style="text-align: center; margin-bottom: 20px;">
        <h1 style="color: #3b82f6;">JobsDB</h1>
        <p style="color: #666;">แจ้งเตือนการลบบัญชี</p>
      </div>
      
      <div style="padding: 20px; background-color: #f9fafb; border-radius: 5px;">
        <div style="background-color: #fee2e2; border-left: 4px solid #ef4444; padding: 15px; margin-bottom: 20px; border-radius: 5px;">
          <p style="color: #b91c1c; font-weight: bold; margin: 0;">บัญชีของคุณจะถูกลบในอีก ${daysRemaining} วัน หากไม่มีการยืนยันอีเมล</p>
        </div>
        
        <p>สวัสดี ${fullName || 'คุณ'},</p>
        <p>เราพบว่าคุณได้สมัครสมาชิกกับ JobsDB แต่ยังไม่ได้ยืนยันอีเมลของคุณ</p>
        
        <p>หากคุณยังต้องการใช้บัญชีนี้ กรุณาดำเนินการดังนี้:</p>
        <div style="margin: 20px 0; padding: 15px; background-color: #e0f2fe; border-radius: 5px;">
          <ol style="margin: 0 0 0 20px; padding: 0;">
            <li style="margin-bottom: 8px;">เข้าสู่ระบบด้วยอีเมลและรหัสผ่านของคุณ</li>
            <li style="margin-bottom: 8px;">ระบบจะส่งรหัสยืนยันไปยังอีเมลของคุณ</li>
            <li>กรอกรหัสยืนยันเพื่อเปิดใช้งานบัญชี</li>
          </ol>
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
          <a href="${CONFIG.FRONTEND_URL}/auth/login" style="background-color: #ef4444; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">
            เข้าสู่ระบบเพื่อยืนยันอีเมล
          </a>
        </div>
        
        <p>หากคุณไม่ต้องการใช้บริการของเราอีกต่อไป คุณสามารถเพิกเฉยต่ออีเมลฉบับนี้ได้ บัญชีที่ไม่ได้ยืนยันจะถูกลบโดยอัตโนมัติ</p>
      </div>
      
      <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #e0e0e0; text-align: center; color: #666; font-size: 12px;">
        <p>© ${new Date().getFullYear()} JobsDB. All rights reserved.</p>
      </div>
    </div>
  `;
};

/**
 * ส่งอีเมลแจ้งเตือนก่อนลบบัญชี
 */
export const sendAccountDeletionWarningEmail = async (
  email: string,
  fullName: string,
  daysRemaining: number = 3
): Promise<boolean> => {
  const emailHTML = createAccountDeletionWarningTemplate(fullName, daysRemaining);
  return await sendEmail(email, `แจ้งเตือน: บัญชี JobsDB ของคุณจะถูกลบใน ${daysRemaining} วัน`, emailHTML);
};