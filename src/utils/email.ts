// src/utils/email.ts
import nodemailer from 'nodemailer';
import { CONFIG } from '../config/env';
import { UserData } from './jwt';

/**
 * สร้าง nodemailer transporter
 */
const createEmailTransporter = () => {
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
  if (!tempToken) {
    console.error("⚠️ Warning: tempToken is undefined or empty in sendOTPEmail");
    tempToken = "invalid-token";
  }

  const emailHTML = createOTPEmailTemplate(otp, tempToken, fullName);
  return sendEmail(email, "รหัสยืนยันตัวตนแบบสองขั้นตอน JobsDB", emailHTML);
};