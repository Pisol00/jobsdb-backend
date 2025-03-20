import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import prisma from '../utils/prisma';

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const JWT_LIFETIME = process.env.JWT_LIFETIME || '1d';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';
const EMAIL_USER = process.env.EMAIL_USER || '';
const EMAIL_PASS = process.env.EMAIL_PASS || '';
const EMAIL_HOST = process.env.EMAIL_HOST || 'smtp.gmail.com';
const EMAIL_PORT = parseInt(process.env.EMAIL_PORT || '587', 10);
const EMAIL_FROM = process.env.EMAIL_FROM || 'noreply@jobsdb.com';

// Generate JWT token
const generateToken = (user: { id: string; email: string }) => {
  // @ts-ignore - ข้ามการตรวจสอบ TypeScript สำหรับ jwt.sign
  return jwt.sign(
    { id: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: JWT_LIFETIME }
  );
};

// ฟังก์ชันสำหรับส่งอีเมล
const sendEmail = async (to: string, subject: string, html: string) => {
  try {
    // สร้าง transporter สำหรับส่งอีเมล
    const transporter = nodemailer.createTransport({
      host: EMAIL_HOST,
      port: EMAIL_PORT,
      secure: EMAIL_PORT === 465, // true for 465, false for other ports
      auth: {
        user: EMAIL_USER,
        pass: EMAIL_PASS,
      },
    });

    // ส่งอีเมล
    const info = await transporter.sendMail({
      from: `"JobsDB" <${EMAIL_FROM}>`,
      to,
      subject,
      html,
    });

    console.log('Message sent: %s', info.messageId);
    return true;
  } catch (error) {
    console.error('Email send error:', error);
    return false;
  }
};

// Register new user
export const register = async (req: Request, res: Response) => {
  try {
    const { username, email, password, fullName = "" } = req.body;

    // ตรวจสอบว่า username เป็นรูปแบบที่ถูกต้อง
    const usernameRegex = /^[a-zA-Z0-9_]+$/;
    if (!usernameRegex.test(username)) {
      return res.status(400).json({
        success: false,
        message: 'Username ต้องประกอบด้วยตัวอักษรภาษาอังกฤษ ตัวเลข และเครื่องหมาย _ เท่านั้น',
      });
    }

    // ตรวจสอบความยาวของ username
    if (username.length < 3 || username.length > 20) {
      return res.status(400).json({
        success: false,
        message: 'Username ต้องมีความยาว 3-20 ตัวอักษร',
      });
    }

    // Check if username already exists
    const existingUsername = await prisma.user.findUnique({
      where: { username },
    });

    if (existingUsername) {
      return res.status(400).json({
        success: false,
        message: 'Username นี้มีผู้ใช้งานแล้ว',
      });
    }

    // Check if email already exists
    const existingEmail = await prisma.user.findUnique({
      where: { email },
    });

    if (existingEmail) {
      return res.status(400).json({
        success: false,
        message: 'อีเมลนี้มีผู้ใช้งานแล้ว',
      });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create new user
    const user = await prisma.user.create({
      data: {
        username,
        fullName,
        email,
        password: hashedPassword,
        provider: 'local',
      },
    });

    // Generate token
    const token = generateToken(user);

    res.status(201).json({
      success: true,
      message: 'ลงทะเบียนผู้ใช้งานเรียบร้อยแล้ว',
      token,
      user: {
        id: user.id,
        username: user.username,
        fullName: user.fullName,
        email: user.email,
      },
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาด กรุณาลองใหม่อีกครั้ง',
    });
  }
};

// Login user
export const login = async (req: Request, res: Response) => {
  try {
    const { usernameOrEmail, password } = req.body;

    if (!usernameOrEmail || !password) {
      return res.status(400).json({
        success: false,
        message: 'กรุณากรอกข้อมูลให้ครบถ้วน',
      });
    }

    // Check if user exists (by email or username)
    const isEmail = usernameOrEmail.includes('@');
    
    const user = await prisma.user.findFirst({
      where: isEmail 
        ? { email: usernameOrEmail } 
        : { username: usernameOrEmail },
    });

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'ชื่อผู้ใช้/อีเมล หรือรหัสผ่านไม่ถูกต้อง',
      });
    }

    // Check if password exists (user might be registered via OAuth)
    if (!user.password) {
      return res.status(401).json({
        success: false,
        message: 'บัญชีนี้ใช้การเข้าสู่ระบบด้วย Google กรุณาใช้ปุ่ม "เข้าสู่ระบบด้วย Google"',
      });
    }

    // Check if password is correct
    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) {
      return res.status(401).json({
        success: false,
        message: 'ชื่อผู้ใช้/อีเมล หรือรหัสผ่านไม่ถูกต้อง',
      });
    }

    // Generate token
    const token = generateToken(user);

    res.status(200).json({
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        fullName: user.fullName,
        email: user.email,
        profileImage: user.profileImage,
      },
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาด กรุณาลองใหม่อีกครั้ง',
    });
  }
};

// Get current user
export const getCurrentUser = async (req: Request, res: Response) => {
  try {
    // User is already added to request in the auth middleware
    const user = req.user;
    
    res.status(200).json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        fullName: user.fullName,
        email: user.email,
        profileImage: user.profileImage,
        provider: user.provider
      },
    });
  } catch (error) {
    console.error('Get current user error:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาด กรุณาลองใหม่อีกครั้ง',
    });
  }
};

// Request forgot password
export const forgotPassword = async (req: Request, res: Response) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'กรุณากรอกอีเมล',
      });
    }

    // ตรวจสอบว่ามีผู้ใช้ที่ใช้อีเมลนี้หรือไม่
    const user = await prisma.user.findUnique({
      where: { email },
    });

    // ถ้าไม่พบผู้ใช้งาน
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'ไม่พบบัญชีผู้ใช้ที่ใช้อีเมลนี้',
      });
    }

    // ถ้าผู้ใช้ลงทะเบียนด้วย OAuth
    if (user.provider && user.provider !== 'local') {
      return res.status(400).json({
        success: false,
        message: `บัญชีนี้ลงทะเบียนด้วย ${user.provider} กรุณาใช้บริการ ${user.provider} ในการเข้าสู่ระบบ`,
      });
    }

    // สร้าง reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenHashed = crypto.createHash('sha256').update(resetToken).digest('hex');

    // กำหนดเวลาหมดอายุ token (10 นาที)
    const resetTokenExpires = new Date(Date.now() + 10 * 60 * 1000);

    // บันทึก resetToken และเวลาหมดอายุลงในฐานข้อมูล
    await prisma.user.update({
      where: { id: user.id },
      data: {
        resetPasswordToken: resetTokenHashed,
        resetPasswordExpires: resetTokenExpires,
      },
    });

    // สร้าง URL สำหรับรีเซ็ตรหัสผ่าน
    const resetURL = `${FRONTEND_URL}/auth/reset-password?token=${resetToken}`;

    // เนื้อหาอีเมล
    const emailHTML = `
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

    // ส่งอีเมล
    const emailSent = await sendEmail(
      user.email,
      'รีเซ็ตรหัสผ่าน JobsDB ของคุณ',
      emailHTML
    );

    if (emailSent) {
      res.status(200).json({
        success: true,
        message: 'ส่งลิงก์รีเซ็ตรหัสผ่านไปยังอีเมลของคุณแล้ว',
      });
    } else {
      res.status(500).json({
        success: false,
        message: 'ไม่สามารถส่งอีเมลได้ กรุณาลองใหม่อีกครั้ง',
      });
    }
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาด กรุณาลองใหม่อีกครั้ง',
    });
  }
};

// Verify reset token
export const verifyResetToken = async (req: Request, res: Response) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({
        success: false,
        message: 'ไม่พบ Token',
      });
    }

    // แปลง token เป็น hash
    const resetTokenHashed = crypto.createHash('sha256').update(token).digest('hex');

    // ค้นหาผู้ใช้ที่มี reset token และยังไม่หมดอายุ
    const user = await prisma.user.findFirst({
      where: {
        resetPasswordToken: resetTokenHashed,
        resetPasswordExpires: {
          gt: new Date(),
        },
      },
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Token ไม่ถูกต้องหรือหมดอายุแล้ว',
      });
    }

    res.status(200).json({
      success: true,
      message: 'Token ถูกต้อง',
    });
  } catch (error) {
    console.error('Verify reset token error:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาด กรุณาลองใหม่อีกครั้ง',
    });
  }
};

// Reset password
export const resetPassword = async (req: Request, res: Response) => {
  try {
    const { token, password } = req.body;

    if (!token || !password) {
      return res.status(400).json({
        success: false,
        message: 'กรุณากรอกข้อมูลให้ครบถ้วน',
      });
    }

    // ตรวจสอบความยาวของรหัสผ่าน
    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'รหัสผ่านต้องมีความยาวอย่างน้อย 6 ตัวอักษร',
      });
    }

    // แปลง token เป็น hash
    const resetTokenHashed = crypto.createHash('sha256').update(token).digest('hex');

    // ค้นหาผู้ใช้ที่มี reset token และยังไม่หมดอายุ
    const user = await prisma.user.findFirst({
      where: {
        resetPasswordToken: resetTokenHashed,
        resetPasswordExpires: {
          gt: new Date(),
        },
      },
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Token ไม่ถูกต้องหรือหมดอายุแล้ว',
      });
    }

    // Hash รหัสผ่านใหม่
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // อัปเดตรหัสผ่านและล้าง reset token
    await prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashedPassword,
        resetPasswordToken: null,
        resetPasswordExpires: null,
      },
    });

    res.status(200).json({
      success: true,
      message: 'รีเซ็ตรหัสผ่านสำเร็จ',
    });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาด กรุณาลองใหม่อีกครั้ง',
    });
  }
};