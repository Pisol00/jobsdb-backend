// src/middleware/auth.ts
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { CONFIG } from '../config/env';
import prisma from '../utils/prisma';

interface DecodedToken {
  id: string;
  email: string;
  iat: number;
  exp: number;
}

/**
 * Middleware ตรวจสอบความถูกต้องของ token และนำข้อมูลผู้ใช้มาแนบกับ request
 */
export const authenticateUser = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    // ตรวจสอบ Authorization header
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'กรุณาเข้าสู่ระบบก่อน',
      });
    }

    // ดึง token จาก header
    const token = authHeader.split(' ')[1];

    // ตรวจสอบความถูกต้องของ token
    const decoded = jwt.verify(token, CONFIG.JWT.SECRET) as DecodedToken;

    // ค้นหาผู้ใช้จาก ID
    const user = await prisma.user.findUnique({
      where: { id: decoded.id },
    });

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'ไม่พบผู้ใช้งาน กรุณาเข้าสู่ระบบอีกครั้ง',
      });
    }

    // แนบข้อมูลผู้ใช้กับ request
    req.user = user;
    
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: 'ไม่มีสิทธิ์ในการเข้าถึง กรุณาเข้าสู่ระบบอีกครั้ง',
    });
  }
};