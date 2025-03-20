import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import prisma from '../utils/prisma';

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';


interface DecodedToken {
  id: string;
  email: string;
  iat: number;
  exp: number;
}

export const authenticateUser = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    // Check for Authorization header
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'กรุณาเข้าสู่ระบบก่อน',
      });
    }

    // Get token from header
    const token = authHeader.split(' ')[1];

    // Verify token
    // @ts-ignore - ข้ามการตรวจสอบ TypeScript สำหรับ jwt.verify
    const decoded = jwt.verify(token, JWT_SECRET) as DecodedToken;

    // Find user by ID
    const user = await prisma.user.findUnique({
      where: { id: decoded.id },
    });

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'ไม่พบผู้ใช้งาน กรุณาเข้าสู่ระบบอีกครั้ง',
      });
    }

    // Attach user to request
    req.user = user;
    
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: 'ไม่มีสิทธิ์ในการเข้าถึง กรุณาเข้าสู่ระบบอีกครั้ง',
    });
  }
};