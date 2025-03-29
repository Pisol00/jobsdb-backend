// src/middleware/auth.ts
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { CONFIG } from '../config/env';
import prisma from '../utils/prisma';
import { ApiError } from './errorHandler';
import { logMessage, LogLevel } from '../utils/errorLogger';
import { constantTimeCompare } from '../utils/security';
import { User } from '@prisma/client';

/**
 * Interface สำหรับข้อมูลที่ถอดรหัสจาก JWT
 */
interface DecodedToken {
  id: string;
  email: string;
  iat: number;
  exp: number;
  temp?: boolean;
  deviceId?: string;
}

/**
 * Middleware ตรวจสอบความถูกต้องของ token และนำข้อมูลผู้ใช้มาแนบกับ request
 * ใช้สำหรับเส้นทางที่ต้องการการยืนยันตัวตน
 */
export const authenticateUser = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    // บันทึกข้อมูลสำหรับ logging
    const context = {
      method: req.method,
      path: req.path,
      ip: req.ip || req.socket.remoteAddress || 'unknown',
      userAgent: req.headers['user-agent']
    };

    // ตรวจสอบ Authorization header
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      logMessage(LogLevel.WARN, 'Authentication failed: No Bearer token', null, context);
      throw new ApiError(401, 'กรุณาเข้าสู่ระบบก่อน', 'NO_TOKEN');
    }

    // ดึง token จาก header
    const token = authHeader.split(' ')[1];

    // ตรวจสอบความถูกต้องของ token
    let decoded: DecodedToken;
    try {
      decoded = jwt.verify(token, CONFIG.JWT.SECRET) as DecodedToken;
    } catch (error) {
      // จัดการข้อผิดพลาดตามประเภท
      if (error.name === 'TokenExpiredError') {
        logMessage(LogLevel.WARN, 'Authentication failed: Token expired', error, context);
        throw new ApiError(401, 'การยืนยันตัวตนหมดอายุ กรุณาเข้าสู่ระบบใหม่', 'TOKEN_EXPIRED');
      } else if (error.name === 'JsonWebTokenError') {
        logMessage(LogLevel.WARN, 'Authentication failed: Invalid token', error, context);
        throw new ApiError(401, 'การยืนยันตัวตนไม่ถูกต้อง กรุณาเข้าสู่ระบบใหม่', 'INVALID_TOKEN');
      }
      
      logMessage(LogLevel.ERROR, 'Authentication failed: JWT error', error, context);
      throw new ApiError(401, 'ไม่สามารถยืนยันตัวตนได้ กรุณาเข้าสู่ระบบใหม่', 'AUTH_ERROR');
    }

    // ตรวจสอบว่าเป็น token ชั่วคราวหรือไม่
    if (decoded.temp) {
      logMessage(LogLevel.WARN, 'Authentication failed: Temporary token used for protected route', null, {
        ...context,
        userId: decoded.id
      });
      throw new ApiError(401, 'กรุณายืนยัน OTP ก่อนเข้าถึงข้อมูลนี้', 'REQUIRES_2FA');
    }

    // ค้นหาผู้ใช้จาก ID
    const user = await prisma.user.findUnique({
      where: { id: decoded.id },
    });

    if (!user) {
      logMessage(LogLevel.WARN, 'Authentication failed: User not found', null, {
        ...context,
        userId: decoded.id
      });
      throw new ApiError(401, 'ไม่พบผู้ใช้งาน กรุณาเข้าสู่ระบบอีกครั้ง', 'USER_NOT_FOUND');
    }

    // แนบข้อมูลผู้ใช้กับ request
    req.user = user;
    
    // บันทึก Log การเข้าถึงข้อมูลสำคัญ (ขึ้นอยู่กับเส้นทาง)
    const sensitiveRoutes = ['/api/auth/change-password', '/api/user/profile/update'];
    if (sensitiveRoutes.some(route => req.path.includes(route))) {
      logMessage(LogLevel.INFO, 'User accessed sensitive endpoint', null, {
        ...context,
        userId: user.id,
        endpoint: req.path
      });
    }
    
    next();
  } catch (error) {
    if (error instanceof ApiError) {
      return res.status(error.statusCode).json({
        success: false,
        message: error.message,
        code: error.errorCode
      });
    }
    
    return res.status(401).json({
      success: false,
      message: 'ไม่มีสิทธิ์ในการเข้าถึง กรุณาเข้าสู่ระบบอีกครั้ง',
      code: 'UNAUTHORIZED'
    });
  }
};

/**
 * Middleware ตรวจสอบว่ามีการเข้าสู่ระบบแล้วหรือไม่ (optional)
 * ใช้สำหรับเส้นทางที่สามารถใช้ได้ทั้งกรณีเข้าสู่ระบบและไม่ได้เข้าสู่ระบบ
 */
export const optionalAuth = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    // ตรวจสอบ Authorization header
    const authHeader = req.headers.authorization;
    
    // ถ้าไม่มี header ให้ผ่านไปเลย
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return next();
    }

    // ดึง token จาก header
    const token = authHeader.split(' ')[1];

    // ตรวจสอบความถูกต้องของ token
    try {
      const decoded = jwt.verify(token, CONFIG.JWT.SECRET) as DecodedToken;
      
      // ค้นหาผู้ใช้จาก ID
      const user = await prisma.user.findUnique({
        where: { id: decoded.id },
      });
      
      if (user) {
        // แนบข้อมูลผู้ใช้กับ request
        req.user = user;
      }
    } catch (error) {
      // ในกรณีที่ token ไม่ถูกต้อง แต่ไม่จำเป็นต้องหยุดการทำงาน
      // เพียงไม่เพิ่มข้อมูลผู้ใช้ใน request
      logMessage(LogLevel.INFO, 'Optional auth: Invalid token', error, {
        method: req.method,
        path: req.path,
        ip: req.ip
      });
    }
    
    next();
  } catch (error) {
    // ในกรณีที่เกิดข้อผิดพลาดอื่น ๆ ให้ข้ามการตรวจสอบ
    next();
  }
};

/**
 * Middleware ตรวจสอบสิทธิ์ของผู้ดูแลระบบ
 * ใช้ต่อจาก authenticateUser
 */
export const requireAdmin = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  // ตรวจสอบว่ามีผู้ใช้และเป็นผู้ดูแลระบบหรือไม่
  const user = req.user as User;
  
  if (!user) {
    return res.status(401).json({
      success: false,
      message: 'กรุณาเข้าสู่ระบบก่อน',
      code: 'UNAUTHORIZED'
    });
  }
  
  // ตรวจสอบว่าเป็นผู้ดูแลระบบหรือไม่ (สมมติว่าผู้ดูแลระบบมี email ลงท้ายด้วย @jobsdb.com)
  const isAdmin = user.email.endsWith('@jobsdb.com');
  
  if (!isAdmin) {
    logMessage(LogLevel.WARN, 'Authorization failed: Not an admin', null, {
      userId: user.id,
      method: req.method,
      path: req.path,
      ip: req.ip
    });
    
    return res.status(403).json({
      success: false,
      message: 'คุณไม่มีสิทธิ์ในการเข้าถึง',
      code: 'FORBIDDEN'
    });
  }
  
  // ผ่านการตรวจสอบ
  next();
};

/**
 * Middleware ตรวจสอบว่า request มาจากเว็บไซต์ที่เชื่อถือได้
 * ป้องกัน CSRF attack
 */
export const validateReferer = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  // ตรวจสอบจาก header Origin หรือ Referer
  const origin = req.headers.origin || req.headers.referer;
  
  // ถ้าเป็น OPTIONS request (preflight) ให้ผ่านไปเลย
  if (req.method === 'OPTIONS') {
    return next();
  }
  
  // ถ้าไม่มี origin และเป็น request ที่ต้องการข้อมูล (GET, HEAD) ให้ผ่านไปเลย
  if (!origin && (req.method === 'GET' || req.method === 'HEAD')) {
    return next();
  }
  
  // ถ้ามี origin ตรวจสอบว่าตรงกับที่กำหนดหรือไม่
  const trustedOrigins = [CONFIG.FRONTEND_URL];
  // ในโหมด development เพิ่ม localhost เข้าไปด้วย
  if (process.env.NODE_ENV === 'development') {
    trustedOrigins.push('http://localhost:3000');
  }
  
  // ถ้าไม่มี origin หรือ origin ไม่ตรงกับที่กำหนด
  if (!origin || !trustedOrigins.some(trusted => origin.startsWith(trusted))) {
    logMessage(LogLevel.WARN, 'Security check failed: Invalid origin', null, {
      origin,
      method: req.method,
      path: req.path,
      ip: req.ip
    });
    
    return res.status(403).json({
      success: false,
      message: 'ไม่อนุญาตให้เข้าถึงจากภายนอก',
      code: 'INVALID_ORIGIN'
    });
  }
  
  // ผ่านการตรวจสอบ
  next();
};

/**
 * ฟังก์ชันสำหรับสร้าง middleware ตรวจสอบสิทธิ์ตามบทบาท (roles)
 */
export const authorize = (roles: string[]) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const user = req.user as User & { roles?: string[] };
    
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'กรุณาเข้าสู่ระบบก่อน',
        code: 'UNAUTHORIZED'
      });
    }
    
    // ตรวจสอบบทบาท (สมมติว่าผู้ใช้มี property roles เป็น array)
    const userRoles = user.roles || [];
    
    if (!roles.some(role => userRoles.includes(role))) {
      logMessage(LogLevel.WARN, 'Authorization failed: Insufficient role', null, {
        userId: user.id,
        requiredRoles: roles,
        userRoles,
        method: req.method,
        path: req.path
      });
      
      return res.status(403).json({
        success: false,
        message: 'คุณไม่มีสิทธิ์ในการเข้าถึง',
        code: 'INSUFFICIENT_ROLE'
      });
    }
    
    // ผ่านการตรวจสอบ
    next();
  };
};

/**
 * Export middleware functions
 */
export default {
  authenticateUser,
  optionalAuth,
  requireAdmin,
  validateReferer,
  authorize
};