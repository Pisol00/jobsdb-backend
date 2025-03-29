// src/middleware/errorHandler.ts
import { Request, Response, NextFunction } from 'express';
import { logMessage, LogLevel } from '../utils/errorLogger';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { env } from '../config/env';

/**
 * Class สำหรับจัดการข้อผิดพลาดที่มีรหัสสถานะ
 */
export class ApiError extends Error {
  statusCode: number;
  errorCode?: string;
  details?: any;
  
  constructor(statusCode: number, message: string, errorCode?: string, details?: any) {
    super(message);
    this.statusCode = statusCode;
    this.errorCode = errorCode;
    this.details = details;
    this.name = this.constructor.name;
    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * แปลงและจัดการข้อผิดพลาดจาก Prisma
 */
const handlePrismaError = (err: PrismaClientKnownRequestError): ApiError => {
  // จัดการข้อผิดพลาดจาก Prisma ตาม error code
  // ดูเพิ่มเติมที่: https://www.prisma.io/docs/reference/api-reference/error-reference
  
  const isDevelopment = env.NODE_ENV === 'development';
  
  switch (err.code) {
    case 'P2002': // Unique constraint violation
      const target = err.meta?.target as string[] || [];
      const field = target.join(', ');
      return new ApiError(
        409, 
        `ข้อมูล ${field} นี้มีอยู่แล้วในระบบ`,
        'UNIQUE_CONSTRAINT_VIOLATION',
        isDevelopment ? err.meta : undefined
      );
      
    case 'P2025': // Record not found
      return new ApiError(
        404,
        'ไม่พบข้อมูลที่ต้องการ',
        'RECORD_NOT_FOUND',
        isDevelopment ? err.meta : undefined
      );
      
    case 'P2003': // Foreign key constraint violation
      return new ApiError(
        400,
        'ข้อมูลที่อ้างอิงไม่ถูกต้อง',
        'FOREIGN_KEY_VIOLATION',
        isDevelopment ? err.meta : undefined
      );
      
    default:
      return new ApiError(
        500,
        'เกิดข้อผิดพลาดกับฐานข้อมูล กรุณาลองใหม่อีกครั้ง',
        'DATABASE_ERROR',
        isDevelopment ? { code: err.code, meta: err.meta } : undefined
      );
  }
};

/**
 * แปลงและจัดการข้อผิดพลาดจาก token verification
 */
const handleJwtError = (err: Error): ApiError => {
  if (err.name === 'TokenExpiredError') {
    return new ApiError(
      401,
      'การยืนยันตัวตนหมดอายุ กรุณาเข้าสู่ระบบใหม่',
      'TOKEN_EXPIRED'
    );
  } else if (err.name === 'JsonWebTokenError') {
    return new ApiError(
      401,
      'การยืนยันตัวตนไม่ถูกต้อง กรุณาเข้าสู่ระบบใหม่',
      'INVALID_TOKEN'
    );
  }
  
  return new ApiError(
    401,
    'เกิดข้อผิดพลาดในการยืนยันตัวตน กรุณาเข้าสู่ระบบใหม่',
    'AUTH_ERROR'
  );
};

/**
 * Middleware เพื่อจัดการข้อผิดพลาดทั้งหมดในแอปพลิเคชัน
 */
export const errorHandler = (
  err: Error | ApiError,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  let error: ApiError;
  
  // บันทึกข้อมูล request
  const context = {
    userId: req.user?.id,
    method: req.method,
    path: req.path,
    query: req.query,
    ip: req.ip,
    userAgent: req.headers['user-agent']
  };
  
  // แปลง error เป็น ApiError ตามประเภท
  if (err instanceof ApiError) {
    error = err;
  } else if (err instanceof PrismaClientKnownRequestError) {
    error = handlePrismaError(err);
  } else if (err.name === 'TokenExpiredError' || err.name === 'JsonWebTokenError') {
    error = handleJwtError(err);
  } else {
    error = new ApiError(
      500,
      'เกิดข้อผิดพลาด กรุณาลองใหม่อีกครั้ง'
    );
  }
  
  // บันทึก error
  const logLevel = error.statusCode >= 500 ? LogLevel.ERROR : LogLevel.WARN;
  logMessage(logLevel, `${error.name}: ${error.message}`, err, context);
  
  // สร้าง response object
  const response = {
    success: false,
    message: error.message,
    ...(error.errorCode && { code: error.errorCode }),
  };
  
  // เพิ่มรายละเอียดเพิ่มเติมในโหมด development
  if (env.NODE_ENV === 'development' && error.details) {
    Object.assign(response, { details: error.details });
    
    // เพิ่ม stack trace ใน development mode
    if (err.stack) {
      Object.assign(response, { stack: err.stack });
    }
  }
  
  // ส่ง response กลับไปยังผู้ใช้
  return res.status(error.statusCode).json(response);
};

/**
 * Middleware สำหรับจัดการเส้นทางที่ไม่มีอยู่
 */
export const notFound = (req: Request, res: Response, next: NextFunction) => {
  const error = new ApiError(404, 'ไม่พบเส้นทางที่คุณต้องการ', 'NOT_FOUND');
  
  // บันทึก error
  logMessage(
    LogLevel.WARN,
    `ไม่พบเส้นทาง: ${req.method} ${req.path}`,
    null,
    {
      method: req.method,
      path: req.originalUrl,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    }
  );
  
  next(error);
};