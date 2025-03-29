// src/middleware/errorHandler.ts
import { Request, Response, NextFunction } from 'express';

/**
 * Class สำหรับจัดการข้อผิดพลาดที่มีรหัสสถานะ
 */
export class ApiError extends Error {
  statusCode: number;
  
  constructor(statusCode: number, message: string) {
    super(message);
    this.statusCode = statusCode;
    this.name = this.constructor.name;
    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Middleware เพื่อจัดการข้อผิดพลาดทั้งหมดในแอปพลิเคชัน
 */
export const errorHandler = (
  err: Error | ApiError,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  console.error('❌ Error:', err);
  
  // กรณีเป็น ApiError จะมี statusCode
  if (err instanceof ApiError) {
    return res.status(err.statusCode).json({
      success: false,
      message: err.message,
    });
  }

  // กรณีไม่มี statusCode ให้ถือว่าเป็น Internal Server Error (500)
  return res.status(500).json({
    success: false,
    message: 'เกิดข้อผิดพลาด กรุณาลองใหม่อีกครั้ง',
  });
};

/**
 * Middleware สำหรับจัดการเส้นทางที่ไม่มีอยู่
 */
export const notFound = (req: Request, res: Response) => {
  res.status(404).json({
    success: false,
    message: 'ไม่พบเส้นทางที่คุณต้องการ',
  });
};