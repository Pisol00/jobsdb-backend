// src/middleware/asyncHandler.ts
import { Request, Response, NextFunction } from 'express';
import { logMessage, LogLevel } from '../utils/errorLogger';
import { ApiError } from './errorHandler';

/**
 * Middleware แบบ wrapper สำหรับจัดการ async route handlers
 * ช่วยให้ไม่ต้องเขียน try/catch ซ้ำๆ ในทุก controller
 * 
 * @param fn async route handler function
 * @returns wrapped route handler ที่มีการจัดการ error อัตโนมัติ
 */
export const asyncHandler = (
  fn: (req: Request, res: Response, next: NextFunction) => Promise<any>
) => {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      await fn(req, res, next);
    } catch (error) {
      // บันทึก error พร้อมข้อมูลของ request
      logMessage(
        LogLevel.ERROR,
        `Unhandled error in route handler: ${req.method} ${req.path}`,
        error as Error,
        {
          userId: req.user?.id,
          method: req.method,
          path: req.path,
          query: req.query,
          body: req.body,
          ip: req.ip,
          userAgent: req.headers['user-agent'],
        }
      );
      
      // ส่ง error ไปยัง global error handler
      if (error instanceof ApiError) {
        return next(error);
      } else {
        // แปลง error ทั่วไปเป็น ApiError ถ้ายังไม่ใช่
        const apiError = new ApiError(
          500,
          'เกิดข้อผิดพลาด กรุณาลองใหม่อีกครั้ง'
        );
        return next(apiError);
      }
    }
  };
};