// src/middleware/asyncHandler.ts
import { Request, Response, NextFunction } from 'express';
import { logMessage, LogLevel } from '../utils/errorLogger';
import { ApiError } from './errorHandler';

/**
 * Type สำหรับฟังก์ชัน Express route handler
 */
type ExpressHandler = (
  req: Request, 
  res: Response, 
  next: NextFunction
) => Promise<any>;

/**
 * Middleware แบบ wrapper สำหรับจัดการ async route handlers
 * ช่วยให้ไม่ต้องเขียน try/catch ซ้ำๆ ในทุก controller
 * 
 * @param fn async route handler function
 * @returns wrapped route handler ที่มีการจัดการ error อัตโนมัติ
 */
export const asyncHandler = (fn: ExpressHandler): ExpressHandler => {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      // ติดตามว่า response ถูกส่งแล้วหรือไม่
      let isResponseSent = false;
      
      // สร้าง promise จาก handler
      const resultPromise = fn(req, res, next);
      
      // ตรวจจับเหตุการณ์ที่ response ถูกส่งแล้ว
      const originalEnd = res.end;
      res.end = function(...args: any[]): any {
        isResponseSent = true;
        return originalEnd.apply(res, args);
      };
      
      // รอให้ Promise เสร็จสิ้น
      await resultPromise;
      
      // คืนค่า function res.end เดิม
      res.end = originalEnd;
    } catch (error: unknown) {
      // จัดการกับ error ตาม type
      const errorObject = error instanceof Error 
        ? error 
        : new Error(typeof error === 'string' ? error : 'Unknown error');
      
      // บันทึก error พร้อมข้อมูลของ request
      logMessage(
        LogLevel.ERROR,
        `Unhandled error in route handler: ${req.method} ${req.path}`,
        errorObject,
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
      
      // ตรวจสอบว่า response ถูกส่งแล้วหรือไม่
      if (res.headersSent) {
        // ถ้า response ถูกส่งแล้ว ไม่สามารถส่ง error response ได้
        return next(errorObject);
      }
      
      // ส่ง error ไปยัง global error handler
      if (error instanceof ApiError) {
        return next(error);
      } else {
        // แปลง error ทั่วไปเป็น ApiError ถ้ายังไม่ใช่
        const apiError = new ApiError(
          500,
          'เกิดข้อผิดพลาด กรุณาลองใหม่อีกครั้ง',
          'INTERNAL_SERVER_ERROR',
          process.env.NODE_ENV === 'development' ? { 
            originalError: errorObject.message,
            stack: errorObject.stack 
          } : undefined
        );
        return next(apiError);
      }
    }
  };
};

/**
 * เวอร์ชันที่ง่ายขึ้นของ asyncHandler สำหรับ middleware ที่ไม่ส่ง response
 * เหมาะสำหรับ middleware ที่เรียกต่อไปยัง middleware ถัดไปด้วย next()
 */
export const asyncMiddleware = (fn: ExpressHandler): ExpressHandler => {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      await fn(req, res, next);
    } catch (error: unknown) {
      next(error instanceof Error ? error : new Error(String(error)));
    }
  };
};