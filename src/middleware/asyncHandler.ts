// src/middleware/asyncHandler.ts
import { Request, Response, NextFunction, RequestHandler } from 'express';
import { logMessage, LogLevel } from '../utils/errorLogger';
import { ApiError } from './errorHandler';
import { performance } from 'perf_hooks';

/**
 * ประเภทของฟังก์ชันที่ asyncHandler สามารถจัดการได้
 */
export type AsyncFunction = (
  req: Request, 
  res: Response, 
  next: NextFunction
) => Promise<any>;

/**
 * Middleware แบบ wrapper สำหรับจัดการ async route handlers
 * ช่วยให้ไม่ต้องเขียน try/catch ซ้ำๆ ในทุก controller
 */
export const asyncHandler = (fn: AsyncFunction): RequestHandler => {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    // เก็บเวลาเริ่มต้นสำหรับการวัดประสิทธิภาพ
    const startTime = performance.now();
    
    try {
      // สร้าง context พื้นฐานสำหรับการ logging
      const basicContext = {
        method: req.method,
        path: req.path,
        ip: req.ip || req.socket.remoteAddress || 'unknown',
        userAgent: req.headers['user-agent'],
        userId: req.user?.id,
        queryParams: Object.keys(req.query).length > 0 ? req.query : undefined,
        requestId: req.headers['x-request-id'] || undefined
      };
      
      // บันทึก log ขั้นต้นสำหรับการติดตาม (เฉพาะในโหมด development)
      if (process.env.NODE_ENV === 'development') {
        logMessage(
          LogLevel.INFO,
          `Request started: ${req.method} ${req.path}`,
          null,
          basicContext
        );
      }
      
      // เรียกใช้ handler function
      await fn(req, res, next);
      
      // บันทึกเวลาที่ใช้ในการประมวลผล (เฉพาะในโหมด development)
      if (process.env.NODE_ENV === 'development') {
        const processingTime = performance.now() - startTime;
        logMessage(
          LogLevel.INFO,
          `Request completed: ${req.method} ${req.path} (${processingTime.toFixed(2)}ms)`,
          null,
          basicContext
        );
      }
    } catch (error) {
      // เก็บเวลาที่ใช้จนถึงจุดที่เกิดข้อผิดพลาด
      const processingTime = performance.now() - startTime;
      
      // สร้าง context สำหรับการบันทึก error
      const errorContext = {
        method: req.method,
        path: req.path,
        ip: req.ip || req.socket.remoteAddress || 'unknown',
        userAgent: req.headers['user-agent'],
        userId: req.user?.id,
        query: Object.keys(req.query).length > 0 ? req.query : undefined,
        body: process.env.NODE_ENV === 'development' ? req.body : undefined, // ในโหมด production ไม่บันทึก body
        processingTime: `${processingTime.toFixed(2)}ms`,
        requestId: req.headers['x-request-id'] || undefined
      };
      
      // เก็บเวลาการประมวลผลที่ใช้จนถึงจุดที่เกิดข้อผิดพลาด
      if (error instanceof Error) {
        logMessage(
          LogLevel.ERROR,
          `Error in route handler: ${req.method} ${req.path}`,
          error as Error,
          errorContext
        );
      } else {
        // กรณีที่ไม่ใช่ Error object
        logMessage(
          LogLevel.ERROR,
          `Non-error thrown in route handler: ${req.method} ${req.path}`,
          new Error(String(error)),
          errorContext
        );
      }
      
      // ส่ง error ไปยัง global error handler
      if (error instanceof ApiError) {
        return next(error);
      } else {
        // แปลง error ทั่วไปเป็น ApiError
        const statusCode = error.statusCode || 500;
        const message = error.message || 'เกิดข้อผิดพลาด กรุณาลองใหม่อีกครั้ง';
        const apiError = new ApiError(statusCode, message, error.code || 'SERVER_ERROR');
        
        return next(apiError);
      }
    }
  };
};

/**
 * Middleware สำหรับวัดประสิทธิภาพของ route แบบอัตโนมัติ
 * บันทึกเวลาที่ใช้ในการประมวลผลแต่ละ request
 */
export const performanceMonitor = (
  req: Request, 
  res: Response, 
  next: NextFunction
): void => {
  const startTime = performance.now();
  
  // บันทึกเวลาเมื่อ response เสร็จสิ้น
  res.on('finish', () => {
    const processingTime = performance.now() - startTime;
    const responseTime = processingTime.toFixed(2);
    
    // บันทึก log ถ้าใช้เวลามากกว่า threshold (เช่น 1000ms)
    if (processingTime > 1000) {
      logMessage(
        LogLevel.WARN,
        `Slow request: ${req.method} ${req.path} (${responseTime}ms)`,
        null,
        {
          method: req.method,
          path: req.path,
          statusCode: res.statusCode,
          processingTime: `${responseTime}ms`,
          userId: req.user?.id,
          ip: req.ip || req.socket.remoteAddress || 'unknown'
        }
      );
    } else if (process.env.NODE_ENV === 'development') {
      // ในโหมด development บันทึกทุก request
      logMessage(
        LogLevel.INFO,
        `Request completed: ${req.method} ${req.path} (${responseTime}ms)`,
        null,
        {
          method: req.method,
          path: req.path,
          statusCode: res.statusCode,
          processingTime: `${responseTime}ms`
        }
      );
    }
    
    // เพิ่ม header สำหรับเวลาที่ใช้ในการประมวลผล (เฉพาะในโหมด development)
    if (process.env.NODE_ENV === 'development') {
      res.setHeader('X-Response-Time', `${responseTime}ms`);
    }
  });
  
  next();
};

/**
 * Utility function ที่รวม asyncHandler และ route handler เข้าด้วยกัน
 * เพื่อสร้าง asyncController ที่ใช้งานง่ายขึ้น
 */
export interface ControllerResponse<T = any> {
  status: number;
  data: T;
}

export const asyncController = <T = any, P = any, ResBody = any, ReqBody = any, ReqQuery = any>(
  controllerFn: (req: Request<P, ResBody, ReqBody, ReqQuery>) => Promise<ControllerResponse<T>>
): RequestHandler<P, ResBody, ReqBody, ReqQuery> => {
  return asyncHandler(async (req, res) => {
    const { status, data } = await controllerFn(req as Request<P, ResBody, ReqBody, ReqQuery>);
    res.status(status).json(data);
  });
};