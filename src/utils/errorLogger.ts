// src/utils/errorLogger.ts
import { ApiError } from '../middleware/errorHandler';
import { env } from '../config/env';

/**
 * ระดับความรุนแรงของ log
 */
export enum LogLevel {
  INFO = 'INFO',
  WARN = 'WARN',
  ERROR = 'ERROR',
  FATAL = 'FATAL',
}

/**
 * ข้อมูลเพิ่มเติมสำหรับการ log
 */
interface LogContext {
  userId?: string;
  requestId?: string;
  path?: string;
  [key: string]: any;
}

/**
 * บันทึก error หรือ log message
 * 
 * @param level ระดับความรุนแรงของ log
 * @param message ข้อความที่ต้องการ log
 * @param error error object (ถ้ามี)
 * @param context ข้อมูลเพิ่มเติม
 */
export const logMessage = (
  level: LogLevel,
  message: string,
  error?: Error | null,
  context?: LogContext
) => {
  const timestamp = new Date().toISOString();
  const isDevelopment = env.NODE_ENV === 'development';
  
  // สร้าง log object
  const logObject = {
    timestamp,
    level,
    message,
    error: error ? {
      name: error.name,
      message: error.message,
      stack: isDevelopment ? error.stack : undefined,
    } : undefined,
    ...context,
  };
  
  // แสดงผลตามระดับ log
  switch (level) {
    case LogLevel.INFO:
      console.log(`✅ [${timestamp}] INFO:`, message, context || '');
      break;
    case LogLevel.WARN:
      console.warn(`⚠️ [${timestamp}] WARN:`, message, error || '', context || '');
      break;
    case LogLevel.ERROR:
      console.error(`❌ [${timestamp}] ERROR:`, message, error || '', context || '');
      break;
    case LogLevel.FATAL:
      console.error(`🔥 [${timestamp}] FATAL:`, message, error || '', context || '');
      break;
  }
  
  // สำหรับ Production อาจเพิ่มการส่ง log ไปยังบริการอื่น เช่น Sentry, LogRocket, etc.
  if (env.NODE_ENV === 'production') {
    // TODO: ส่ง log ไปยังบริการ monitoring หรือ logging ระบบอื่น
    // เช่น Sentry.captureException(error, { extra: context });
  }
  
  return logObject;
};

/**
 * บันทึก error และสร้าง ApiError
 * 
 * @param statusCode HTTP status code
 * @param message ข้อความที่ต้องการแสดงให้ผู้ใช้
 * @param error error object ต้นฉบับ (ถ้ามี)
 * @param context ข้อมูลเพิ่มเติม
 * @returns ApiError
 */
export const logAndCreateApiError = (
  statusCode: number,
  message: string,
  error?: Error | null,
  context?: LogContext
): ApiError => {
  const logLevel = statusCode >= 500 ? LogLevel.ERROR : LogLevel.WARN;
  
  logMessage(logLevel, message, error, context);
  
  return new ApiError(statusCode, message);
};

/**
 * Utility สำหรับ async function เพื่อให้มีการจัดการ error อย่างสม่ำเสมอ
 * 
 * @param fn async function ที่ต้องการ wrap
 * @param errorHandler function สำหรับจัดการ error
 * @returns wrapped function
 */
export function withErrorHandling<T, A extends any[]>(
  fn: (...args: A) => Promise<T>,
  errorHandler: (error: any, ...args: A) => Promise<T>
) {
  return async (...args: A): Promise<T> => {
    try {
      return await fn(...args);
    } catch (error) {
      return errorHandler(error, ...args);
    }
  };
}