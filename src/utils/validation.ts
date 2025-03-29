// src/utils/validation.ts

/**
 * ผลลัพธ์การตรวจสอบความถูกต้อง
 */
export interface ValidationResult {
    isValid: boolean;
    message?: string;
  }
  
  /**
   * ตรวจสอบรูปแบบ username
   * - ต้องประกอบด้วยตัวอักษรภาษาอังกฤษ ตัวเลข และเครื่องหมาย _ เท่านั้น
   * - ต้องมีความยาว 3-20 ตัวอักษร
   */
  export const validateUsername = (username: string): ValidationResult => {
    const usernameRegex = /^[a-zA-Z0-9_]+$/;
    
    if (!usernameRegex.test(username)) {
      return {
        isValid: false,
        message: "Username ต้องประกอบด้วยตัวอักษรภาษาอังกฤษ ตัวเลข และเครื่องหมาย _ เท่านั้น"
      };
    }
    
    if (username.length < 3 || username.length > 20) {
      return {
        isValid: false,
        message: "Username ต้องมีความยาว 3-20 ตัวอักษร"
      };
    }
    
    return { isValid: true };
  };
  
  /**
   * ตรวจสอบรูปแบบรหัสผ่านตามมาตรฐานความปลอดภัย
   * - ต้องมีความยาวอย่างน้อย 8 ตัวอักษร
   * - ต้องมีตัวอักษรพิมพ์ใหญ่อย่างน้อย 1 ตัว
   * - ต้องมีตัวอักษรพิมพ์เล็กอย่างน้อย 1 ตัว
   * - ต้องมีตัวเลขอย่างน้อย 1 ตัว
   * (อักขระพิเศษเป็นตัวเลือกเสริม ไม่บังคับ)
   */
  export const validatePassword = (password: string): ValidationResult => {
    if (password.length < 8) {
      return {
        isValid: false,
        message: "รหัสผ่านต้องมีความยาวอย่างน้อย 8 ตัวอักษร"
      };
    }
    
    if (!/[A-Z]/.test(password)) {
      return {
        isValid: false,
        message: "รหัสผ่านต้องมีตัวอักษรพิมพ์ใหญ่อย่างน้อย 1 ตัว"
      };
    }
    
    if (!/[a-z]/.test(password)) {
      return {
        isValid: false,
        message: "รหัสผ่านต้องมีตัวอักษรพิมพ์เล็กอย่างน้อย 1 ตัว"
      };
    }
    
    if (!/[0-9]/.test(password)) {
      return {
        isValid: false,
        message: "รหัสผ่านต้องมีตัวเลขอย่างน้อย 1 ตัว"
      };
    }
    
    // อักขระพิเศษเป็นตัวเลือกเสริม ไม่ได้บังคับ
    // if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    //   return {
    //     isValid: false,
    //     message: "รหัสผ่านต้องมีอักขระพิเศษอย่างน้อย 1 ตัว (เช่น !@#$%^&*)"
    //   };
    // }
    
    return { isValid: true };
  };
  
  /**
   * ตรวจสอบรูปแบบอีเมล
   */
  export const validateEmail = (email: string): ValidationResult => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    
    if (!emailRegex.test(email)) {
      return {
        isValid: false,
        message: "รูปแบบอีเมลไม่ถูกต้อง"
      };
    }
    
    return { isValid: true };
  };