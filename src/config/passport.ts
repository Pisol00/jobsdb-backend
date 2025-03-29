// src/config/passport.ts
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import prisma from '../utils/prisma';
import { env } from './env';
import { generateUsername } from '../controllers/auth/register'; // แก้ไขเส้นทาง import
import { logMessage, LogLevel } from '../utils/errorLogger';

// Google OAuth Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: env.GOOGLE_CLIENT_ID,
      clientSecret: env.GOOGLE_CLIENT_SECRET,
      callbackURL: env.GOOGLE_CALLBACK_URL,
      scope: ['profile', 'email'],
      passReqToCallback: true, // ส่ง request object ให้กับ callback
    },
    async (req, accessToken, refreshToken, profile, done) => {
      try {
        // บันทึก context สำหรับการ log
        const context = {
          provider: 'google',
          providerId: profile.id,
          email: profile.emails?.[0]?.value,
          ip: req.ip || req.socket.remoteAddress,
          userAgent: req.headers['user-agent']
        };
        
        logMessage(LogLevel.INFO, 'Google OAuth authentication attempt', null, context);
        
        // ตรวจสอบว่ามีผู้ใช้ในฐานข้อมูลหรือไม่
        let user = await prisma.user.findFirst({
          where: {
            provider: 'google',
            providerId: profile.id,
          },
        });

        // ถ้าพบผู้ใช้ที่มีอยู่แล้ว
        if (user) {
          logMessage(LogLevel.INFO, 'Existing Google user found', null, {
            ...context,
            userId: user.id
          });
          
          // อัปเดตข้อมูลภาพโปรไฟล์ ถ้ามีการเปลี่ยนแปลง
          if (profile.photos?.[0]?.value && profile.photos[0].value !== user.profileImage) {
            user = await prisma.user.update({
              where: { id: user.id },
              data: {
                profileImage: profile.photos[0].value
              }
            });
            
            logMessage(LogLevel.INFO, 'User profile image updated', null, {
              ...context,
              userId: user.id
            });
          }
          
          return done(null, user);
        }

        // ถ้ายังไม่มีผู้ใช้ ให้สร้างผู้ใช้ใหม่
        // ตรวจสอบว่ามีอีเมลหรือไม่
        const email = profile.emails && profile.emails[0].value;
        if (!email) {
          logMessage(LogLevel.ERROR, 'No email provided from Google OAuth', null, context);
          return done(new Error('ไม่พบอีเมลจาก Google OAuth'));
        }

        // ตรวจสอบว่ามีผู้ใช้ที่ใช้อีเมลนี้แล้วหรือไม่
        const existingUser = await prisma.user.findUnique({
          where: { email },
        });

        if (existingUser) {
          // เปลี่ยนจากการอัปเดตเป็นการแจ้งเตือนว่ามีอีเมลนี้ในระบบแล้ว
          if (existingUser.provider === 'local') {
            // ถ้ามีบัญชี local ที่ใช้อีเมลนี้แล้ว ไม่ให้เชื่อมโยงกับ Google
            logMessage(LogLevel.WARN, 'Email exists as local account', null, {
              ...context,
              existingUserId: existingUser.id
            });
            
            return done(null, false, { 
              message: 'อีเมลนี้มีบัญชีในระบบแล้ว กรุณาเข้าสู่ระบบด้วยรหัสผ่าน',
              email,
              errorCode: 'EMAIL_EXISTS_AS_LOCAL'
            });
          } else if (existingUser.provider === 'google') {
            // ถ้ามีบัญชี Google ที่ใช้อีเมลนี้แล้ว แต่ providerId ไม่ตรงกัน (อาจจะมีการเปลี่ยน Google Account)
            logMessage(LogLevel.INFO, 'Updating Google account with new providerId', null, {
              ...context,
              existingUserId: existingUser.id,
              oldProviderId: existingUser.providerId
            });
            
            user = await prisma.user.update({
              where: { id: existingUser.id },
              data: {
                providerId: profile.id,
                profileImage: profile.photos?.[0]?.value || null,
              },
            });
            
            return done(null, user);
          }
        } else {
          // สร้าง username จากชื่อของผู้ใช้
          const displayName = profile.displayName || 
                            `${profile.name?.givenName || ''}${profile.name?.familyName || ''}`.trim();
          
          try {
            const generatedUsername = await generateUsername(displayName || email.split('@')[0]);
            
            logMessage(LogLevel.INFO, 'Creating new Google user', null, {
              ...context,
              generatedUsername
            });
            
            // สร้างผู้ใช้ใหม่
            user = await prisma.user.create({
              data: {
                username: generatedUsername,
                email,
                fullName: profile.displayName || `${profile.name?.givenName || ''} ${profile.name?.familyName || ''}`.trim(),
                provider: 'google',
                providerId: profile.id,
                profileImage: profile.photos?.[0]?.value || null,
              },
            });
            
            logMessage(LogLevel.INFO, 'New Google user created successfully', null, {
              ...context,
              userId: user.id
            });
            
            return done(null, user);
          } catch (error) {
            const errorMsg = `ไม่สามารถสร้าง username ได้: ${error.message}`;
            logMessage(LogLevel.ERROR, errorMsg, error as Error, context);
            return done(new Error(errorMsg));
          }
        }
      } catch (error) {
        logMessage(
          LogLevel.ERROR, 
          'Unexpected error during Google authentication', 
          error as Error, 
          {
            profileId: profile.id,
            email: profile.emails?.[0]?.value
          }
        );
        return done(error as Error);
      }
    }
  )
);

// ตั้งค่า session serialization/deserialization
passport.serializeUser((user: any, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id: string, done) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id },
    });
    
    if (!user) {
      return done(new Error('User not found'), null);
    }
    
    done(null, user);
  } catch (error) {
    logMessage(
      LogLevel.ERROR, 
      'Error deserializing user', 
      error as Error, 
      { userId: id }
    );
    done(error, null);
  }
});

// ฟังก์ชันช่วยเหลือสำหรับการตรวจสอบสถานะการตั้งค่า OAuth
export const verifyOAuthConfig = (): boolean => {
  const missingEnvVars = [];
  
  if (!env.GOOGLE_CLIENT_ID) missingEnvVars.push('GOOGLE_CLIENT_ID');
  if (!env.GOOGLE_CLIENT_SECRET) missingEnvVars.push('GOOGLE_CLIENT_SECRET');
  if (!env.GOOGLE_CALLBACK_URL) missingEnvVars.push('GOOGLE_CALLBACK_URL');
  
  if (missingEnvVars.length > 0) {
    console.warn(`⚠️ Missing OAuth environment variables: ${missingEnvVars.join(', ')}`);
    return false;
  }
  
  return true;
};

// ตรวจสอบการตั้งค่า OAuth เมื่อโมดูลถูกนำเข้า
verifyOAuthConfig();

export default passport;