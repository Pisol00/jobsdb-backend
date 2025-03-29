// src/config/passport.ts
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import prisma from '../utils/prisma';
import { env } from './env';
import { generateUsername } from '../controllers/auth/register';

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
        // ตรวจสอบว่ามีผู้ใช้ในฐานข้อมูลหรือไม่
        let user = await prisma.user.findFirst({
          where: {
            provider: 'google',
            providerId: profile.id,
          },
        });

        // ถ้ายังไม่มีผู้ใช้ ให้สร้างผู้ใช้ใหม่
        if (!user) {
          // ตรวจสอบว่ามีอีเมลหรือไม่
          const email = profile.emails && profile.emails[0].value;
          if (!email) {
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
              return done(null, false, { 
                message: 'อีเมลนี้มีบัญชีในระบบแล้ว กรุณาเข้าสู่ระบบด้วยรหัสผ่าน',
                email,
                errorCode: 'EMAIL_EXISTS_AS_LOCAL'
              });
            } else if (existingUser.provider === 'google') {
              // ถ้ามีบัญชี Google ที่ใช้อีเมลนี้แล้ว แต่ providerId ไม่ตรงกัน (อาจจะมีการเปลี่ยน Google Account)
              user = await prisma.user.update({
                where: { id: existingUser.id },
                data: {
                  providerId: profile.id,
                  profileImage: profile.photos?.[0]?.value || null,
                },
              });
            }
          } else {
            // สร้าง username จากชื่อของผู้ใช้
            const displayName = profile.displayName || 
                               `${profile.name?.givenName || ''}${profile.name?.familyName || ''}`.trim();
            // แก้ไข: ต้องรอให้ generateUsername ทำงานเสร็จก่อน
            try {
              const generatedUsername = await generateUsername(displayName || email.split('@')[0]);
              
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
            } catch (error) {
              return done(new Error(`ไม่สามารถสร้าง username ได้: ${error.message}`));
            }
          }
        }

        return done(null, user);
      } catch (error) {
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
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

export default passport;