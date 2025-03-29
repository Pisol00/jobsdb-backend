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
<<<<<<< Updated upstream
=======
      passReqToCallback: true, // ส่ง request object ให้กับ callback
>>>>>>> Stashed changes
    },
    async (accessToken, refreshToken, profile, done) => {
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
            // ถ้ามีผู้ใช้ที่ลงทะเบียนด้วยอีเมลนี้แล้ว ให้อัปเดตข้อมูล OAuth
            user = await prisma.user.update({
              where: { id: existingUser.id },
              data: {
                provider: 'google',
                providerId: profile.id,
                profileImage: profile.photos?.[0]?.value || null,
              },
            });
          } else {
            // สร้าง username จากชื่อของผู้ใช้
            const displayName = profile.displayName || 
                               `${profile.name?.givenName || ''}${profile.name?.familyName || ''}`.trim();
            const username = await generateUsername(displayName || email.split('@')[0]);
            
            // สร้างผู้ใช้ใหม่
            user = await prisma.user.create({
              data: {
                username,
                email,
                fullName: profile.displayName || `${profile.name?.givenName || ''} ${profile.name?.familyName || ''}`.trim(),
                provider: 'google',
                providerId: profile.id,
                profileImage: profile.photos?.[0]?.value || null,
              },
            });
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