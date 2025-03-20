import { DataSource } from 'typeorm';
import dotenv from 'dotenv';

dotenv.config();

const DATABASE_URL = process.env.DATABASE_URL as string;

export const AppDataSource = new DataSource({
  type: 'postgres',
  url: DATABASE_URL,
  ssl: {
    rejectUnauthorized: false, // จำเป็นสำหรับการเชื่อมต่อกับ Neon DB
  },
  entities: [__dirname + '/../models/*.{js,ts}'],
  synchronize: true, // ใช้ในการพัฒนา ไม่แนะนำสำหรับ production
});

export const connectDB = async () => {
  try {
    await AppDataSource.initialize();
    console.log('PostgreSQL database connected successfully');
  } catch (error) {
    console.error('Database connection error:', error);
    process.exit(1);
  }
};