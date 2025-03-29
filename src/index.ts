// src/index.ts
import express, { Express } from 'express';
import cors from 'cors';
import passport from './config/passport';
import authRoutes from './routes/auth';
import prisma, { testConnection } from './utils/prisma';
import { env } from './config/env';
import { errorHandler, notFound } from './middleware/errorHandler';
import { testEmailConnection } from './config/email';
import { performanceMonitor } from './middleware/asyncHandler';

// Initialize Express app
const app: Express = express();
const port = env.PORT;

// Middleware
app.use(cors({
  origin: env.FRONTEND_URL,
  credentials: true
}));
app.use(express.json());
app.use(performanceMonitor); // เพิ่ม middleware สำหรับวัดประสิทธิภาพ

// Initialize Passport
app.use(passport.initialize());

// Routes
app.use('/api/auth', authRoutes);

// Basic route for testing
app.get('/', (req, res) => {
  res.send('Job Search API is running with Prisma, NeonDB and Google OAuth');
});

// Error handling
app.use(notFound);
app.use(errorHandler);

// Start server after database connection check
async function startServer() {
  try {
    // Test database connection
    const dbConnected = await testConnection();
    
    if (!dbConnected) {
      console.error('❌ Cannot connect to database. Exiting...');
      process.exit(1);
    }
    
    // Test email server connection (optional)
    const emailConnected = await testEmailConnection();
    if (!emailConnected) {
      console.warn('⚠️ Email server connection failed. Email features may not work properly.');
    }
    
    // Start server only after confirming database connection
    app.listen(port, () => {
      console.log(`✅ Server is running at http://localhost:${port}`);
      console.log(`✅ Environment: ${env.NODE_ENV}`);
      
      if (env.NODE_ENV === 'development') {
        console.log(`✅ Frontend URL: ${env.FRONTEND_URL}`);
      }
    });
    
    console.log('✅ Routes initialized:');
    console.log('  - Authentication: /api/auth');
    console.log('  - Google OAuth: /api/auth/google');
  } catch (error) {
    console.error('❌ Error starting server:', error);
    process.exit(1);
  }
}

// Call the function to start the server
startServer();

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('✅ Received SIGINT. Graceful shutdown initiated...');
  await cleanupResources();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('✅ Received SIGTERM. Graceful shutdown initiated...');
  await cleanupResources();
  process.exit(0);
});

// Function to cleanup resources
async function cleanupResources() {
  try {
    console.log('✅ Closing database connections...');
    await prisma.$disconnect();
    console.log('✅ Database disconnected successfully');
  } catch (error) {
    console.error('❌ Error during cleanup:', error);
    process.exit(1);
  }
}

// Handling unhandled rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
});

// Handling uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('❌ Uncaught Exception:', error);
  cleanupResources().then(() => {
    process.exit(1);
  }).catch(() => {
    process.exit(1);
  });
});