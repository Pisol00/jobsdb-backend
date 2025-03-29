// src/index.ts
import express, { Express } from 'express';
import cors from 'cors';
import passport from './config/passport';
import authRoutes from './routes/auth';
import prisma, { testConnection } from './utils/prisma';
import { env } from './config/env';
import { errorHandler, notFound } from './middleware/errorHandler';

// Initialize Express app
const app: Express = express();
const port = env.PORT;

// Start server function with async/await
const startServer = async () => {
  try {
    // Test database connection
    const connected = await testConnection();
    if (!connected) {
      console.error('❌ Cannot connect to database. Exiting...');
      process.exit(1);
    }

    // Middleware
    app.use(cors({
      origin: env.FRONTEND_URL,
      credentials: true
    }));
    app.use(express.json());

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

    // Start server
    app.listen(port, () => {
      console.log(`✅ Server is running at http://localhost:${port}`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
};

// Execute the start server function
startServer();

// Graceful shutdown
process.on('SIGINT', async () => {
  await prisma.$disconnect();
  console.log('✅ Disconnected from database');
  process.exit(0);
});

process.on('SIGTERM', async () => {
  await prisma.$disconnect();
  console.log('✅ Disconnected from database');
  process.exit(0);
});