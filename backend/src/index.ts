import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import { createServer } from 'http';
import { Server } from 'socket.io';
import authRoutes from './routes/auth.routes';
import sosRoutes from './routes/sos.routes';
import presentationRoutes from './routes/presentation.routes';
import riskZonesRoutes from './routes/risk-zones.routes';
import analyticsRoutes from './routes/analytics.routes';
import { setupSocketHandlers } from './sockets/handlers';
import { authenticateToken, AuthRequest } from './middlewares/auth';

dotenv.config();

const app = express();

const allowedOrigins = [
  'http://localhost:3000',
  'https://aurora-sentinals-frontend-33py4uy43-nandantemkars-projects.vercel.app',
  'https://aurora-sentinal.space',
];

app.use(
  cors({
    origin: [
      "https://aurora-sentinal.space",
      "https://www.aurora-sentinal.space",
      /^https:\/\/.*\.vercel\.app$/,
    ],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);


app.use(express.json());
app.use(cookieParser());
const httpServer = createServer(app);
const io = new Server(httpServer);


const PORT = process.env.PORT || 3001;


app.use(express.json());
app.use(cookieParser());
app.use(express.static('uploads'));

// Make io available to routes
app.use((req: AuthRequest, res, next) => {
  (req as any).io = io;
  next();
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/sos', sosRoutes);
app.use('/api/presentation', presentationRoutes);
app.use('/api/risk-zones', riskZonesRoutes);
app.use('/api/analytics', analyticsRoutes);

// Error handling
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Setup Socket.io handlers
setupSocketHandlers(io);

// Start server
httpServer.listen(PORT, () => {
  console.log(`🚀 Aurora Sentinel Backend running on port ${PORT}`);
  console.log(`📡 WebSocket server ready`);
  console.log(`🔗 CORS enabled for: ${process.env.CORS_ORIGIN || 'http://localhost:3000'}`);
});


