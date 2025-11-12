import express from 'express';
import dotenv from 'dotenv';
import { config } from './config';
import authRouter from './api/auth';
import usersRouter from './api/users';

dotenv.config();

const app = express();
app.use(express.json());

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'API is running' });
});

// Auth routes (public)
app.use('/auth', authRouter);

// Users routes (protected)
app.use('/users', usersRouter);

app.listen(config.port, () => {
  console.log(`Server running on port ${config.port}`);
});
