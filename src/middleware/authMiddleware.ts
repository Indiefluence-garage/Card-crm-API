import { Request, Response, NextFunction } from 'express';
import { jwtService } from '../services/jwtService';

export interface AuthRequest extends Request {
  userId?: string; // Changed from number to string (UUID)
  email?: string;
}

export const authMiddleware = (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.substring(7);
    const decoded = jwtService.verifyToken(token);

    req.userId = decoded.userId; // Now a string UUID
    req.email = decoded.email;

    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};
