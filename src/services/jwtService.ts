import jwt from 'jsonwebtoken';
import { config } from '../config';

export const jwtService = {
  generateToken(userId: number, email: string) {
    return jwt.sign(
      { userId, email },
      config.jwt.secret,
      { expiresIn: config.jwt.expiresIn }
    );
  },

  verifyToken(token: string) {
    try {
      const decoded = jwt.verify(token, config.jwt.secret) as {
        userId: number;
        email: string;
      };
      return decoded;
    } catch (error) {
      throw new Error('Invalid token');
    }
  },

  decodeToken(token: string) {
    return jwt.decode(token);
  },
};
