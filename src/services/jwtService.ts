import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this';
const JWT_EXPIRY = process.env.JWT_EXPIRY || '7d';

interface JWTPayload {
  userId: string; // Changed from number to string (UUID)
  email: string;
}

export const jwtService = {
  generateToken(userId: string, email: string): string { // Changed from number to string
    return jwt.sign(
      { userId, email } as JWTPayload,
      JWT_SECRET,
      { expiresIn: JWT_EXPIRY }
    );
  },

  verifyToken(token: string): JWTPayload {
    try {
      const decoded = jwt.verify(token, JWT_SECRET) as JWTPayload;
      return decoded;
    } catch (error) {
      throw new Error('Invalid or expired token');
    }
  },
};
