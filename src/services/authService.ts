import { db } from '../db/drizzle';
import { users } from '../db/schema';
import { eq } from 'drizzle-orm';
import { jwtService } from './jwtService';
import { passwordService } from './passwordService';

export const authService = {
  // Register with email/password
  async register(
    email: string,
    password: string,
    firstName: string,
    lastName: string
  ) {
    try {
      // Check if user exists
      const existingUser = await db
        .select()
        .from(users)
        .where(eq(users.email, email));

      if (existingUser.length > 0) {
        throw new Error('User already exists with this email');
      }

      // Hash password
      const hashedPassword = await passwordService.hashPassword(password);

      // Create user
      const newUser = await db
        .insert(users)
        .values({
          email,
          password: hashedPassword,
          firstName,
          lastName,
          authProvider: 'email',
        })
        .returning();

      const user = newUser[0];

      // Generate token
      const token = jwtService.generateToken(user.id, user.email);

      return {
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
        },
        token,
      };
    } catch (error: any) {
      throw new Error(error.message || 'Registration failed');
    }
  },

  // Login with email/password
  async login(email: string, password: string) {
    try {
      // Find user
      const userResult = await db
        .select()
        .from(users)
        .where(eq(users.email, email));

      if (userResult.length === 0) {
        throw new Error('Invalid email or password');
      }

      const user = userResult[0];

      // Check if user has password (not Google-only account)
      if (!user.password) {
        throw new Error('Please use Google sign-in for this account');
      }

      // Compare password
      const isValidPassword = await passwordService.comparePassword(
        password,
        user.password
      );

      if (!isValidPassword) {
        throw new Error('Invalid email or password');
      }

      // Generate token
      const token = jwtService.generateToken(user.id, user.email);

      return {
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
        },
        token,
      };
    } catch (error: any) {
      throw new Error(error.message || 'Login failed');
    }
  },

  // Get user by ID
  async getUserById(userId: number) {
    try {
      const user = await db
        .select()
        .from(users)
        .where(eq(users.id, userId));

      if (user.length === 0) {
        return null;
      }

      return user[0];
    } catch (error) {
      throw new Error('Failed to fetch user');
    }
  },

  // Update user profile
  async updateUser(userId: number, data: Partial<any>) {
    try {
      const updated = await db
        .update(users)
        .set({
          ...data,
          updatedAt: new Date(),
        })
        .where(eq(users.id, userId))
        .returning();

      return updated[0];
    } catch (error) {
      throw new Error('Failed to update user');
    }
  },
};
