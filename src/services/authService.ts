import { db } from '../db/drizzle';
import { users } from '../db/schema';
import { eq } from 'drizzle-orm';
import { jwtService } from './jwtService';
import { passwordService } from './passwordService';
import { emailService } from './emailService';
import { emailVerificationService } from './emailVerificationService';

export const authService = {
  // Register with email/password (without verification yet)
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

      // Create user (not verified yet)
      const newUser = await db
        .insert(users)
        .values({
          email,
          password: hashedPassword,
          firstName,
          lastName,
          authProvider: 'email',
          isEmailVerified: false, // Set to false initially
        })
        .returning();

      const user = newUser[0];

      // Generate OTP
      const otp = await emailVerificationService.generateOTP(email);

      // Send OTP email
      await emailService.sendOTP(email, otp);

      return {
        message: 'Registration successful. OTP sent to your email.',
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          isEmailVerified: false,
        },
      };
    } catch (error: any) {
      throw new Error(error.message || 'Registration failed');
    }
  },

  // Verify email with OTP
  async verifyEmail(email: string, otp: string) {
    try {
      // Verify OTP
      await emailVerificationService.verifyOTP(email, otp);

      // Update user as verified
      const updated = await db
        .update(users)
        .set({ isEmailVerified: true })
        .where(eq(users.email, email))
        .returning();

      if (updated.length === 0) {
        throw new Error('User not found');
      }

      const user = updated[0];

      // Generate JWT token
      const token = jwtService.generateToken(user.id, user.email);

      // Send welcome email
      await emailService.sendWelcomeEmail(email, user.firstName);

      return {
        message: 'Email verified successfully',
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          isEmailVerified: true,
        },
        token,
      };
    } catch (error: any) {
      throw new Error(error.message || 'Email verification failed');
    }
  },

  // Resend OTP
  async resendOTP(email: string) {
    try {
      // Check if user exists
      const user = await db
        .select()
        .from(users)
        .where(eq(users.email, email));

      if (user.length === 0) {
        throw new Error('User not found');
      }

      if (user[0].isEmailVerified) {
        throw new Error('Email is already verified');
      }

      // Generate new OTP
      const otp = await emailVerificationService.generateOTP(email);

      // Send OTP email
      await emailService.sendOTP(email, otp);

      return {
        message: 'OTP sent to your email',
      };
    } catch (error: any) {
      throw new Error(error.message || 'Failed to resend OTP');
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

      // Check if email is verified
      if (!user.isEmailVerified) {
        throw new Error('Please verify your email first. Check your inbox for OTP.');
      }

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
          isEmailVerified: true,
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
