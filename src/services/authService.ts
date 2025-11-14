import { db } from '../db/drizzle';
import { users } from '../db/schema';
import { eq } from 'drizzle-orm';
import { jwtService } from './jwtService';
import { passwordService } from './passwordService';
import { emailService } from './emailService';
import { emailVerificationService } from './emailVerificationService';

export const authService = {
  // Register with email/password and AUTOMATICALLY send OTP email
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
          isEmailVerified: false,
        })
        .returning();

      const user = newUser[0];

      // Generate OTP
      const otp = await emailVerificationService.generateOTP(email);

      // AUTOMATICALLY send OTP email (no frontend trigger needed)
      try {
        await emailService.sendOTP(email, otp);
        console.log(`✅ OTP email sent successfully to ${email}`);
      } catch (emailError: any) {
        // Log error but don't fail registration
        console.error('❌ Failed to send OTP email:', emailError.message);
        // Consider: Should we rollback user creation if email fails?
        // For now, we'll allow registration to succeed but log the error
        throw new Error('Registration successful but failed to send OTP email. Please use resend OTP.');
      }

      return {
        success: true,
        message: 'Registration successful. OTP sent to your email.',
        user: {
          id: user.id, // UUID string
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          isEmailVerified: false,
        },
      };
    } catch (error: any) {
      console.error('Registration service error:', error);
      throw new Error(error.message || 'Registration failed');
    }
  },

  // Verify email with OTP and send welcome email
  async verifyEmail(email: string, otp: string) {
    try {
      // Verify OTP
      await emailVerificationService.verifyOTP(email, otp);

      // Update user as verified
      const updated = await db
        .update(users)
        .set({ isEmailVerified: true, updatedAt: new Date() })
        .where(eq(users.email, email))
        .returning();

      if (updated.length === 0) {
        throw new Error('User not found');
      }

      const user = updated[0];

      // Generate JWT token
      const token = jwtService.generateToken(user.id, user.email);

      // AUTOMATICALLY send welcome email
      try {
        await emailService.sendWelcomeEmail(email, user.firstName);
        console.log(`✅ Welcome email sent to ${email}`);
      } catch (emailError: any) {
        console.error('❌ Failed to send welcome email:', emailError.message);
        // Don't fail verification if welcome email fails
      }

      return {
        success: true,
        message: 'Email verified successfully',
        user: {
          id: user.id, // UUID string
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          isEmailVerified: true,
        },
        token,
      };
    } catch (error: any) {
      console.error('Email verification service error:', error);
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

      // AUTOMATICALLY send OTP email
      try {
        await emailService.sendOTP(email, otp);
        console.log(`✅ OTP resent successfully to ${email}`);
      } catch (emailError: any) {
        console.error('❌ Failed to resend OTP email:', emailError.message);
        throw new Error('Failed to send OTP email. Please try again later.');
      }

      return {
        success: true,
        message: 'OTP sent to your email',
      };
    } catch (error: any) {
      console.error('Resend OTP service error:', error);
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
        success: true,
        user: {
          id: user.id, // UUID string
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          imageUrl: user.imageUrl,
          isEmailVerified: true,
        },
        token,
      };
    } catch (error: any) {
      console.error('Login service error:', error);
      throw new Error(error.message || 'Login failed');
    }
  },

  // Get user by ID (UUID)
  async getUserById(userId: string) { // Changed from number to string
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
      console.error('Get user by ID error:', error);
      throw new Error('Failed to fetch user');
    }
  },

  // Update user profile
  async updateUser(userId: string, data: Partial<any>) { // Changed from number to string
    try {
      const updateData: any = { updatedAt: new Date() };

      // Only include fields that are provided
      if (data.firstName !== undefined) updateData.firstName = data.firstName;
      if (data.lastName !== undefined) updateData.lastName = data.lastName;
      if (data.imageUrl !== undefined) updateData.imageUrl = data.imageUrl;

      const updated = await db
        .update(users)
        .set(updateData)
        .where(eq(users.id, userId))
        .returning();

      if (updated.length === 0) {
        throw new Error('User not found');
      }

      return updated[0];
    } catch (error) {
      console.error('Update user error:', error);
      throw new Error('Failed to update user');
    }
  },
};
