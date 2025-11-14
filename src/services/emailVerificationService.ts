import { db } from '../db/drizzle';
import { emailVerifications } from '../db/schema';
import { eq, sql } from 'drizzle-orm';
import crypto from 'crypto';

function generateOTP(): string {
  return crypto.randomInt(100000, 999999).toString();
}

export const emailVerificationService = {
  async generateOTP(email: string): Promise<string> {
    try {
      const otp = generateOTP();
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

      const existing = await db
        .select()
        .from(emailVerifications)
        .where(eq(emailVerifications.email, email));

      if (existing.length > 0) {
        await db
          .update(emailVerifications)
          .set({ otp, expiresAt, attempts: 0 })
          .where(eq(emailVerifications.email, email));
      } else {
        await db.insert(emailVerifications).values({
          email,
          otp,
          expiresAt,
          attempts: 0,
        });
      }

      return otp;
    } catch (error) {
      console.error('Generate OTP failed:', error);
      throw new Error('Failed to generate OTP');
    }
  },

  async verifyOTP(email: string, otp: string): Promise<boolean> {
    try {
      const records = await db
        .select()
        .from(emailVerifications)
        .where(eq(emailVerifications.email, email));

      if (records.length === 0) {
        throw new Error('OTP not found');
      }

      const record = records[0];

      if (new Date() > record.expiresAt) {
        throw new Error('OTP has expired');
      }

      if (record.attempts >= 3) {
        throw new Error('Too many attempts. Please request a new OTP.');
      }

      if (record.otp !== otp) {
        await db
          .update(emailVerifications)
          .set({ attempts: record.attempts + 1 })
          .where(eq(emailVerifications.email, email));
        throw new Error('Invalid OTP');
      }

      await db.delete(emailVerifications).where(eq(emailVerifications.email, email));

      return true;
    } catch (error) {
      console.error('Verify OTP failed:', error);
      throw new Error(error.message || 'OTP verification failed');
    }
  },

  async cleanupExpiredOTPs(): Promise<void> {
    try {
      await db.delete(emailVerifications).where(sql`${emailVerifications.expiresAt} < NOW()`);
    } catch (error) {
      console.error('Failed to cleanup expired OTPs:', error);
    }
  },
};
