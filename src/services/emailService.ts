import nodemailer from 'nodemailer';
import { config as dotenvConfig } from 'dotenv';

dotenvConfig();

const transporter = nodemailer.createTransport({
  host: 'smtp.hostinger.com',
  port: 465,
  secure: true, // true for port 465, false for 587
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});

export const emailService = {
  async sendOTP(email: string, otp: string): Promise<boolean> {
    try {
      const htmlContent = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin:auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
          <h2 style="color:#333;">Email Verification</h2>
          <p>Hello,</p>
          <p>Your OTP for email verification is:</p>
          <div style="text-align:center; margin: 20px 0;">
            <span style="font-size: 36px; font-weight: bold; letter-spacing: 10px; color: #007bff; user-select: all;">${otp}</span>
          </div>
          <p>This OTP is valid for 10 minutes.</p>
          <p>If you did not request this code, please ignore this email.</p>
          <p>Thanks,<br />CardCRM Team</p>
          <hr style="margin-top: 40px; border: none; border-top: 1px solid #eee;" />
          <small style="color: #666;">&copy; ${new Date().getFullYear()} CardCRM. All rights reserved.</small>
        </div>
      `;

      await transporter.sendMail({
        from: process.env.EMAIL_FROM || '"CardCRM" <card@indietrbie.space>',
        to: email,
        subject: 'Email Verification OTP for CardCRM',
        html: htmlContent,
      });

      return true;
    } catch (error) {
      console.error('Failed to send OTP email:', error);
      throw error; // Throw the original error for better debugging
    }
  },

  async sendWelcomeEmail(email: string, name: string): Promise<boolean> {
    try {
      const htmlContent = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin:auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
          <h2 style="color:#333;">Welcome to CardCRM, ${name}!</h2>
          <p>Your account has been successfully verified.</p>
          <p>Thank you for joining us.</p>
          <p>Best regards,<br />CardCRM Team</p>
          <hr style="margin-top: 40px; border: none; border-top: 1px solid #eee;" />
          <small style="color: #666;">&copy; ${new Date().getFullYear()} CardCRM. All rights reserved.</small>
        </div>
      `;

      await transporter.sendMail({
        from: process.env.EMAIL_FROM || '"CardCRM" <card@indietrbie.space>',
        to: email,
        subject: 'Welcome to CardCRM!',
        html: htmlContent,
      });

      return true;
    } catch (error) {
      console.error('Failed to send welcome email:', error);
      throw error;
    }
  },
};
