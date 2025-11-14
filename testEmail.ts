import { emailService } from './src/services/emailService';

async function test() {
  try {
    await emailService.sendOTP('anuragmishra262000@gmail.com', '123456');
    console.log('OTP email sent successfully');
  } catch (error) {
    console.error('Email test failed:', error);
  }
}

test();
