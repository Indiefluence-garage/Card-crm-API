import dotenv from 'dotenv';

dotenv.config();

export const config = {
  database: {
    url: process.env.DATABASE_URL,
  },
  jwt: {
    secret: process.env.JWT_SECRET || 'your-secret-key-change-this',
    expiresIn: '7d',
  },
  google: {
    clientId: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    redirectUri: process.env.GOOGLE_REDIRECT_URI,
  },
  port: process.env.PORT || 4000,
};
