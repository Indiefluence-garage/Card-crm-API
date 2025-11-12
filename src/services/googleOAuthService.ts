import axios from 'axios';
import { db } from '../db/drizzle';
import { users } from '../db/schema';
import { eq } from 'drizzle-orm';
import { jwtService } from './jwtService';
import { config } from '../config';

interface GoogleTokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
  token_type: string;
  id_token: string;
}

interface GoogleUserInfo {
  id: string;
  email: string;
  name: string;
  picture: string;
  given_name: string;
  family_name: string;
}

export const googleOAuthService = {
  // Generate Google OAuth URL
  getGoogleAuthUrl() {
    const params = new URLSearchParams({
      client_id: config.google.clientId!,
      redirect_uri: config.google.redirectUri!,
      response_type: 'code',
      scope: 'openid email profile',
      access_type: 'offline',
    });

    return `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
  },

  // Exchange authorization code for tokens
  async exchangeCodeForToken(code: string): Promise<GoogleTokenResponse> {
    try {
      const response = await axios.post('https://oauth2.googleapis.com/token', {
        code,
        client_id: config.google.clientId,
        client_secret: config.google.clientSecret,
        redirect_uri: config.google.redirectUri,
        grant_type: 'authorization_code',
      });

      return response.data;
    } catch (error: any) {
      throw new Error('Failed to exchange code for token');
    }
  },

  // Get user info from Google
  async getGoogleUserInfo(accessToken: string): Promise<GoogleUserInfo> {
    try {
      const response = await axios.get(
        'https://www.googleapis.com/oauth2/v2/userinfo',
        {
          headers: { Authorization: `Bearer ${accessToken}` },
        }
      );

      return response.data;
    } catch (error) {
      throw new Error('Failed to fetch user info from Google');
    }
  },

  // Handle Google sign-in/sign-up
  async handleGoogleAuth(code: string) {
    try {
      // Exchange code for tokens
      const tokenResponse = await this.exchangeCodeForToken(code);

      // Get user info
      const googleUser = await this.getGoogleUserInfo(tokenResponse.access_token);

      // Check if user exists
      let user = await db
        .select()
        .from(users)
        .where(eq(users.email, googleUser.email));

      if (user.length > 0) {
        // User exists, update if needed
        const existingUser = user[0];
        if (existingUser.googleId !== googleUser.id) {
          await db
            .update(users)
            .set({ googleId: googleUser.id })
            .where(eq(users.id, existingUser.id));
        }
        user = await db
          .select()
          .from(users)
          .where(eq(users.id, existingUser.id));
      } else {
        // Create new user
        const newUser = await db
          .insert(users)
          .values({
            email: googleUser.email,
            firstName: googleUser.given_name || googleUser.name.split(' ')[0],
            lastName: googleUser.family_name || googleUser.name.split(' ')[1] || '',
            imageUrl: googleUser.picture,
            googleId: googleUser.id,
            authProvider: 'google',
            isEmailVerified: true,
          })
          .returning();

        user = newUser;
      }

      const userData = user[0];

      // Generate JWT token
      const token = jwtService.generateToken(userData.id, userData.email);

      return {
        user: {
          id: userData.id,
          email: userData.email,
          firstName: userData.firstName,
          lastName: userData.lastName,
          imageUrl: userData.imageUrl,
        },
        token,
      };
    } catch (error: any) {
      throw new Error(error.message || 'Google authentication failed');
    }
  },
};
