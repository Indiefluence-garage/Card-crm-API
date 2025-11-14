import express, { Request, Response } from 'express';
import { authService } from '../services/authService';
import { googleOAuthService } from '../services/googleOAuthService';
import { authMiddleware, AuthRequest } from '../middleware/authMiddleware';
import {
  registerSchema,
  loginSchema,
  sendOTPSchema,
  verifyOTPSchema,
} from '../utils/validators';

const router = express.Router();

// ==================== EMAIL/PASSWORD ROUTES ====================

// REGISTER - Step 1: Create account and automatically send OTP email
router.post('/register', async (req: Request, res: Response) => {
  try {
    const validatedData = registerSchema.parse(req.body);

    const result = await authService.register(
      validatedData.email,
      validatedData.password,
      validatedData.firstName,
      validatedData.lastName
    );

    // Email is automatically sent inside authService.register
    // Frontend doesn't need to trigger anything else
    res.status(201).json(result);
  } catch (error: any) {
    console.error('Registration error:', error);
    res.status(400).json({ error: error.message });
  }
});

// VERIFY EMAIL - Step 2: Verify with OTP
router.post('/verify-email', async (req: Request, res: Response) => {
  try {
    const validatedData = verifyOTPSchema.parse(req.body);

    const result = await authService.verifyEmail(
      validatedData.email,
      validatedData.otp
    );

    res.json(result);
  } catch (error: any) {
    console.error('Email verification error:', error);
    res.status(400).json({ error: error.message });
  }
});

// RESEND OTP
router.post('/resend-otp', async (req: Request, res: Response) => {
  try {
    const validatedData = sendOTPSchema.parse(req.body);

    const result = await authService.resendOTP(validatedData.email);

    res.json(result);
  } catch (error: any) {
    console.error('Resend OTP error:', error);
    res.status(400).json({ error: error.message });
  }
});

// LOGIN
router.post('/login', async (req: Request, res: Response) => {
  try {
    const validatedData = loginSchema.parse(req.body);

    const result = await authService.login(
      validatedData.email,
      validatedData.password
    );

    res.json({
      message: 'Login successful',
      ...result,
    });
  } catch (error: any) {
    console.error('Login error:', error);
    res.status(401).json({ error: error.message });
  }
});

// ==================== GOOGLE OAUTH ROUTES ====================

// Get Google Auth URL
router.get('/google/auth-url', (req: Request, res: Response) => {
  try {
    const authUrl = googleOAuthService.getGoogleAuthUrl();
    res.json({ authUrl });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Google OAuth Callback - GET (Browser redirect from Google)
router.get('/google/callback', async (req: Request, res: Response) => {
  try {
    const { code, error } = req.query;

    if (error) {
      return res.status(400).json({ error: `Google auth failed: ${error}` });
    }

    if (!code || typeof code !== 'string') {
      return res.status(400).json({ error: 'No authorization code received' });
    }

    const result = await googleOAuthService.handleGoogleAuth(code);

    res.send(`
      <!DOCTYPE html>
      <html>
        <head>
          <title>Authentication Successful</title>
          <script>
            window.authResult = ${JSON.stringify(result)};
            window.opener.postMessage({
              type: 'AUTH_SUCCESS',
              data: ${JSON.stringify(result)}
            }, '*');
            window.close();
          </script>
        </head>
        <body>
          <h1>Authentication Successful!</h1>
          <p>You can close this window. Your app will receive the login data.</p>
          <pre>${JSON.stringify(result, null, 2)}</pre>
        </body>
      </html>
    `);
  } catch (error: any) {
    res.send(`
      <!DOCTYPE html>
      <html>
        <head>
          <title>Authentication Failed</title>
        </head>
        <body>
          <h1>Authentication Failed</h1>
          <p>Error: ${error.message}</p>
        </body>
      </html>
    `);
  }
});

// Google OAuth Callback - POST (React Native sends code here)
router.post('/google/callback', async (req: Request, res: Response) => {
  try {
    const { code } = req.body;

    if (!code) {
      return res.status(400).json({ error: 'Authorization code is required' });
    }

    const result = await googleOAuthService.handleGoogleAuth(code);

    res.json({
      message: 'Google sign-in successful',
      ...result,
    });
  } catch (error: any) {
    res.status(400).json({ error: error.message });
  }
});

// ==================== PROTECTED ROUTES ====================

// GET CURRENT USER
router.get('/me', authMiddleware, async (req: AuthRequest, res: Response) => {
  try {
    const user = await authService.getUserById(req.userId!);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      imageUrl: user.imageUrl,
      authProvider: user.authProvider,
      isEmailVerified: user.isEmailVerified,
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

// UPDATE PROFILE
router.put('/me', authMiddleware, async (req: AuthRequest, res: Response) => {
  try {
    const { firstName, lastName, imageUrl } = req.body;

    // Validate at least one field is provided
    if (!firstName && !lastName && !imageUrl) {
      return res.status(400).json({
        error: 'At least one field (firstName, lastName, or imageUrl) is required'
      });
    }

    const updatedUser = await authService.updateUser(req.userId!, {
      firstName,
      lastName,
      imageUrl,
    });

    res.json({
      message: 'Profile updated successfully',
      user: {
        id: updatedUser.id,
        email: updatedUser.email,
        firstName: updatedUser.firstName,
        lastName: updatedUser.lastName,
        imageUrl: updatedUser.imageUrl,
      },
    });
  } catch (error: any) {
    console.error('Update profile error:', error);
    res.status(500).json({ error: error.message });
  }
});

export default router;
