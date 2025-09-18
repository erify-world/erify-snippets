/**
 * ERIFY™ Express.js Complete Authentication Example
 * Demonstrates OAuth, JWT, sessions, and security middleware
 */

import express from 'express';
import cookieParser from 'cookie-parser';
import { 
  ErifyOAuth, 
  createOAuthConfig,
  ErifyJWT,
  createJWTConfig,
  createAuthMiddleware,
  createRateLimitMiddleware,
  securityHeaders,
  ErifyValidator 
} from '../index';

const app = express();

// Middleware setup
app.use(express.json());
app.use(cookieParser());
app.use(securityHeaders);

// Rate limiting
const rateLimit = createRateLimitMiddleware(100, 15 * 60 * 1000); // 100 requests per 15 minutes
app.use('/api', rateLimit);

// OAuth configuration
const oauthConfig = createOAuthConfig({
  google: {
    clientId: process.env.GOOGLE_CLIENT_ID!,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
    redirectUri: process.env.GOOGLE_REDIRECT_URI!,
  },
  github: {
    clientId: process.env.GITHUB_CLIENT_ID!,
    clientSecret: process.env.GITHUB_CLIENT_SECRET!,
    redirectUri: process.env.GITHUB_REDIRECT_URI!,
  },
});

const oauth = new ErifyOAuth(oauthConfig);

// JWT configuration
const jwtConfig = createJWTConfig(process.env.JWT_SECRET!);
const jwtManager = new ErifyJWT(jwtConfig);

// Authentication middleware
const requireAuth = createAuthMiddleware({ jwtManager });
const optionalAuth = createAuthMiddleware({ jwtManager, optional: true });
const requireAdmin = createAuthMiddleware({ jwtManager, roles: ['admin'] });

// Validation middleware
const validateRegistration = ErifyValidator.createValidationMiddleware(
  ErifyValidator.userRegistrationSchema
);

// Routes

// OAuth initiation
app.get('/auth/:provider', (req, res) => {
  try {
    const { provider } = req.params;
    const state = crypto.randomUUID();
    
    // Store state in session or database for verification
    res.cookie('oauth_state', state, { 
      httpOnly: true, 
      secure: process.env.NODE_ENV === 'production',
      maxAge: 10 * 60 * 1000 // 10 minutes
    });
    
    const authUrl = oauth.getAuthUrl(provider, state);
    res.redirect(authUrl);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// OAuth callback
app.get('/auth/:provider/callback', async (req, res) => {
  try {
    const { provider } = req.params;
    const { code, state } = req.query as { code: string; state: string };
    const storedState = req.cookies.oauth_state;
    
    // Verify state parameter
    if (!storedState || state !== storedState) {
      return res.status(400).json({ error: 'Invalid state parameter' });
    }
    
    // Clear state cookie
    res.clearCookie('oauth_state');
    
    // Exchange code for token
    const tokens = await oauth.exchangeCodeForToken(provider, code);
    const userInfo = await oauth.getUserInfo(provider, tokens.accessToken);
    
    // Create or find user in database
    const user = await findOrCreateUser(userInfo, provider);
    
    // Generate JWT tokens
    const jwtTokens = jwtManager.generateTokenPair({
      userId: user.id,
      email: user.email,
      roles: user.roles,
    });
    
    // Set JWT as httpOnly cookie
    res.cookie('auth_token', jwtTokens.accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000, // 15 minutes
    });
    
    res.cookie('refresh_token', jwtTokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });
    
    res.redirect('/dashboard');
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Traditional registration
app.post('/auth/register', validateRegistration, async (req, res) => {
  try {
    const userData = req.validatedData;
    
    // Check if user already exists
    const existingUser = await findUserByEmail(userData.email);
    if (existingUser) {
      return res.status(409).json({ error: 'User already exists' });
    }
    
    // Hash password and create user
    const hashedPassword = await hashPassword(userData.password);
    const user = await createUser({
      ...userData,
      password: hashedPassword,
    });
    
    // Generate tokens
    const tokens = jwtManager.generateTokenPair({
      userId: user.id,
      email: user.email,
      roles: ['user'],
    });
    
    res.json({
      message: 'Registration successful',
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Validate credentials
    const user = await validateUserCredentials(email, password);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Generate tokens
    const tokens = jwtManager.generateTokenPair({
      userId: user.id,
      email: user.email,
      roles: user.roles,
    });
    
    res.json({
      message: 'Login successful',
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Token refresh
app.post('/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return res.status(401).json({ error: 'Refresh token required' });
    }
    
    // Get user data for new token
    const tokenData = jwtManager.verifyToken(refreshToken);
    const user = await findUserById(tokenData.userId);
    
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }
    
    // Generate new access token
    const newAccessToken = jwtManager.refreshAccessToken(refreshToken, {
      userId: user.id,
      email: user.email,
      roles: user.roles,
    });
    
    res.json({
      accessToken: newAccessToken,
    });
  } catch (error) {
    res.status(401).json({ error: error.message });
  }
});

// Protected routes
app.get('/api/profile', requireAuth, (req, res) => {
  res.json({
    user: req.user,
    message: 'This is a protected route',
  });
});

app.get('/api/admin', requireAdmin, (req, res) => {
  res.json({
    message: 'This is an admin-only route',
    user: req.user,
  });
});

// Public route with optional auth
app.get('/api/public', optionalAuth, (req, res) => {
  res.json({
    message: 'This is a public route',
    user: req.user || null,
    authenticated: !!req.user,
  });
});

// Logout
app.post('/auth/logout', requireAuth, (req, res) => {
  // Clear cookies
  res.clearCookie('auth_token');
  res.clearCookie('refresh_token');
  
  res.json({ message: 'Logged out successfully' });
});

// Helper functions (implement based on your database)
async function findOrCreateUser(userInfo: any, provider: string) {
  // Implement user lookup/creation logic
  return {
    id: 'user123',
    email: userInfo.email,
    name: userInfo.name,
    roles: ['user'],
  };
}

async function findUserByEmail(email: string) {
  // Implement user lookup by email
  return null;
}

async function createUser(userData: any) {
  // Implement user creation
  return {
    id: 'user123',
    email: userData.email,
    roles: ['user'],
  };
}

async function hashPassword(password: string): Promise<string> {
  // Implement password hashing
  return 'hashed_password';
}

async function validateUserCredentials(email: string, password: string) {
  // Implement credential validation
  return null;
}

async function findUserById(id: string) {
  // Implement user lookup by ID
  return null;
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`ERIFY™ Authentication server running on port ${PORT}`);
});

export default app;