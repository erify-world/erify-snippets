import * as jwt from 'jsonwebtoken';
import { SessionData, AuthError } from '../types';

/**
 * ERIFY™ JWT Token Management
 * Secure token generation, validation, and refresh
 */

export interface JWTConfig {
  secret: string;
  expiresIn: string;
  refreshExpiresIn?: string;
  issuer?: string;
  audience?: string;
}

export class ErifyJWT {
  private config: JWTConfig;

  constructor(config: JWTConfig) {
    this.config = config;
  }

  /**
   * Generate JWT access token
   */
  generateAccessToken(payload: SessionData): string {
    const options: jwt.SignOptions = {
      expiresIn: this.config.expiresIn as any, // Using any to bypass type issue
    };
    
    if (this.config.issuer) options.issuer = this.config.issuer;
    if (this.config.audience) options.audience = this.config.audience;
    
    return jwt.sign(payload, this.config.secret, options);
  }

  /**
   * Generate JWT refresh token
   */
  generateRefreshToken(payload: Pick<SessionData, 'userId'>): string {
    const options: jwt.SignOptions = {
      expiresIn: (this.config.refreshExpiresIn || '7d') as any, // Using any to bypass type issue
    };
    
    if (this.config.issuer) options.issuer = this.config.issuer;
    if (this.config.audience) options.audience = this.config.audience;
    
    return jwt.sign(
      { userId: payload.userId, type: 'refresh' },
      this.config.secret,
      options
    );
  }

  /**
   * Generate both access and refresh tokens
   */
  generateTokenPair(payload: SessionData): {
    accessToken: string;
    refreshToken: string;
  } {
    return {
      accessToken: this.generateAccessToken(payload),
      refreshToken: this.generateRefreshToken({ userId: payload.userId }),
    };
  }

  /**
   * Verify and decode JWT token
   */
  verifyToken(token: string): SessionData {
    try {
      const options: jwt.VerifyOptions = {};
      
      if (this.config.issuer) options.issuer = this.config.issuer;
      if (this.config.audience) options.audience = this.config.audience;
      
      const decoded = jwt.verify(token, this.config.secret, options);
      
      if (typeof decoded === 'string') {
        throw new AuthError('Invalid token format');
      }

      return decoded as SessionData;
    } catch (error) {
      if (error instanceof jwt.JsonWebTokenError) {
        throw new AuthError('Invalid token');
      }
      if (error instanceof jwt.TokenExpiredError) {
        throw new AuthError('Token expired');
      }
      throw new AuthError('Token verification failed');
    }
  }

  /**
   * Refresh access token using refresh token
   */
  refreshAccessToken(refreshToken: string, newPayload: SessionData): string {
    const decoded = this.verifyToken(refreshToken);
    
    if (decoded.type !== 'refresh') {
      throw new AuthError('Invalid refresh token');
    }

    if (decoded.userId !== newPayload.userId) {
      throw new AuthError('User ID mismatch');
    }

    return this.generateAccessToken(newPayload);
  }

  /**
   * Extract token from Authorization header
   */
  extractTokenFromHeader(authHeader?: string): string {
    if (!authHeader) {
      throw new AuthError('No authorization header provided');
    }

    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      throw new AuthError('Invalid authorization header format');
    }

    return parts[1];
  }
}

/**
 * Utility functions for JWT management
 */

export const createJWTConfig = (
  secret: string,
  options: Partial<Omit<JWTConfig, 'secret'>> = {}
): JWTConfig => ({
  secret,
  expiresIn: options.expiresIn || '15m',
  refreshExpiresIn: options.refreshExpiresIn || '7d',
  issuer: options.issuer || 'erify-technologies',
  audience: options.audience || 'erify-app',
});

/**
 * Generate secure random secret for JWT
 */
export const generateJWTSecret = (): string => {
  return require('crypto').randomBytes(64).toString('hex');
};

/**
 * Example usage snippets
 */
export const jwtExamples = {
  // Basic setup
  basicSetup: `
const jwtConfig = createJWTConfig(process.env.JWT_SECRET!);
const jwtManager = new ErifyJWT(jwtConfig);

// Generate tokens
const tokens = jwtManager.generateTokenPair({
  userId: 'user123',
  email: 'user@example.com',
  roles: ['user'],
});
  `,

  // Express middleware
  expressMiddleware: `
const authenticateToken = (req, res, next) => {
  try {
    const token = jwtManager.extractTokenFromHeader(req.headers.authorization);
    const user = jwtManager.verifyToken(token);
    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ error: error.message });
  }
};

// Protected route
app.get('/profile', authenticateToken, (req, res) => {
  res.json(req.user);
});
  `,

  // Token refresh endpoint
  refreshEndpoint: `
app.post('/auth/refresh', (req, res) => {
  try {
    const { refreshToken } = req.body;
    const userData = getUserData(userId); // Your user lookup logic
    
    const newAccessToken = jwtManager.refreshAccessToken(refreshToken, userData);
    
    res.json({ accessToken: newAccessToken });
  } catch (error) {
    res.status(401).json({ error: error.message });
  }
});
  `,
};