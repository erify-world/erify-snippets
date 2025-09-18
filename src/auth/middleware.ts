import { SessionData } from '../types';
import { ErifyJWT } from './jwt';

/**
 * ERIFY™ Authentication Middleware
 * Express.js and general purpose authentication utilities
 */

import { AuthError } from '../types';

export interface AuthMiddlewareConfig {
  jwtManager: ErifyJWT;
  optional?: boolean;
  roles?: string[];
}

/**
 * Express.js authentication middleware
 */
export const createAuthMiddleware = (config: AuthMiddlewareConfig) => {
  return (req: any, res: any, next: any) => {
    try {
      const authHeader = req.headers.authorization;
      
      if (!authHeader && config.optional) {
        return next();
      }

      const token = config.jwtManager.extractTokenFromHeader(authHeader);
      const user = config.jwtManager.verifyToken(token);

      // Role-based access control
      if (config.roles && config.roles.length > 0) {
        const userRoles = user.roles || [];
        const hasRequiredRole = config.roles.some(role => userRoles.includes(role));
        
        if (!hasRequiredRole) {
          return res.status(403).json({ 
            error: 'Insufficient permissions',
            required: config.roles,
            current: userRoles
          });
        }
      }

      req.user = user;
      next();
    } catch (error) {
      if (config.optional) {
        return next();
      }
      
      throw new AuthError((error as Error).message || 'Authentication failed');
    }
  };
};

/**
 * Rate limiting middleware
 */
export const createRateLimitMiddleware = (
  maxRequests: number,
  windowMs: number
) => {
  const requests = new Map<string, { count: number; resetTime: number }>();

  return (req: any, res: any, next: any) => {
    const clientId = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    
    const clientData = requests.get(clientId) || { count: 0, resetTime: now + windowMs };
    
    if (now > clientData.resetTime) {
      clientData.count = 0;
      clientData.resetTime = now + windowMs;
    }
    
    if (clientData.count >= maxRequests) {
      return res.status(429).json({
        error: 'Too many requests',
        resetTime: new Date(clientData.resetTime).toISOString()
      });
    }
    
    clientData.count++;
    requests.set(clientId, clientData);
    
    next();
  };
};

/**
 * CORS middleware for OAuth
 */
export const createCORSMiddleware = (allowedOrigins: string[]) => {
  return (req: any, res: any, next: any) => {
    const origin = req.headers.origin;
    
    if (allowedOrigins.includes(origin)) {
      res.header('Access-Control-Allow-Origin', origin);
    }
    
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    res.header('Access-Control-Allow-Credentials', 'true');
    
    if (req.method === 'OPTIONS') {
      res.sendStatus(200);
    } else {
      next();
    }
  };
};

/**
 * Security headers middleware
 */
export const securityHeaders = (req: any, res: any, next: any) => {
  res.header('X-Content-Type-Options', 'nosniff');
  res.header('X-Frame-Options', 'DENY');
  res.header('X-XSS-Protection', '1; mode=block');
  res.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.header('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
};

/**
 * User context utilities
 */
export class UserContext {
  constructor(private user: SessionData) {}

  hasRole(role: string): boolean {
    return this.user.roles?.includes(role) || false;
  }

  hasAnyRole(roles: string[]): boolean {
    return roles.some(role => this.hasRole(role));
  }

  hasAllRoles(roles: string[]): boolean {
    return roles.every(role => this.hasRole(role));
  }

  isAdmin(): boolean {
    return this.hasRole('admin') || this.hasRole('administrator');
  }

  getUserId(): string {
    return this.user.userId;
  }

  getEmail(): string | undefined {
    return this.user.email;
  }

  getData(): SessionData {
    return { ...this.user };
  }
}

/**
 * Example usage snippets
 */
export const middlewareExamples = {
  // Basic auth setup
  basicSetup: `
const authMiddleware = createAuthMiddleware({ jwtManager });
const optionalAuth = createAuthMiddleware({ jwtManager, optional: true });
const adminOnly = createAuthMiddleware({ jwtManager, roles: ['admin'] });

app.use('/api/protected', authMiddleware);
app.use('/api/admin', adminOnly);
  `,

  // Rate limiting
  rateLimiting: `
const rateLimit = createRateLimitMiddleware(100, 15 * 60 * 1000); // 100 requests per 15 minutes
app.use('/api/auth', rateLimit);
  `,

  // Complete security setup
  securitySetup: `
const cors = createCORSMiddleware(['https://yourapp.com', 'https://app.yourdomain.com']);

app.use(cors);
app.use(securityHeaders);
app.use(rateLimit);
  `,
};