import { SessionConfig, SessionData, AuthError } from '../types';
import { randomBytes, createHash } from 'crypto';

/**
 * ERIFY™ Session Management
 * Secure session handling with multiple storage backends
 */

export interface SessionStore {
  get(sessionId: string): Promise<SessionData | null>;
  set(sessionId: string, data: SessionData, ttl: number): Promise<void>;
  delete(sessionId: string): Promise<void>;
  cleanup(): Promise<void>;
}

/**
 * In-memory session store (for development)
 */
export class MemorySessionStore implements SessionStore {
  private sessions = new Map<string, { data: SessionData; expires: number }>();

  async get(sessionId: string): Promise<SessionData | null> {
    const session = this.sessions.get(sessionId);
    if (!session || session.expires < Date.now()) {
      this.sessions.delete(sessionId);
      return null;
    }
    return session.data;
  }

  async set(sessionId: string, data: SessionData, ttl: number): Promise<void> {
    this.sessions.set(sessionId, {
      data,
      expires: Date.now() + ttl * 1000,
    });
  }

  async delete(sessionId: string): Promise<void> {
    this.sessions.delete(sessionId);
  }

  async cleanup(): Promise<void> {
    const now = Date.now();
    for (const [id, session] of this.sessions.entries()) {
      if (session.expires < now) {
        this.sessions.delete(id);
      }
    }
  }
}

/**
 * Redis session store
 */
export class RedisSessionStore implements SessionStore {
  constructor(private redis: any) {}

  async get(sessionId: string): Promise<SessionData | null> {
    const data = await this.redis.get(`session:${sessionId}`);
    return data ? JSON.parse(data) : null;
  }

  async set(sessionId: string, data: SessionData, ttl: number): Promise<void> {
    await this.redis.setex(`session:${sessionId}`, ttl, JSON.stringify(data));
  }

  async delete(sessionId: string): Promise<void> {
    await this.redis.del(`session:${sessionId}`);
  }

  async cleanup(): Promise<void> {
    // Redis handles TTL automatically
  }
}

/**
 * Database session store
 */
export class DatabaseSessionStore implements SessionStore {
  constructor(private db: any, private tableName = 'sessions') {}

  async get(sessionId: string): Promise<SessionData | null> {
    const result = await this.db.query(
      `SELECT data FROM ${this.tableName} WHERE id = ? AND expires_at > NOW()`,
      [sessionId]
    );
    return result.length > 0 ? JSON.parse(result[0].data) : null;
  }

  async set(sessionId: string, data: SessionData, ttl: number): Promise<void> {
    const expiresAt = new Date(Date.now() + ttl * 1000);
    await this.db.query(
      `INSERT INTO ${this.tableName} (id, data, expires_at) VALUES (?, ?, ?) 
       ON DUPLICATE KEY UPDATE data = ?, expires_at = ?`,
      [sessionId, JSON.stringify(data), expiresAt, JSON.stringify(data), expiresAt]
    );
  }

  async delete(sessionId: string): Promise<void> {
    await this.db.query(`DELETE FROM ${this.tableName} WHERE id = ?`, [sessionId]);
  }

  async cleanup(): Promise<void> {
    await this.db.query(`DELETE FROM ${this.tableName} WHERE expires_at < NOW()`);
  }
}

/**
 * Main session manager
 */
export class ErifySessionManager {
  private config: SessionConfig;
  private store: SessionStore;

  constructor(config: SessionConfig, store: SessionStore) {
    this.config = config;
    this.store = store;
  }

  /**
   * Generate secure session ID
   */
  generateSessionId(): string {
    return randomBytes(32).toString('hex');
  }

  /**
   * Create new session
   */
  async createSession(data: SessionData): Promise<string> {
    const sessionId = this.generateSessionId();
    await this.store.set(sessionId, data, this.config.expiresIn);
    return sessionId;
  }

  /**
   * Get session data
   */
  async getSession(sessionId: string): Promise<SessionData | null> {
    if (!sessionId) return null;
    return await this.store.get(sessionId);
  }

  /**
   * Update session data
   */
  async updateSession(sessionId: string, data: Partial<SessionData>): Promise<void> {
    const existingData = await this.store.get(sessionId);
    if (!existingData) {
      throw new AuthError('Session not found');
    }

    const updatedData = { ...existingData, ...data };
    await this.store.set(sessionId, updatedData, this.config.expiresIn);
  }

  /**
   * Destroy session
   */
  async destroySession(sessionId: string): Promise<void> {
    await this.store.delete(sessionId);
  }

  /**
   * Regenerate session ID (for security)
   */
  async regenerateSession(oldSessionId: string): Promise<string> {
    const data = await this.store.get(oldSessionId);
    if (!data) {
      throw new AuthError('Session not found');
    }

    await this.store.delete(oldSessionId);
    return await this.createSession(data);
  }

  /**
   * Generate secure cookie options
   */
  getCookieOptions() {
    return {
      httpOnly: this.config.httpOnly,
      secure: this.config.secure,
      sameSite: this.config.sameSite,
      maxAge: this.config.expiresIn * 1000,
    };
  }

  /**
   * Sign cookie value
   */
  signCookie(value: string): string {
    const signature = createHash('sha256')
      .update(value + this.config.secret)
      .digest('hex');
    return `${value}.${signature}`;
  }

  /**
   * Verify signed cookie
   */
  verifyCookie(signedValue: string): string | null {
    const parts = signedValue.split('.');
    if (parts.length !== 2) return null;

    const [value, signature] = parts;
    const expectedSignature = createHash('sha256')
      .update(value + this.config.secret)
      .digest('hex');

    if (signature !== expectedSignature) return null;
    return value;
  }
}

/**
 * Express.js session middleware
 */
export const createSessionMiddleware = (sessionManager: ErifySessionManager) => {
  return async (req: any, res: any, next: any) => {
    const cookieName = 'erify_session';
    const signedSessionId = req.cookies?.[cookieName];

    let sessionId: string | null = null;
    if (signedSessionId) {
      sessionId = sessionManager.verifyCookie(signedSessionId);
    }

    // Load session data
    req.session = sessionId ? await sessionManager.getSession(sessionId) : null;
    req.sessionId = sessionId;

    // Helper methods
    req.createSession = async (data: SessionData) => {
      const newSessionId = await sessionManager.createSession(data);
      const signedValue = sessionManager.signCookie(newSessionId);
      res.cookie(cookieName, signedValue, sessionManager.getCookieOptions());
      req.session = data;
      req.sessionId = newSessionId;
    };

    req.updateSession = async (data: Partial<SessionData>) => {
      if (!req.sessionId) {
        throw new AuthError('No active session');
      }
      await sessionManager.updateSession(req.sessionId, data);
      req.session = { ...req.session, ...data };
    };

    req.destroySession = async () => {
      if (req.sessionId) {
        await sessionManager.destroySession(req.sessionId);
        res.clearCookie(cookieName);
        req.session = null;
        req.sessionId = null;
      }
    };

    next();
  };
};

/**
 * Example usage snippets
 */
export const sessionExamples = {
  // Basic setup
  basicSetup: `
const sessionConfig: SessionConfig = {
  secret: process.env.SESSION_SECRET!,
  expiresIn: 3600, // 1 hour
  secure: process.env.NODE_ENV === 'production',
  httpOnly: true,
  sameSite: 'strict',
};

const store = new MemorySessionStore(); // or RedisSessionStore, DatabaseSessionStore
const sessionManager = new ErifySessionManager(sessionConfig, store);
const sessionMiddleware = createSessionMiddleware(sessionManager);

app.use(sessionMiddleware);
  `,

  // Login endpoint
  loginEndpoint: `
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  
  // Verify credentials
  const user = await authenticateUser(email, password);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  // Create session
  await req.createSession({
    userId: user.id,
    email: user.email,
    roles: user.roles,
  });
  
  res.json({ message: 'Logged in successfully' });
});
  `,

  // Logout endpoint
  logoutEndpoint: `
app.post('/logout', async (req, res) => {
  await req.destroySession();
  res.json({ message: 'Logged out successfully' });
});
  `,
};