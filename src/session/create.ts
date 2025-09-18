/**
 * ERIFY™ Session Creation Implementation
 * 
 * Secure session management with strong random IDs and encryption
 * Designed for Cloudflare Workers, Node.js, and fintech ecosystems
 * 
 * @author Yahaya Ibrahim | ERIFY™ Founder
 * @license MIT
 */

export interface SessionConfig {
  readonly secret: string;
  readonly expirationMs: number;
  readonly secureCookies: boolean;
  readonly sameSite: 'strict' | 'lax' | 'none';
  readonly domain?: string;
  readonly path?: string;
}

export interface SessionData {
  readonly sessionId: string;
  readonly userId: string;
  readonly email: string | undefined;
  readonly role: string | undefined;
  readonly permissions: readonly string[] | undefined;
  readonly metadata: Record<string, unknown> | undefined;
  readonly createdAt: Date;
  readonly expiresAt: Date;
  readonly ipAddress: string | undefined;
  readonly userAgent: string | undefined;
}

export interface EncryptedSession {
  readonly sessionId: string;
  readonly encryptedData: string;
  readonly signature: string;
  readonly expiresAt: Date;
}

/**
 * Generates a cryptographically secure session ID
 */
export function generateSecureSessionId(): string {
  const timestamp = Date.now().toString(36);
  const randomBytes = new Uint8Array(32);
  crypto.getRandomValues(randomBytes);
  
  const randomString = Array.from(randomBytes, byte => 
    byte.toString(36).padStart(2, '0')
  ).join('');
  
  // Additional entropy from performance.now() if available
  const extraEntropy = typeof performance !== 'undefined' ? 
    performance.now().toString(36).replace('.', '') : 
    Math.random().toString(36).substring(2);
  
  return `erify_${timestamp}_${randomString}_${extraEntropy}`;
}

/**
 * Creates HMAC signature for session data integrity
 */
export async function createSessionSignature(
  data: string,
  secret: string
): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  return Array.from(new Uint8Array(signature), byte => 
    byte.toString(16).padStart(2, '0')
  ).join('');
}

/**
 * Encrypts session data using AES-GCM
 */
export async function encryptSessionData(
  sessionData: SessionData,
  secret: string
): Promise<EncryptedSession> {
  const encoder = new TextEncoder();
  const data = encoder.encode(JSON.stringify(sessionData));
  
  // Derive encryption key from secret
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    data
  );

  // Combine salt, iv, and encrypted data
  const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
  combined.set(salt);
  combined.set(iv, salt.length);
  combined.set(new Uint8Array(encrypted), salt.length + iv.length);

  const encryptedData = btoa(String.fromCharCode(...combined));
  const signature = await createSessionSignature(encryptedData, secret);

  return {
    sessionId: sessionData.sessionId,
    encryptedData,
    signature,
    expiresAt: sessionData.expiresAt
  };
}

/**
 * Creates session cookie string with security flags
 */
export function createSessionCookie(
  name: string,
  value: string,
  config: SessionConfig
): string {
  const expires = new Date(Date.now() + config.expirationMs);
  let cookie = `${name}=${value}; Expires=${expires.toUTCString()}; HttpOnly`;

  if (config.secureCookies) {
    cookie += '; Secure';
  }

  cookie += `; SameSite=${config.sameSite}`;

  if (config.domain) {
    cookie += `; Domain=${config.domain}`;
  }

  if (config.path) {
    cookie += `; Path=${config.path}`;
  } else {
    cookie += '; Path=/';
  }

  return cookie;
}

/**
 * Validates session data structure and required fields
 */
export function validateSessionData(data: Partial<SessionData>): data is SessionData {
  return !!(
    data.sessionId &&
    data.userId &&
    data.createdAt &&
    data.expiresAt &&
    data.expiresAt > new Date()
  );
}

/**
 * Creates session with automatic expiration and security features
 * 
 * @example Cloudflare Workers usage:
 * ```typescript
 * export default {
 *   async fetch(request: Request, env: Env): Promise<Response> {
 *     const sessionManager = new ERIFYSessionCreator({
 *       secret: env.SESSION_SECRET,
 *       expirationMs: 24 * 60 * 60 * 1000, // 24 hours
 *       secureCookies: true,
 *       sameSite: 'strict'
 *     });
 *     
 *     const session = await sessionManager.createSession({
 *       userId: 'user123',
 *       email: 'user@erify.world',
 *       role: 'premium',
 *       permissions: ['read:profile', 'write:data']
 *     });
 *     
 *     const cookie = sessionManager.createCookie('erify_session', session.sessionId);
 *     
 *     return new Response('Session created', {
 *       headers: { 'Set-Cookie': cookie }
 *     });
 *   }
 * };
 * ```
 */
export class ERIFYSessionCreator {
  constructor(private readonly config: SessionConfig) {}

  async createSession(userData: {
    userId: string;
    email: string | undefined;
    role: string | undefined;
    permissions: readonly string[] | undefined;
    metadata: Record<string, unknown> | undefined;
    ipAddress: string | undefined;
    userAgent: string | undefined;
  }): Promise<EncryptedSession> {
    const sessionId = generateSecureSessionId();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + this.config.expirationMs);

    const sessionData: SessionData = {
      sessionId,
      userId: userData.userId,
      email: userData.email,
      role: userData.role,
      permissions: userData.permissions,
      metadata: userData.metadata,
      createdAt: now,
      expiresAt,
      ipAddress: userData.ipAddress,
      userAgent: userData.userAgent
    };

    if (!validateSessionData(sessionData)) {
      throw new Error('ERIFY™ Session: Invalid session data provided');
    }

    return encryptSessionData(sessionData, this.config.secret);
  }

  createCookie(name: string, sessionId: string): string {
    return createSessionCookie(name, sessionId, this.config);
  }

  createSecureCookie(name: string, sessionId: string): string {
    return createSessionCookie(name, sessionId, {
      ...this.config,
      secureCookies: true,
      sameSite: 'strict'
    });
  }

  /**
   * Creates session with IP and User-Agent tracking for security
   */
  async createTrackedSession(
    userData: {
      userId: string;
      email: string | undefined;
      role: string | undefined;
      permissions: readonly string[] | undefined;
      metadata: Record<string, unknown> | undefined;
    },
    request: Request
  ): Promise<EncryptedSession> {
    const ipAddress = request.headers.get('CF-Connecting-IP') || 
                     request.headers.get('X-Forwarded-For') || 
                     request.headers.get('X-Real-IP') || 
                     'unknown';
    
    const userAgent = request.headers.get('User-Agent') || 'unknown';

    return this.createSession({
      ...userData,
      ipAddress,
      userAgent
    });
  }

  /**
   * Batch create multiple sessions (useful for multi-device scenarios)
   */
  async createMultipleSessions(
    userData: {
      userId: string;
      email: string | undefined;
      role: string | undefined;
      permissions: readonly string[] | undefined;
      metadata: Record<string, unknown> | undefined;
    },
    count: number,
    deviceInfo: readonly string[] | undefined
  ): Promise<EncryptedSession[]> {
    if (count > 10) {
      throw new Error('ERIFY™ Session: Maximum 10 sessions per batch');
    }

    const sessions: EncryptedSession[] = [];
    
    for (let i = 0; i < count; i++) {
      const metadata = {
        ...userData.metadata,
        deviceIndex: i,
        deviceInfo: deviceInfo?.[i] || `device_${i}`
      };

      const session = await this.createSession({
        ...userData,
        metadata,
        ipAddress: undefined,
        userAgent: undefined
      });

      sessions.push(session);
    }

    return sessions;
  }

  /**
   * Create session with additional security context
   */
  async createSecurityAwareSession(
    userData: {
      userId: string;
      email: string | undefined;
      role: string | undefined;
      permissions: readonly string[] | undefined;
    },
    securityContext: {
      ipAddress: string;
      userAgent: string;
      fingerprint: string | undefined;
      riskScore: number | undefined;
      location: string | undefined;
    }
  ): Promise<EncryptedSession> {
    const metadata = {
      fingerprint: securityContext.fingerprint,
      riskScore: securityContext.riskScore,
      location: securityContext.location,
      securityLevel: securityContext.riskScore && securityContext.riskScore > 0.7 ? 'high' : 'normal'
    };

    return this.createSession({
      ...userData,
      metadata,
      ipAddress: securityContext.ipAddress,
      userAgent: securityContext.userAgent
    });
  }
}