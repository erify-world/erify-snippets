/**
 * ERIFY™ Session Validation Implementation
 * 
 * Secure session validation with integrity checks and security monitoring
 * Designed for Cloudflare Workers, Node.js, and fintech ecosystems
 * 
 * @author Yahaya Ibrahim | ERIFY™ Founder
 * @license MIT
 */

import type { SessionData, EncryptedSession, SessionConfig } from './create.js';

export interface ValidationResult {
  readonly isValid: boolean;
  readonly sessionData?: SessionData;
  readonly errors: readonly string[];
  readonly warnings: readonly string[];
  readonly securityFlags: readonly string[];
}

export interface SecurityCheck {
  readonly ipMismatch: boolean;
  readonly userAgentMismatch: boolean;
  readonly timeAnomalies: boolean;
  readonly suspiciousActivity: boolean;
}

/**
 * Verifies HMAC signature for session data integrity
 */
export async function verifySessionSignature(
  data: string,
  signature: string,
  secret: string
): Promise<boolean> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  );

  const expectedSignature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  const expectedHex = Array.from(new Uint8Array(expectedSignature), byte => 
    byte.toString(16).padStart(2, '0')
  ).join('');

  // Constant-time comparison to prevent timing attacks
  if (signature.length !== expectedHex.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < signature.length; i++) {
    result |= signature.charCodeAt(i) ^ expectedHex.charCodeAt(i);
  }

  return result === 0;
}

/**
 * Decrypts session data using AES-GCM
 */
export async function decryptSessionData(
  encryptedSession: EncryptedSession,
  secret: string
): Promise<SessionData> {
  try {
    const encoder = new TextEncoder();
    const combined = new Uint8Array(
      atob(encryptedSession.encryptedData)
        .split('')
        .map(char => char.charCodeAt(0))
    );

    const salt = combined.slice(0, 16);
    const iv = combined.slice(16, 28);
    const encrypted = combined.slice(28);

    // Derive decryption key
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

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
      ['decrypt']
    );

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      encrypted
    );

    const decoder = new TextDecoder();
    const sessionDataStr = decoder.decode(decrypted);
    const sessionData = JSON.parse(sessionDataStr) as SessionData;

    // Convert date strings back to Date objects
    return {
      ...sessionData,
      createdAt: new Date(sessionData.createdAt),
      expiresAt: new Date(sessionData.expiresAt)
    };
  } catch (error) {
    throw new Error(`ERIFY™ Session: Decryption failed - ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}

/**
 * Performs comprehensive security checks on session
 */
export function performSecurityChecks(
  sessionData: SessionData,
  currentRequest: {
    ipAddress: string;
    userAgent: string;
    timestamp: Date;
  }
): SecurityCheck {
  const ipMismatch = sessionData.ipAddress !== undefined && 
                    sessionData.ipAddress !== currentRequest.ipAddress;

  const userAgentMismatch = sessionData.userAgent !== undefined && 
                           sessionData.userAgent !== currentRequest.userAgent;

  // Check for time anomalies (session used before creation or after expiration)
  const timeAnomalies = currentRequest.timestamp < sessionData.createdAt ||
                       currentRequest.timestamp > sessionData.expiresAt;

  // Simple heuristic for suspicious activity
  const suspiciousActivity = (
    ipMismatch && userAgentMismatch
  ) || (
    currentRequest.timestamp.getTime() - sessionData.createdAt.getTime() < 1000 // Too fast
  );

  return {
    ipMismatch,
    userAgentMismatch,
    timeAnomalies,
    suspiciousActivity
  };
}

/**
 * Validates session structure and required fields
 */
export function validateSessionStructure(sessionData: unknown): sessionData is SessionData {
  if (!sessionData || typeof sessionData !== 'object') {
    return false;
  }

  const data = sessionData as Record<string, unknown>;
  
  return !!(
    typeof data.sessionId === 'string' &&
    typeof data.userId === 'string' &&
    data.createdAt &&
    data.expiresAt &&
    new Date(data.createdAt as string).getTime() > 0 &&
    new Date(data.expiresAt as string).getTime() > 0
  );
}

/**
 * Extracts session ID from various cookie formats
 */
export function extractSessionId(cookies: string, sessionName: string = 'erify_session'): string | null {
  const cookieRegex = new RegExp(`${sessionName}=([^;]+)`);
  const match = cookies.match(cookieRegex);
  return match ? decodeURIComponent(match[1]!) : null;
}

/**
 * Complete session validation for ERIFY™ ecosystems
 * 
 * @example Cloudflare Workers usage:
 * ```typescript
 * export default {
 *   async fetch(request: Request, env: Env): Promise<Response> {
 *     const validator = new ERIFYSessionValidator({
 *       secret: env.SESSION_SECRET,
 *       expirationMs: 24 * 60 * 60 * 1000,
 *       secureCookies: true,
 *       sameSite: 'strict'
 *     });
 *     
 *     const sessionId = validator.extractSessionFromRequest(request);
 *     if (!sessionId) {
 *       return new Response('No session', { status: 401 });
 *     }
 *     
 *     const result = await validator.validateSession(sessionId, request);
 *     if (!result.isValid) {
 *       return new Response(`Invalid session: ${result.errors.join(', ')}`, { status: 401 });
 *     }
 *     
 *     return new Response(`Welcome ${result.sessionData?.email}!`);
 *   }
 * };
 * ```
 */
export class ERIFYSessionValidator {
  constructor(private readonly config: SessionConfig) {}

  async validateSession(
    encryptedSession: EncryptedSession,
    currentRequest?: {
      ipAddress: string;
      userAgent: string;
      timestamp?: Date;
    }
  ): Promise<ValidationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];
    const securityFlags: string[] = [];
    const timestamp = currentRequest?.timestamp || new Date();

    try {
      // Verify signature first
      const signatureValid = await verifySessionSignature(
        encryptedSession.encryptedData,
        encryptedSession.signature,
        this.config.secret
      );

      if (!signatureValid) {
        errors.push('Invalid session signature');
        return { isValid: false, errors, warnings, securityFlags };
      }

      // Check expiration at envelope level
      if (timestamp > encryptedSession.expiresAt) {
        errors.push('Session expired');
        return { isValid: false, errors, warnings, securityFlags };
      }

      // Decrypt and validate session data
      const sessionData = await decryptSessionData(encryptedSession, this.config.secret);

      if (!validateSessionStructure(sessionData)) {
        errors.push('Invalid session structure');
        return { isValid: false, errors, warnings, securityFlags };
      }

      // Additional expiration check from decrypted data
      if (timestamp > sessionData.expiresAt) {
        errors.push('Session data expired');
        return { isValid: false, errors, warnings, securityFlags };
      }

      // Perform security checks if request context provided
      if (currentRequest) {
        const securityCheck = performSecurityChecks(sessionData, {
          ipAddress: currentRequest.ipAddress,
          userAgent: currentRequest.userAgent,
          timestamp
        });

        if (securityCheck.timeAnomalies) {
          errors.push('Time anomaly detected');
        }

        if (securityCheck.suspiciousActivity) {
          securityFlags.push('suspicious_activity');
          warnings.push('Suspicious activity detected');
        }

        if (securityCheck.ipMismatch) {
          securityFlags.push('ip_mismatch');
          warnings.push('IP address mismatch');
        }

        if (securityCheck.userAgentMismatch) {
          securityFlags.push('user_agent_mismatch');
          warnings.push('User agent mismatch');
        }
      }

      // Check if session is about to expire (within 10% of total lifetime)
      const lifetime = sessionData.expiresAt.getTime() - sessionData.createdAt.getTime();
      const timeRemaining = sessionData.expiresAt.getTime() - timestamp.getTime();
      if (timeRemaining < lifetime * 0.1) {
        warnings.push('Session expiring soon');
      }

      return {
        isValid: errors.length === 0,
        sessionData,
        errors,
        warnings,
        securityFlags
      };

    } catch (error) {
      errors.push(`Validation error: ${error instanceof Error ? error.message : 'unknown'}`);
      return { isValid: false, errors, warnings, securityFlags };
    }
  }

  extractSessionFromRequest(request: Request, sessionName: string = 'erify_session'): string | null {
    const cookies = request.headers.get('Cookie') || '';
    return extractSessionId(cookies, sessionName);
  }

  async validateSessionFromRequest(
    request: Request,
    sessionName: string = 'erify_session'
  ): Promise<ValidationResult> {
    const sessionId = this.extractSessionFromRequest(request, sessionName);
    
    if (!sessionId) {
      return {
        isValid: false,
        errors: ['No session cookie found'],
        warnings: [],
        securityFlags: []
      };
    }

    // Parse session ID to get encrypted session data
    try {
      const [, , encryptedData, signature] = sessionId.split('_');
      if (!encryptedData || !signature) {
        return {
          isValid: false,
          errors: ['Invalid session ID format'],
          warnings: [],
          securityFlags: []
        };
      }

      const encryptedSession: EncryptedSession = {
        sessionId,
        encryptedData,
        signature,
        expiresAt: new Date(Date.now() + this.config.expirationMs) // Default expiry
      };

      const ipAddress = request.headers.get('CF-Connecting-IP') || 
                       request.headers.get('X-Forwarded-For') || 
                       request.headers.get('X-Real-IP') || 
                       'unknown';
      
      const userAgent = request.headers.get('User-Agent') || 'unknown';

      return this.validateSession(encryptedSession, {
        ipAddress,
        userAgent,
        timestamp: new Date()
      });

    } catch (error) {
      return {
        isValid: false,
        errors: [`Session parsing error: ${error instanceof Error ? error.message : 'unknown'}`],
        warnings: [],
        securityFlags: []
      };
    }
  }

  /**
   * Validates session with additional permission checks
   */
  async validateSessionWithPermissions(
    encryptedSession: EncryptedSession,
    requiredPermissions: readonly string[],
    currentRequest?: {
      ipAddress: string;
      userAgent: string;
      timestamp?: Date;
    }
  ): Promise<ValidationResult> {
    const result = await this.validateSession(encryptedSession, currentRequest);
    
    if (!result.isValid || !result.sessionData) {
      return result;
    }

    const userPermissions = result.sessionData.permissions || [];
    const missingPermissions = requiredPermissions.filter(
      permission => !userPermissions.includes(permission)
    );

    if (missingPermissions.length > 0) {
      return {
        ...result,
        isValid: false,
        errors: [...result.errors, `Missing permissions: ${missingPermissions.join(', ')}`]
      };
    }

    return result;
  }

  /**
   * Quick session validity check without full decryption
   */
  async quickValidityCheck(sessionId: string): Promise<boolean> {
    try {
      // Basic format check
      const parts = sessionId.split('_');
      if (parts.length < 4 || parts[0] !== 'erify') {
        return false;
      }

      // Check timestamp part for basic expiry
      const timestamp = parseInt(parts[1]!, 36);
      const sessionAge = Date.now() - timestamp;
      
      return sessionAge < this.config.expirationMs;
    } catch {
      return false;
    }
  }
}