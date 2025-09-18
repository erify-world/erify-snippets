/**
 * ERIFY™ Session Creation
 * Production-ready session management for Cloudflare Workers and Node.js
 * Enterprise-grade security with cryptographically strong random IDs
 */

interface SessionData {
  /** User ID or identifier */
  userId: string;
  /** Session metadata */
  metadata?: Record<string, any>;
  /** IP address for security tracking */
  ipAddress?: string;
  /** User agent for security tracking */
  userAgent?: string;
  /** Custom session duration in seconds */
  duration?: number;
  /** Additional security context */
  securityContext?: {
    /** Multi-factor authentication status */
    mfaVerified?: boolean;
    /** Risk score (0-100) */
    riskScore?: number;
    /** Device fingerprint */
    deviceFingerprint?: string;
  };
}

interface SessionConfig {
  /** Default session duration in seconds (default: 24 hours) */
  defaultDuration?: number;
  /** Maximum session duration in seconds (default: 7 days) */
  maxDuration?: number;
  /** Minimum session duration in seconds (default: 5 minutes) */
  minDuration?: number;
  /** Session ID length in bytes (default: 32) */
  sessionIdLength?: number;
  /** Enable secure random generation fallback */
  enableFallback?: boolean;
}

interface CreatedSession {
  /** Cryptographically strong session ID */
  sessionId: string;
  /** Session expiration timestamp (Unix timestamp) */
  expiresAt: number;
  /** Session creation timestamp (Unix timestamp) */
  createdAt: number;
  /** User ID */
  userId: string;
  /** Session metadata */
  metadata?: Record<string, any>;
  /** Security context */
  securityContext?: SessionData['securityContext'];
}

/**
 * Generates a cryptographically strong random session ID
 * Compatible with Cloudflare Workers crypto.getRandomValues() and Node.js crypto
 * 
 * @param length Length in bytes (default: 32)
 * @param enableFallback Enable fallback for environments without crypto (default: false)
 * @returns Base64URL-encoded session ID
 */
function generateSecureSessionId(length: number = 32, enableFallback: boolean = false): string {
  // Validate length
  if (length < 16 || length > 64) {
    throw new Error('ERIFY™ Session: Session ID length must be between 16 and 64 bytes');
  }

  try {
    // Try Web Crypto API (Cloudflare Workers) or Node.js crypto
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      const buffer = new Uint8Array(length);
      crypto.getRandomValues(buffer);
      return base64UrlEncode(buffer);
    }

    // Node.js crypto fallback
    if (typeof require !== 'undefined') {
      try {
        const nodeCrypto = require('crypto');
        const buffer = nodeCrypto.randomBytes(length);
        return base64UrlEncode(new Uint8Array(buffer));
      } catch (nodeError) {
        // Node.js crypto not available
      }
    }

    // Fallback for testing/development (NOT for production)
    if (enableFallback) {
      console.warn('ERIFY™ Session: Using fallback random generation - NOT suitable for production');
      const buffer = new Uint8Array(length);
      for (let i = 0; i < length; i++) {
        buffer[i] = Math.floor(Math.random() * 256);
      }
      return base64UrlEncode(buffer);
    }

    throw new Error('ERIFY™ Session: No secure random number generator available');

  } catch (error) {
    throw new Error(`ERIFY™ Session: Failed to generate secure session ID - ${error.message}`);
  }
}

/**
 * Converts Uint8Array to Base64URL encoding (RFC 4648)
 * Safe for URLs and JSON without escaping
 */
function base64UrlEncode(buffer: Uint8Array): string {
  const base64 = typeof btoa !== 'undefined' 
    ? btoa(String.fromCharCode(...buffer))
    : Buffer.from(buffer).toString('base64');
  
  return base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Validates session data input
 */
function validateSessionData(data: SessionData): void {
  if (!data.userId?.trim()) {
    throw new Error('ERIFY™ Session: User ID is required and cannot be empty');
  }

  if (data.userId.length > 255) {
    throw new Error('ERIFY™ Session: User ID cannot exceed 255 characters');
  }

  // Validate IP address format if provided
  if (data.ipAddress) {
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    if (!ipRegex.test(data.ipAddress)) {
      throw new Error('ERIFY™ Session: Invalid IP address format');
    }
  }

  // Validate security context
  if (data.securityContext?.riskScore !== undefined) {
    if (typeof data.securityContext.riskScore !== 'number' || 
        data.securityContext.riskScore < 0 || 
        data.securityContext.riskScore > 100) {
      throw new Error('ERIFY™ Session: Risk score must be a number between 0 and 100');
    }
  }

  // Validate metadata size
  if (data.metadata) {
    const metadataString = JSON.stringify(data.metadata);
    if (metadataString.length > 4096) {
      throw new Error('ERIFY™ Session: Metadata cannot exceed 4KB when serialized');
    }
  }
}

/**
 * Creates a new secure session with cryptographically strong random ID
 * 
 * @param sessionData Session data including user ID and optional metadata
 * @param config Session configuration options
 * @returns Promise resolving to created session information
 */
export async function createSession(
  sessionData: SessionData,
  config: SessionConfig = {}
): Promise<CreatedSession> {
  // Validate input data
  validateSessionData(sessionData);

  // Apply configuration defaults
  const {
    defaultDuration = 24 * 60 * 60, // 24 hours
    maxDuration = 7 * 24 * 60 * 60,  // 7 days
    minDuration = 5 * 60,            // 5 minutes
    sessionIdLength = 32,            // 32 bytes = 256 bits
    enableFallback = false,
  } = config;

  // Validate and calculate session duration
  let sessionDuration = sessionData.duration || defaultDuration;
  
  if (sessionDuration < minDuration) {
    sessionDuration = minDuration;
  } else if (sessionDuration > maxDuration) {
    sessionDuration = maxDuration;
  }

  try {
    // Generate cryptographically strong session ID
    const sessionId = generateSecureSessionId(sessionIdLength, enableFallback);
    
    // Calculate timestamps
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + sessionDuration;

    // Create session object
    const session: CreatedSession = {
      sessionId,
      expiresAt,
      createdAt: now,
      userId: sessionData.userId,
    };

    // Add optional fields
    if (sessionData.metadata && Object.keys(sessionData.metadata).length > 0) {
      session.metadata = { ...sessionData.metadata };
    }

    if (sessionData.securityContext) {
      session.securityContext = { ...sessionData.securityContext };
    }

    return session;

  } catch (error) {
    throw new Error(`ERIFY™ Session: Failed to create session - ${error.message}`);
  }
}

/**
 * Creates a high-security session for sensitive operations
 * Enhanced security settings for financial and critical operations
 * 
 * @param sessionData Session data
 * @param additionalSecurity Additional security requirements
 * @returns Promise resolving to created session with enhanced security
 */
export async function createHighSecuritySession(
  sessionData: SessionData,
  additionalSecurity: {
    /** Require MFA verification */
    requireMfa?: boolean;
    /** Maximum risk score allowed */
    maxRiskScore?: number;
    /** Required device fingerprint */
    requiredDeviceFingerprint?: string;
    /** Shorter session duration for high-security */
    maxDuration?: number;
  } = {}
): Promise<CreatedSession> {
  // Validate high-security requirements
  if (additionalSecurity.requireMfa && !sessionData.securityContext?.mfaVerified) {
    throw new Error('ERIFY™ Session: MFA verification is required for high-security sessions');
  }

  if (additionalSecurity.maxRiskScore !== undefined && 
      sessionData.securityContext?.riskScore !== undefined &&
      sessionData.securityContext.riskScore > additionalSecurity.maxRiskScore) {
    throw new Error(`ERIFY™ Session: Risk score ${sessionData.securityContext.riskScore} exceeds maximum allowed ${additionalSecurity.maxRiskScore}`);
  }

  if (additionalSecurity.requiredDeviceFingerprint &&
      sessionData.securityContext?.deviceFingerprint !== additionalSecurity.requiredDeviceFingerprint) {
    throw new Error('ERIFY™ Session: Device fingerprint mismatch for high-security session');
  }

  // Create session with enhanced security configuration
  const config: SessionConfig = {
    defaultDuration: additionalSecurity.maxDuration || 2 * 60 * 60, // 2 hours default
    maxDuration: additionalSecurity.maxDuration || 4 * 60 * 60,     // 4 hours max
    minDuration: 5 * 60,     // 5 minutes min
    sessionIdLength: 48,     // 48 bytes = 384 bits for enhanced security
    enableFallback: false,   // Never allow fallback for high-security
  };

  return createSession(sessionData, config);
}

/**
 * Utility function to extract session context from request headers
 * Useful for Cloudflare Workers and Node.js request handling
 * 
 * @param headers Request headers (Headers object or plain object)
 * @returns Extracted session context
 */
export function extractSessionContext(
  headers: Headers | Record<string, string>
): Pick<SessionData, 'ipAddress' | 'userAgent'> {
  const getHeader = (key: string): string | undefined => {
    if (headers instanceof Headers) {
      return headers.get(key) || undefined;
    }
    return headers[key] || headers[key.toLowerCase()];
  };

  return {
    ipAddress: getHeader('cf-connecting-ip') || 
               getHeader('x-forwarded-for')?.split(',')[0]?.trim() ||
               getHeader('x-real-ip') ||
               getHeader('remote-addr'),
    userAgent: getHeader('user-agent'),
  };
}

/**
 * Creates a session with automatic context extraction from request
 * Convenience function for web applications
 * 
 * @param userId User identifier
 * @param headers Request headers
 * @param additionalData Additional session data
 * @param config Session configuration
 * @returns Promise resolving to created session
 */
export async function createSessionFromRequest(
  userId: string,
  headers: Headers | Record<string, string>,
  additionalData: Omit<SessionData, 'userId' | 'ipAddress' | 'userAgent'> = {},
  config: SessionConfig = {}
): Promise<CreatedSession> {
  const context = extractSessionContext(headers);
  
  const sessionData: SessionData = {
    userId,
    ...context,
    ...additionalData,
  };

  return createSession(sessionData, config);
}