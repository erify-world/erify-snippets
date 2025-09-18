/**
 * ERIFY™ Session Validation
 * Production-ready session validation for Cloudflare Workers and Node.js
 * Enterprise-grade security with comprehensive validation and threat detection
 */

interface StoredSession {
  /** Session ID */
  sessionId: string;
  /** User ID */
  userId: string;
  /** Session expiration timestamp (Unix timestamp) */
  expiresAt: number;
  /** Session creation timestamp (Unix timestamp) */
  createdAt: number;
  /** Last activity timestamp (Unix timestamp) */
  lastActivityAt?: number;
  /** Session metadata */
  metadata?: Record<string, any>;
  /** Security context */
  securityContext?: {
    mfaVerified?: boolean;
    riskScore?: number;
    deviceFingerprint?: string;
    ipAddress?: string;
    userAgent?: string;
  };
  /** Session status flags */
  flags?: {
    /** Session is revoked */
    revoked?: boolean;
    /** Session requires refresh */
    requiresRefresh?: boolean;
    /** High-security session */
    highSecurity?: boolean;
  };
}

interface ValidationOptions {
  /** Enable automatic session extension on activity */
  extendOnActivity?: boolean;
  /** Session extension duration in seconds */
  extensionDuration?: number;
  /** Maximum session lifetime regardless of activity */
  maxLifetime?: number;
  /** Enable IP address validation */
  validateIpAddress?: boolean;
  /** Enable user agent validation */
  validateUserAgent?: boolean;
  /** Enable device fingerprint validation */
  validateDeviceFingerprint?: boolean;
  /** Grace period for clock skew in seconds */
  clockSkewGrace?: number;
  /** Enable activity tracking */
  trackActivity?: boolean;
}

interface ValidationContext {
  /** Current IP address */
  ipAddress?: string;
  /** Current user agent */
  userAgent?: string;
  /** Current device fingerprint */
  deviceFingerprint?: string;
  /** Current timestamp override (for testing) */
  currentTime?: number;
}

interface ValidationResult {
  /** Validation success status */
  isValid: boolean;
  /** Session data if valid */
  session?: StoredSession;
  /** Validation error code */
  errorCode?: string;
  /** Human-readable error message */
  errorMessage?: string;
  /** Security warnings */
  warnings?: string[];
  /** Updated session (if extended) */
  updatedSession?: StoredSession;
  /** Validation metadata */
  metadata: {
    /** Validation timestamp */
    validatedAt: number;
    /** Time until expiration in seconds */
    timeUntilExpiration?: number;
    /** Session age in seconds */
    sessionAge: number;
    /** Activity since last validation */
    activityGap?: number;
  };
}

// Common error codes for standardized error handling
export const SESSION_ERROR_CODES = {
  INVALID_SESSION_ID: 'INVALID_SESSION_ID',
  SESSION_NOT_FOUND: 'SESSION_NOT_FOUND',
  SESSION_EXPIRED: 'SESSION_EXPIRED',
  SESSION_REVOKED: 'SESSION_REVOKED',
  SESSION_REQUIRES_REFRESH: 'SESSION_REQUIRES_REFRESH',
  IP_ADDRESS_MISMATCH: 'IP_ADDRESS_MISMATCH',
  USER_AGENT_MISMATCH: 'USER_AGENT_MISMATCH',
  DEVICE_FINGERPRINT_MISMATCH: 'DEVICE_FINGERPRINT_MISMATCH',
  SESSION_LIFETIME_EXCEEDED: 'SESSION_LIFETIME_EXCEEDED',
  SECURITY_VALIDATION_FAILED: 'SECURITY_VALIDATION_FAILED',
} as const;

/**
 * Validates session ID format and structure
 * Ensures session ID meets security requirements
 */
function validateSessionIdFormat(sessionId: string): boolean {
  if (!sessionId || typeof sessionId !== 'string') {
    return false;
  }

  // Check length (Base64URL encoded, minimum 16 bytes = ~22 chars, maximum 64 bytes = ~86 chars)
  if (sessionId.length < 22 || sessionId.length > 86) {
    return false;
  }

  // Check Base64URL format (only alphanumeric, -, and _ characters)
  const base64UrlRegex = /^[A-Za-z0-9_-]+$/;
  if (!base64UrlRegex.test(sessionId)) {
    return false;
  }

  return true;
}

/**
 * Validates session timing and expiration
 */
function validateSessionTiming(
  session: StoredSession,
  currentTime: number,
  options: ValidationOptions
): { isValid: boolean; errorCode?: string; errorMessage?: string; warnings?: string[] } {
  const warnings: string[] = [];
  const clockSkewGrace = options.clockSkewGrace || 30; // 30 seconds default

  // Check if session is expired
  if (currentTime > session.expiresAt + clockSkewGrace) {
    return {
      isValid: false,
      errorCode: SESSION_ERROR_CODES.SESSION_EXPIRED,
      errorMessage: 'Session has expired',
    };
  }

  // Check maximum lifetime if configured
  if (options.maxLifetime) {
    const sessionAge = currentTime - session.createdAt;
    if (sessionAge > options.maxLifetime + clockSkewGrace) {
      return {
        isValid: false,
        errorCode: SESSION_ERROR_CODES.SESSION_LIFETIME_EXCEEDED,
        errorMessage: 'Session has exceeded maximum lifetime',
      };
    }
  }

  // Warning for sessions expiring soon
  const timeUntilExpiration = session.expiresAt - currentTime;
  if (timeUntilExpiration < 300) { // Less than 5 minutes
    warnings.push(`Session expires in ${Math.floor(timeUntilExpiration / 60)} minutes`);
  }

  return { isValid: true, warnings };
}

/**
 * Validates security context and detects anomalies
 */
function validateSecurityContext(
  session: StoredSession,
  context: ValidationContext,
  options: ValidationOptions
): { isValid: boolean; errorCode?: string; errorMessage?: string; warnings?: string[] } {
  const warnings: string[] = [];

  // IP address validation
  if (options.validateIpAddress && context.ipAddress && session.securityContext?.ipAddress) {
    if (context.ipAddress !== session.securityContext.ipAddress) {
      return {
        isValid: false,
        errorCode: SESSION_ERROR_CODES.IP_ADDRESS_MISMATCH,
        errorMessage: 'IP address does not match session origin',
      };
    }
  }

  // User agent validation (more lenient, just warn on mismatch)
  if (options.validateUserAgent && context.userAgent && session.securityContext?.userAgent) {
    if (context.userAgent !== session.securityContext.userAgent) {
      warnings.push('User agent has changed since session creation');
    }
  }

  // Device fingerprint validation
  if (options.validateDeviceFingerprint && context.deviceFingerprint && session.securityContext?.deviceFingerprint) {
    if (context.deviceFingerprint !== session.securityContext.deviceFingerprint) {
      return {
        isValid: false,
        errorCode: SESSION_ERROR_CODES.DEVICE_FINGERPRINT_MISMATCH,
        errorMessage: 'Device fingerprint does not match session origin',
      };
    }
  }

  return { isValid: true, warnings };
}

/**
 * Extends session if activity-based extension is enabled
 */
function extendSession(
  session: StoredSession,
  currentTime: number,
  options: ValidationOptions
): StoredSession | undefined {
  if (!options.extendOnActivity) {
    return undefined;
  }

  const extensionDuration = options.extensionDuration || 3600; // 1 hour default
  const newExpirationTime = currentTime + extensionDuration;

  // Only extend if the new expiration is later than current
  if (newExpirationTime > session.expiresAt) {
    return {
      ...session,
      expiresAt: newExpirationTime,
      lastActivityAt: currentTime,
    };
  }

  // Update activity time even if not extending expiration
  if (options.trackActivity) {
    return {
      ...session,
      lastActivityAt: currentTime,
    };
  }

  return undefined;
}

/**
 * Validates a session and returns comprehensive validation results
 * 
 * @param sessionId Session ID to validate
 * @param storedSession Retrieved session data from storage
 * @param context Current request context for security validation
 * @param options Validation configuration options
 * @returns Comprehensive validation result
 */
export function validateSession(
  sessionId: string,
  storedSession: StoredSession | null,
  context: ValidationContext = {},
  options: ValidationOptions = {}
): ValidationResult {
  const currentTime = context.currentTime || Math.floor(Date.now() / 1000);
  const warnings: string[] = [];

  // Validate session ID format
  if (!validateSessionIdFormat(sessionId)) {
    return {
      isValid: false,
      errorCode: SESSION_ERROR_CODES.INVALID_SESSION_ID,
      errorMessage: 'Invalid session ID format',
      metadata: {
        validatedAt: currentTime,
        sessionAge: 0,
      },
    };
  }

  // Check if session exists
  if (!storedSession) {
    return {
      isValid: false,
      errorCode: SESSION_ERROR_CODES.SESSION_NOT_FOUND,
      errorMessage: 'Session not found',
      metadata: {
        validatedAt: currentTime,
        sessionAge: 0,
      },
    };
  }

  // Verify session ID matches
  if (storedSession.sessionId !== sessionId) {
    return {
      isValid: false,
      errorCode: SESSION_ERROR_CODES.INVALID_SESSION_ID,
      errorMessage: 'Session ID mismatch',
      metadata: {
        validatedAt: currentTime,
        sessionAge: currentTime - storedSession.createdAt,
      },
    };
  }

  // Check session flags
  if (storedSession.flags?.revoked) {
    return {
      isValid: false,
      errorCode: SESSION_ERROR_CODES.SESSION_REVOKED,
      errorMessage: 'Session has been revoked',
      metadata: {
        validatedAt: currentTime,
        sessionAge: currentTime - storedSession.createdAt,
      },
    };
  }

  if (storedSession.flags?.requiresRefresh) {
    return {
      isValid: false,
      errorCode: SESSION_ERROR_CODES.SESSION_REQUIRES_REFRESH,
      errorMessage: 'Session requires refresh',
      metadata: {
        validatedAt: currentTime,
        sessionAge: currentTime - storedSession.createdAt,
      },
    };
  }

  // Validate timing
  const timingResult = validateSessionTiming(storedSession, currentTime, options);
  if (!timingResult.isValid) {
    return {
      isValid: false,
      errorCode: timingResult.errorCode,
      errorMessage: timingResult.errorMessage,
      metadata: {
        validatedAt: currentTime,
        sessionAge: currentTime - storedSession.createdAt,
        timeUntilExpiration: storedSession.expiresAt - currentTime,
      },
    };
  }
  warnings.push(...(timingResult.warnings || []));

  // Validate security context
  const securityResult = validateSecurityContext(storedSession, context, options);
  if (!securityResult.isValid) {
    return {
      isValid: false,
      errorCode: securityResult.errorCode,
      errorMessage: securityResult.errorMessage,
      warnings: [...warnings, ...(securityResult.warnings || [])],
      metadata: {
        validatedAt: currentTime,
        sessionAge: currentTime - storedSession.createdAt,
        timeUntilExpiration: storedSession.expiresAt - currentTime,
      },
    };
  }
  warnings.push(...(securityResult.warnings || []));

  // Calculate activity gap
  const activityGap = storedSession.lastActivityAt 
    ? currentTime - storedSession.lastActivityAt
    : undefined;

  // Extend session if configured
  const updatedSession = extendSession(storedSession, currentTime, options);

  // Return successful validation
  return {
    isValid: true,
    session: storedSession,
    warnings: warnings.length > 0 ? warnings : undefined,
    updatedSession,
    metadata: {
      validatedAt: currentTime,
      sessionAge: currentTime - storedSession.createdAt,
      timeUntilExpiration: storedSession.expiresAt - currentTime,
      activityGap,
    },
  };
}

/**
 * High-level session validation for web requests
 * Extracts session context from request and validates
 * 
 * @param sessionId Session ID from request
 * @param storedSession Retrieved session data
 * @param headers Request headers for context extraction
 * @param options Validation options
 * @returns Validation result
 */
export function validateSessionFromRequest(
  sessionId: string,
  storedSession: StoredSession | null,
  headers: Headers | Record<string, string>,
  options: ValidationOptions = {}
): ValidationResult {
  const getHeader = (key: string): string | undefined => {
    if (headers instanceof Headers) {
      return headers.get(key) || undefined;
    }
    return headers[key] || headers[key.toLowerCase()];
  };

  const context: ValidationContext = {
    ipAddress: getHeader('cf-connecting-ip') || 
               getHeader('x-forwarded-for')?.split(',')[0]?.trim() ||
               getHeader('x-real-ip') ||
               getHeader('remote-addr'),
    userAgent: getHeader('user-agent'),
    deviceFingerprint: getHeader('x-device-fingerprint'),
  };

  return validateSession(sessionId, storedSession, context, options);
}

/**
 * Validates session for high-security operations
 * Enforces stricter validation rules for sensitive operations
 * 
 * @param sessionId Session ID to validate
 * @param storedSession Retrieved session data
 * @param context Validation context
 * @param additionalRequirements Additional security requirements
 * @returns Validation result with enhanced security checks
 */
export function validateHighSecuritySession(
  sessionId: string,
  storedSession: StoredSession | null,
  context: ValidationContext = {},
  additionalRequirements: {
    requireMfa?: boolean;
    maxRiskScore?: number;
    maxSessionAge?: number;
    requireDeviceFingerprint?: boolean;
  } = {}
): ValidationResult {
  // Enhanced validation options for high-security
  const options: ValidationOptions = {
    validateIpAddress: true,
    validateUserAgent: true,
    validateDeviceFingerprint: additionalRequirements.requireDeviceFingerprint || false,
    extendOnActivity: false, // No automatic extension for high-security sessions
    trackActivity: true,
    clockSkewGrace: 5, // Tighter clock skew tolerance
  };

  // Perform standard validation first
  const result = validateSession(sessionId, storedSession, context, options);

  if (!result.isValid || !result.session) {
    return result;
  }

  const session = result.session;
  const warnings = [...(result.warnings || [])];

  // Additional high-security checks
  if (additionalRequirements.requireMfa && !session.securityContext?.mfaVerified) {
    return {
      isValid: false,
      errorCode: SESSION_ERROR_CODES.SECURITY_VALIDATION_FAILED,
      errorMessage: 'MFA verification required for high-security operation',
      metadata: result.metadata,
    };
  }

  if (additionalRequirements.maxRiskScore !== undefined && 
      session.securityContext?.riskScore !== undefined &&
      session.securityContext.riskScore > additionalRequirements.maxRiskScore) {
    return {
      isValid: false,
      errorCode: SESSION_ERROR_CODES.SECURITY_VALIDATION_FAILED,
      errorMessage: `Risk score ${session.securityContext.riskScore} exceeds maximum ${additionalRequirements.maxRiskScore}`,
      metadata: result.metadata,
    };
  }

  if (additionalRequirements.maxSessionAge) {
    const sessionAge = result.metadata.sessionAge;
    if (sessionAge > additionalRequirements.maxSessionAge) {
      return {
        isValid: false,
        errorCode: SESSION_ERROR_CODES.SESSION_LIFETIME_EXCEEDED,
        errorMessage: `Session age ${sessionAge}s exceeds maximum ${additionalRequirements.maxSessionAge}s for high-security operation`,
        metadata: result.metadata,
      };
    }
  }

  return {
    ...result,
    warnings: warnings.length > 0 ? warnings : undefined,
  };
}

/**
 * Utility function to extract session ID from various sources
 * Supports cookies, headers, and query parameters
 * 
 * @param headers Request headers
 * @param cookieName Session cookie name (default: 'sessionId')
 * @param headerName Session header name (default: 'x-session-id')
 * @param queryParam Query parameter name (default: 'sessionId')
 * @returns Extracted session ID or undefined
 */
export function extractSessionId(
  headers: Headers | Record<string, string>,
  cookieName: string = 'sessionId',
  headerName: string = 'x-session-id',
  queryParam?: string
): string | undefined {
  const getHeader = (key: string): string | undefined => {
    if (headers instanceof Headers) {
      return headers.get(key) || undefined;
    }
    return headers[key] || headers[key.toLowerCase()];
  };

  // Try header first
  const headerValue = getHeader(headerName);
  if (headerValue) {
    return headerValue;
  }

  // Try cookie
  const cookieHeader = getHeader('cookie');
  if (cookieHeader) {
    const cookies = cookieHeader.split(';').map(c => c.trim());
    for (const cookie of cookies) {
      const [name, value] = cookie.split('=', 2);
      if (name?.trim() === cookieName && value) {
        return decodeURIComponent(value);
      }
    }
  }

  // Try Authorization header (Bearer token)
  const authHeader = getHeader('authorization');
  if (authHeader?.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }

  return undefined;
}