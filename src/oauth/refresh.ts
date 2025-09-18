/**
 * ERIFY™ OAuth Token Refresh Implementation
 * 
 * Secure OAuth 2.0 token refresh with rotation and security best practices
 * Designed for Cloudflare Workers, Node.js, and fintech ecosystems
 * 
 * @author Yahaya Ibrahim | ERIFY™ Founder
 * @license MIT
 */

import { jwtVerify, type JWTPayload } from 'jose';

export interface RefreshTokenConfig {
  readonly clientId: string;
  readonly clientSecret: string;
  readonly tokenUrl: string;
  readonly issuer?: string;
  readonly audience?: string;
  readonly rotateRefreshToken?: boolean;
}

export interface RefreshTokenResponse {
  readonly accessToken: string;
  readonly refreshToken: string | undefined;
  readonly expiresIn: number;
  readonly tokenType: string;
  readonly scope: string | undefined;
}

export interface TokenValidationResult {
  readonly isValid: boolean;
  readonly payload: JWTPayload | undefined;
  readonly expiresAt: Date | undefined;
  readonly needsRefresh: boolean;
}

/**
 * Refreshes an OAuth 2.0 access token using refresh token
 */
export async function refreshAccessToken(
  config: RefreshTokenConfig,
  refreshToken: string
): Promise<RefreshTokenResponse> {
  const tokenPayload = new URLSearchParams({
    grant_type: 'refresh_token',
    client_id: config.clientId,
    client_secret: config.clientSecret,
    refresh_token: refreshToken
  });

  if (config.audience) {
    tokenPayload.set('audience', config.audience);
  }

  const response = await fetch(config.tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json',
      'User-Agent': 'ERIFY-Snippets/1.0.0',
      'Authorization': `Basic ${btoa(`${config.clientId}:${config.clientSecret}`)}`
    },
    body: tokenPayload
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`ERIFY™ OAuth: Token refresh failed: ${response.status} ${errorText}`);
  }

  const tokenData = await response.json() as {
    access_token: string;
    refresh_token?: string;
    expires_in: number;
    token_type: string;
    scope?: string;
  };

  return {
    accessToken: tokenData.access_token,
    refreshToken: tokenData.refresh_token,
    expiresIn: tokenData.expires_in,
    tokenType: tokenData.token_type,
    scope: tokenData.scope
  };
}

/**
 * Validates JWT token and checks expiration
 */
export async function validateJWTToken(
  token: string,
  secret: string,
  issuer?: string,
  audience?: string
): Promise<TokenValidationResult> {
  try {
    const encoder = new TextEncoder();
    const secretKey = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const { payload } = await jwtVerify(token, secretKey, {
      issuer: issuer || 'ERIFY™ Technologies',
      audience: audience || 'ERIFY™ Ecosystem'
    });

    const expiresAt = payload.exp ? new Date(payload.exp * 1000) : undefined;
    const now = new Date();
    const needsRefresh = expiresAt ? 
      (expiresAt.getTime() - now.getTime()) < 5 * 60 * 1000 : // Refresh if expires in 5 minutes
      false;

    return {
      isValid: true,
      payload,
      expiresAt,
      needsRefresh
    };
  } catch (error) {
    return {
      isValid: false,
      payload: undefined,
      expiresAt: undefined,
      needsRefresh: true
    };
  }
}

/**
 * Checks if token is close to expiration (within threshold)
 */
export function isTokenExpiringSoon(
  expiresAt: Date,
  thresholdMinutes: number = 5
): boolean {
  const now = new Date();
  const threshold = thresholdMinutes * 60 * 1000; // Convert to milliseconds
  return (expiresAt.getTime() - now.getTime()) < threshold;
}

/**
 * Securely stores tokens with encryption (for server-side storage)
 */
export async function encryptTokenData(
  tokenData: RefreshTokenResponse,
  encryptionKey: string
): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(JSON.stringify(tokenData));
  
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(encryptionKey.padEnd(32, '0').substring(0, 32)),
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    data
  );

  const combined = new Uint8Array(iv.length + encrypted.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(encrypted), iv.length);

  return btoa(String.fromCharCode(...combined));
}

/**
 * Decrypts stored token data
 */
export async function decryptTokenData(
  encryptedData: string,
  encryptionKey: string
): Promise<RefreshTokenResponse> {
  const combined = new Uint8Array(
    atob(encryptedData).split('').map(char => char.charCodeAt(0))
  );
  
  const iv = combined.slice(0, 12);
  const encrypted = combined.slice(12);

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(encryptionKey.padEnd(32, '0').substring(0, 32)),
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    encrypted
  );

  const decoder = new TextDecoder();
  return JSON.parse(decoder.decode(decrypted)) as RefreshTokenResponse;
}

/**
 * Complete token refresh management for ERIFY™ ecosystems
 * 
 * @example Cloudflare Workers usage:
 * ```typescript
 * export default {
 *   async fetch(request: Request, env: Env): Promise<Response> {
 *     const refreshManager = new ERIFYTokenRefresh({
 *       clientId: env.OAUTH_CLIENT_ID,
 *       clientSecret: env.OAUTH_CLIENT_SECRET,
 *       tokenUrl: 'https://auth.erify.world/oauth/token',
 *       rotateRefreshToken: true
 *     });
 *     
 *     const tokens = await refreshManager.refreshIfNeeded(
 *       currentAccessToken,
 *       refreshToken,
 *       env.JWT_SECRET
 *     );
 *     
 *     return new Response(JSON.stringify(tokens));
 *   }
 * };
 * ```
 */
export class ERIFYTokenRefresh {
  constructor(private readonly config: RefreshTokenConfig) {}

  async refreshToken(refreshToken: string): Promise<RefreshTokenResponse> {
    return refreshAccessToken(this.config, refreshToken);
  }

  async validateToken(
    token: string,
    secret: string
  ): Promise<TokenValidationResult> {
    return validateJWTToken(token, secret, this.config.issuer, this.config.audience);
  }

  async refreshIfNeeded(
    accessToken: string,
    refreshToken: string,
    jwtSecret: string
  ): Promise<RefreshTokenResponse | null> {
    const validation = await this.validateToken(accessToken, jwtSecret);
    
    if (!validation.isValid || validation.needsRefresh) {
      return this.refreshToken(refreshToken);
    }
    
    return null; // No refresh needed
  }

  async secureTokenStorage(
    tokenData: RefreshTokenResponse,
    encryptionKey: string
  ): Promise<string> {
    return encryptTokenData(tokenData, encryptionKey);
  }

  async retrieveSecureTokens(
    encryptedData: string,
    encryptionKey: string
  ): Promise<RefreshTokenResponse> {
    return decryptTokenData(encryptedData, encryptionKey);
  }

  /**
   * Automatic token refresh with retry logic
   */
  async autoRefreshWithRetry(
    refreshToken: string,
    maxRetries: number = 3,
    backoffMs: number = 1000
  ): Promise<RefreshTokenResponse> {
    let lastError: Error | null = null;
    
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await this.refreshToken(refreshToken);
      } catch (error) {
        lastError = error as Error;
        
        if (attempt < maxRetries) {
          // Exponential backoff
          await new Promise(resolve => 
            setTimeout(resolve, backoffMs * Math.pow(2, attempt - 1))
          );
        }
      }
    }
    
    throw lastError || new Error('ERIFY™ OAuth: All refresh attempts failed');
  }
}