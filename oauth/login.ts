/**
 * ERIFY™ OAuth Login
 * Production-ready OAuth authorization code flow for Cloudflare Workers and Node.js
 * Enterprise-grade fintech integrations with security and compliance
 */

interface OAuthConfig {
  /** OAuth client ID */
  clientId: string;
  /** OAuth client secret */
  clientSecret: string;
  /** Token exchange endpoint URL */
  tokenUrl: string;
  /** Request timeout in milliseconds (default: 30000) */
  timeout?: number;
  /** Custom headers for the request */
  headers?: Record<string, string>;
  /** OAuth scopes to request */
  scopes?: string[];
  /** PKCE code verifier (for public clients) */
  codeVerifier?: string;
}

interface TokenResponse {
  /** Access token */
  access_token: string;
  /** Refresh token (optional) */
  refresh_token?: string;
  /** Token type (usually 'Bearer') */
  token_type: string;
  /** Token expiration time in seconds */
  expires_in: number;
  /** Token scope */
  scope?: string;
  /** ID token (for OpenID Connect) */
  id_token?: string;
}

interface TokenError {
  /** Error code */
  error: string;
  /** Human-readable error description */
  error_description?: string;
  /** Error URI for more information */
  error_uri?: string;
}

/**
 * Exchanges OAuth authorization code for access tokens
 * Compatible with Cloudflare Workers and Node.js environments
 * Supports PKCE for enhanced security
 * 
 * @param code Authorization code from OAuth provider
 * @param redirectUri Redirect URI used in authorization request
 * @param config OAuth configuration options
 * @returns Promise resolving to token response
 * @throws Error if token exchange fails or response is invalid
 */
export async function login(
  code: string,
  redirectUri: string,
  config: OAuthConfig
): Promise<TokenResponse> {
  // Validate inputs
  if (!code?.trim()) {
    throw new Error('ERIFY™ OAuth: Authorization code is required and cannot be empty');
  }

  if (!redirectUri?.trim()) {
    throw new Error('ERIFY™ OAuth: Redirect URI is required and cannot be empty');
  }

  if (!config.clientId?.trim() || !config.clientSecret?.trim() || !config.tokenUrl?.trim()) {
    throw new Error('ERIFY™ OAuth: Client ID, client secret, and token URL are required');
  }

  // Validate URL format
  try {
    new URL(config.tokenUrl);
    new URL(redirectUri);
  } catch {
    throw new Error('ERIFY™ OAuth: Invalid URL format for token URL or redirect URI');
  }

  const timeout = config.timeout || 30000;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  try {
    // Prepare request body for OAuth 2.0 authorization code grant
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: redirectUri,
      client_id: config.clientId,
      client_secret: config.clientSecret,
    });

    // Add optional PKCE code verifier for enhanced security
    if (config.codeVerifier) {
      body.append('code_verifier', config.codeVerifier);
    }

    // Add scopes if specified
    if (config.scopes && config.scopes.length > 0) {
      body.append('scope', config.scopes.join(' '));
    }

    // Prepare headers with security best practices
    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json',
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Pragma': 'no-cache',
      'User-Agent': 'ERIFY-OAuth/1.0',
      ...config.headers,
    };

    // Make the token exchange request
    const response = await fetch(config.tokenUrl, {
      method: 'POST',
      headers,
      body: body.toString(),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    // Parse response
    let responseData: any;
    try {
      responseData = await response.json();
    } catch (parseError) {
      throw new Error(`ERIFY™ OAuth: Invalid JSON response from token endpoint`);
    }

    // Handle error responses
    if (!response.ok) {
      const errorData = responseData as TokenError;
      const errorMessage = errorData.error_description || errorData.error || `HTTP ${response.status}`;
      throw new Error(`ERIFY™ OAuth: Token exchange failed - ${errorMessage}`);
    }

    // Validate required response fields
    if (!responseData.access_token || typeof responseData.access_token !== 'string') {
      throw new Error('ERIFY™ OAuth: Invalid response - missing or invalid access_token');
    }

    if (!responseData.token_type || typeof responseData.token_type !== 'string') {
      throw new Error('ERIFY™ OAuth: Invalid response - missing or invalid token_type');
    }

    if (responseData.expires_in && (typeof responseData.expires_in !== 'number' || responseData.expires_in <= 0)) {
      throw new Error('ERIFY™ OAuth: Invalid response - invalid expires_in value');
    }

    // Return sanitized response
    const result: TokenResponse = {
      access_token: responseData.access_token,
      token_type: responseData.token_type,
      expires_in: responseData.expires_in || 3600, // Default to 1 hour if not provided
    };

    // Include optional fields if present
    if (responseData.refresh_token && typeof responseData.refresh_token === 'string') {
      result.refresh_token = responseData.refresh_token;
    }

    if (responseData.scope && typeof responseData.scope === 'string') {
      result.scope = responseData.scope;
    }

    if (responseData.id_token && typeof responseData.id_token === 'string') {
      result.id_token = responseData.id_token;
    }

    return result;

  } catch (error) {
    clearTimeout(timeoutId);
    
    if (error.name === 'AbortError') {
      throw new Error(`ERIFY™ OAuth: Token exchange timeout after ${timeout}ms`);
    }
    
    if (error.message?.startsWith('ERIFY™ OAuth:')) {
      throw error;
    }
    
    throw new Error(`ERIFY™ OAuth: Token exchange failed - ${error.message || 'Unknown error'}`);
  }
}

/**
 * Generates PKCE code verifier and challenge for enhanced security
 * Required for public OAuth clients and recommended for all clients
 * 
 * @param length Code verifier length (43-128 characters, default: 64)
 * @returns PKCE code verifier and challenge
 */
export function generatePKCE(length: number = 64): { codeVerifier: string; codeChallenge: string } {
  if (length < 43 || length > 128) {
    throw new Error('ERIFY™ OAuth: PKCE code verifier length must be between 43 and 128 characters');
  }

  // Generate cryptographically strong random code verifier
  const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  let codeVerifier = '';

  try {
    // Use Web Crypto API (Cloudflare Workers) or Node.js crypto
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      const randomValues = new Uint8Array(length);
      crypto.getRandomValues(randomValues);
      
      for (let i = 0; i < length; i++) {
        codeVerifier += charset[randomValues[i] % charset.length];
      }
    } else if (typeof require !== 'undefined') {
      // Node.js crypto fallback
      try {
        const nodeCrypto = require('crypto');
        const randomBytes = nodeCrypto.randomBytes(length);
        
        for (let i = 0; i < length; i++) {
          codeVerifier += charset[randomBytes[i] % charset.length];
        }
      } catch (nodeError) {
        throw new Error('No secure random number generator available');
      }
    } else {
      throw new Error('No secure random number generator available');
    }
  } catch (error) {
    throw new Error(`ERIFY™ OAuth: Failed to generate PKCE code verifier - ${error.message}`);
  }

  // Generate SHA256 code challenge
  const codeChallenge = generateCodeChallenge(codeVerifier);

  return { codeVerifier, codeChallenge };
}

/**
 * Generates SHA256 code challenge from code verifier
 */
async function generateCodeChallenge(codeVerifier: string): Promise<string> {
  try {
    // Use Web Crypto API
    if (typeof crypto !== 'undefined' && crypto.subtle) {
      const encoder = new TextEncoder();
      const data = encoder.encode(codeVerifier);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      
      // Convert to Base64URL
      const hashArray = new Uint8Array(hashBuffer);
      const base64 = typeof btoa !== 'undefined'
        ? btoa(String.fromCharCode(...hashArray))
        : Buffer.from(hashArray).toString('base64');
      
      return base64
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
    }

    // Node.js crypto fallback
    if (typeof require !== 'undefined') {
      try {
        const nodeCrypto = require('crypto');
        const hash = nodeCrypto.createHash('sha256').update(codeVerifier).digest('base64');
        return hash
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=/g, '');
      } catch (nodeError) {
        throw new Error('No SHA256 implementation available');
      }
    }

    throw new Error('No SHA256 implementation available');

  } catch (error) {
    throw new Error(`Failed to generate code challenge: ${error.message}`);
  }
}

/**
 * Builds OAuth authorization URL with proper parameters
 * 
 * @param authUrl Authorization endpoint URL
 * @param clientId OAuth client ID
 * @param redirectUri Redirect URI
 * @param options Additional OAuth parameters
 * @returns Complete authorization URL
 */
export function buildAuthorizationUrl(
  authUrl: string,
  clientId: string,
  redirectUri: string,
  options: {
    /** OAuth scopes */
    scopes?: string[];
    /** OAuth state parameter for CSRF protection */
    state?: string;
    /** PKCE code challenge */
    codeChallenge?: string;
    /** Additional parameters */
    additionalParams?: Record<string, string>;
  } = {}
): string {
  // Validate inputs
  if (!authUrl?.trim() || !clientId?.trim() || !redirectUri?.trim()) {
    throw new Error('ERIFY™ OAuth: Authorization URL, client ID, and redirect URI are required');
  }

  try {
    new URL(authUrl);
    new URL(redirectUri);
  } catch {
    throw new Error('ERIFY™ OAuth: Invalid URL format');
  }

  // Build URL parameters
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: redirectUri,
  });

  // Add optional parameters
  if (options.scopes && options.scopes.length > 0) {
    params.append('scope', options.scopes.join(' '));
  }

  if (options.state) {
    params.append('state', options.state);
  }

  if (options.codeChallenge) {
    params.append('code_challenge', options.codeChallenge);
    params.append('code_challenge_method', 'S256');
  }

  // Add any additional parameters
  if (options.additionalParams) {
    for (const [key, value] of Object.entries(options.additionalParams)) {
      params.append(key, value);
    }
  }

  return `${authUrl}?${params.toString()}`;
}

/**
 * OAuth login with automatic retry logic for production reliability
 * 
 * @param code Authorization code
 * @param redirectUri Redirect URI
 * @param config OAuth configuration
 * @param maxRetries Maximum number of retry attempts (default: 3)
 * @param retryDelayMs Delay between retries in milliseconds (default: 1000)
 * @returns Promise resolving to token response
 */
export async function loginWithRetry(
  code: string,
  redirectUri: string,
  config: OAuthConfig,
  maxRetries: number = 3,
  retryDelayMs: number = 1000
): Promise<TokenResponse> {
  let lastError: Error;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await login(code, redirectUri, config);
    } catch (error) {
      lastError = error;
      
      // Don't retry on validation errors
      if (error.message?.includes('required') || error.message?.includes('Invalid')) {
        throw error;
      }
      
      if (attempt < maxRetries) {
        // Exponential backoff with jitter
        const delay = retryDelayMs * Math.pow(2, attempt - 1) + Math.random() * 1000;
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }

  throw new Error(`ERIFY™ OAuth: Login failed after ${maxRetries} attempts - ${lastError.message}`);
}