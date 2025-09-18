/**
 * ERIFY™ OAuth Token Refresh
 * Production-ready OAuth token refresh for Cloudflare Workers and Node.js
 * Designed for fintech integrations with enterprise security standards
 */

interface RefreshTokenOptions {
  /** OAuth client ID */
  clientId: string;
  /** OAuth client secret */
  clientSecret: string;
  /** Token refresh endpoint URL */
  tokenUrl: string;
  /** Request timeout in milliseconds (default: 30000) */
  timeout?: number;
  /** Custom headers for the request */
  headers?: Record<string, string>;
}

interface RefreshTokenResponse {
  /** New access token */
  access_token: string;
  /** New refresh token (optional) */
  refresh_token?: string;
  /** Token type (usually 'Bearer') */
  token_type: string;
  /** Token expiration time in seconds */
  expires_in: number;
  /** Token scope */
  scope?: string;
}

interface RefreshTokenError {
  /** Error code */
  error: string;
  /** Human-readable error description */
  error_description?: string;
  /** Error URI for more information */
  error_uri?: string;
}

/**
 * Refreshes an OAuth access token using a refresh token
 * Compatible with Cloudflare Workers and Node.js environments
 * 
 * @param refreshToken The refresh token to use
 * @param options OAuth configuration options
 * @returns Promise resolving to new token data
 * @throws Error if refresh fails or response is invalid
 */
export async function refreshOAuthToken(
  refreshToken: string,
  options: RefreshTokenOptions
): Promise<RefreshTokenResponse> {
  // Validate inputs
  if (!refreshToken?.trim()) {
    throw new Error('ERIFY™ OAuth: Refresh token is required and cannot be empty');
  }

  if (!options.clientId?.trim() || !options.clientSecret?.trim() || !options.tokenUrl?.trim()) {
    throw new Error('ERIFY™ OAuth: Client ID, client secret, and token URL are required');
  }

  // Validate URL format
  try {
    new URL(options.tokenUrl);
  } catch {
    throw new Error('ERIFY™ OAuth: Invalid token URL format');
  }

  const timeout = options.timeout || 30000;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  try {
    // Prepare request body for OAuth 2.0 refresh token grant
    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: options.clientId,
      client_secret: options.clientSecret,
    });

    // Prepare headers with security best practices
    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json',
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Pragma': 'no-cache',
      'User-Agent': 'ERIFY-OAuth/1.0',
      ...options.headers,
    };

    // Make the token refresh request
    const response = await fetch(options.tokenUrl, {
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
      const errorData = responseData as RefreshTokenError;
      const errorMessage = errorData.error_description || errorData.error || `HTTP ${response.status}`;
      throw new Error(`ERIFY™ OAuth: Token refresh failed - ${errorMessage}`);
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
    const result: RefreshTokenResponse = {
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

    return result;

  } catch (error) {
    clearTimeout(timeoutId);
    
    if (error.name === 'AbortError') {
      throw new Error(`ERIFY™ OAuth: Token refresh timeout after ${timeout}ms`);
    }
    
    if (error.message?.startsWith('ERIFY™ OAuth:')) {
      throw error;
    }
    
    throw new Error(`ERIFY™ OAuth: Token refresh failed - ${error.message || 'Unknown error'}`);
  }
}

/**
 * Utility function to check if a token is expired or will expire soon
 * 
 * @param tokenResponse Previous token response
 * @param bufferSeconds Buffer time in seconds before considering token expired (default: 300 = 5 minutes)
 * @returns True if token should be refreshed
 */
export function shouldRefreshToken(
  tokenResponse: RefreshTokenResponse & { issued_at?: number },
  bufferSeconds: number = 300
): boolean {
  if (!tokenResponse.expires_in) {
    return false; // Token doesn't expire
  }

  const issuedAt = tokenResponse.issued_at || Date.now() / 1000;
  const expiresAt = issuedAt + tokenResponse.expires_in;
  const now = Date.now() / 1000;
  
  return (expiresAt - now) <= bufferSeconds;
}

/**
 * Automatic token refresh with retry logic for production use
 * 
 * @param refreshToken The refresh token to use
 * @param options OAuth configuration options
 * @param maxRetries Maximum number of retry attempts (default: 3)
 * @param retryDelayMs Delay between retries in milliseconds (default: 1000)
 * @returns Promise resolving to new token data
 */
export async function refreshTokenWithRetry(
  refreshToken: string,
  options: RefreshTokenOptions,
  maxRetries: number = 3,
  retryDelayMs: number = 1000
): Promise<RefreshTokenResponse> {
  let lastError: Error;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await refreshOAuthToken(refreshToken, options);
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

  throw new Error(`ERIFY™ OAuth: Token refresh failed after ${maxRetries} attempts - ${lastError.message}`);
}