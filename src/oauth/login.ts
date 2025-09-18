/**
 * ERIFY™ OAuth Login Implementation
 * 
 * Secure OAuth 2.0 login flow with PKCE (Proof Key for Code Exchange)
 * Designed for Cloudflare Workers, Node.js, and fintech ecosystems
 * 
 * @author Yahaya Ibrahim | ERIFY™ Founder
 * @license MIT
 */

import { SignJWT } from 'jose';

export interface OAuth2Config {
  readonly clientId: string;
  readonly clientSecret: string;
  readonly redirectUri: string;
  readonly authorizationUrl: string;
  readonly tokenUrl: string;
  readonly scopes: readonly string[];
  readonly audience?: string;
  readonly issuer?: string;
}

export interface PKCEPair {
  readonly codeVerifier: string;
  readonly codeChallenge: string;
}

export interface AuthorizationRequest {
  readonly authUrl: string;
  readonly state: string;
  readonly codeVerifier: string;
}

export interface TokenResponse {
  readonly accessToken: string;
  readonly refreshToken: string | undefined;
  readonly expiresIn: number;
  readonly tokenType: string;
  readonly scope: string | undefined;
}

/**
 * Generates a secure random string for PKCE code verifier
 */
export function generateCodeVerifier(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array, byte => String.fromCharCode(byte))
    .join('')
    .replace(/[^a-zA-Z0-9]/g, '')
    .substring(0, 43) + 
    Math.random().toString(36).substring(2, 15);
}

/**
 * Creates PKCE code challenge from verifier using SHA256
 */
export async function createCodeChallenge(codeVerifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Generates a secure state parameter for OAuth flow
 */
export function generateState(): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Creates PKCE pair (verifier and challenge)
 */
export async function createPKCEPair(): Promise<PKCEPair> {
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await createCodeChallenge(codeVerifier);
  
  return {
    codeVerifier,
    codeChallenge
  };
}

/**
 * Builds authorization URL for OAuth 2.0 flow with PKCE
 */
export async function buildAuthorizationUrl(
  config: OAuth2Config,
  customState?: string
): Promise<AuthorizationRequest> {
  const { codeVerifier, codeChallenge } = await createPKCEPair();
  const state = customState || generateState();
  
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    scope: config.scopes.join(' '),
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256'
  });

  if (config.audience) {
    params.set('audience', config.audience);
  }

  const authUrl = `${config.authorizationUrl}?${params.toString()}`;
  
  return {
    authUrl,
    state,
    codeVerifier
  };
}

/**
 * Exchanges authorization code for access token using PKCE
 */
export async function exchangeCodeForToken(
  config: OAuth2Config,
  code: string,
  codeVerifier: string,
  state: string,
  receivedState: string
): Promise<TokenResponse> {
  // Verify state parameter to prevent CSRF attacks
  if (state !== receivedState) {
    throw new Error('ERIFY™ OAuth: Invalid state parameter - possible CSRF attack');
  }

  const tokenPayload = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: config.clientId,
    client_secret: config.clientSecret,
    code,
    redirect_uri: config.redirectUri,
    code_verifier: codeVerifier
  });

  const response = await fetch(config.tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json',
      'User-Agent': 'ERIFY-Snippets/1.0.0'
    },
    body: tokenPayload
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`ERIFY™ OAuth: Token exchange failed: ${response.status} ${errorText}`);
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
 * Creates a secure JWT for internal use with ERIFY™ systems
 */
export async function createSecureJWT(
  payload: Record<string, unknown>,
  secret: string,
  expiresIn: string = '1h'
): Promise<string> {
  const encoder = new TextEncoder();
  const secretKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  return await new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(expiresIn)
    .setIssuer('ERIFY™ Technologies')
    .setAudience('ERIFY™ Ecosystem')
    .sign(secretKey);
}

/**
 * Complete OAuth 2.0 login flow for ERIFY™ ecosystems
 * 
 * @example Cloudflare Workers usage:
 * ```typescript
 * export default {
 *   async fetch(request: Request, env: Env): Promise<Response> {
 *     const config: OAuth2Config = {
 *       clientId: env.OAUTH_CLIENT_ID,
 *       clientSecret: env.OAUTH_CLIENT_SECRET,
 *       redirectUri: 'https://app.erify.world/auth/callback',
 *       authorizationUrl: 'https://auth.erify.world/oauth/authorize',
 *       tokenUrl: 'https://auth.erify.world/oauth/token',
 *       scopes: ['read:profile', 'read:payments'],
 *       audience: 'erify-api'
 *     };
 *     
 *     const authRequest = await buildAuthorizationUrl(config);
 *     return Response.redirect(authRequest.authUrl);
 *   }
 * };
 * ```
 */
export class ERIFYOAuthLogin {
  constructor(private readonly config: OAuth2Config) {}

  async initiateLogin(customState?: string): Promise<AuthorizationRequest> {
    return buildAuthorizationUrl(this.config, customState);
  }

  async completeLogin(
    code: string,
    state: string,
    receivedState: string,
    codeVerifier: string
  ): Promise<TokenResponse> {
    return exchangeCodeForToken(this.config, code, codeVerifier, state, receivedState);
  }

  async createInternalToken(
    userPayload: Record<string, unknown>,
    secret: string
  ): Promise<string> {
    return createSecureJWT(userPayload, secret);
  }
}