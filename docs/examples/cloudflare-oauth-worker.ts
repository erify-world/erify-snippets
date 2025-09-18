/**
 * ERIFY™ Cloudflare Workers OAuth Example
 * Complete OAuth flow implementation for Cloudflare Workers
 */

import {
  CloudflareWorkers,
  CloudflareKV,
  ErifyJWT,
  createJWTConfig,
} from '../index';

interface Env {
  SESSIONS_KV: KVNamespace;
  OAUTH_STATES_KV: KVNamespace;
  JWT_SECRET: string;
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
  ALLOWED_ORIGINS: string;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // Handle CORS preflight
    const corsResponse = CloudflareWorkers.handleCORS(request);
    if (corsResponse) return corsResponse;

    const url = new URL(request.url);
    const origin = request.headers.get('Origin');
    const allowedOrigins = env.ALLOWED_ORIGINS.split(',');

    // Initialize utilities
    const sessionsKV = new CloudflareKV(env.SESSIONS_KV);
    const statesKV = new CloudflareKV(env.OAUTH_STATES_KV);
    const jwtConfig = createJWTConfig(env.JWT_SECRET);
    const jwtManager = new ErifyJWT(jwtConfig);

    try {
      // Rate limiting
      const clientIP = CloudflareWorkers.getClientIP(request);
      const rateLimit = await CloudflareWorkers.rateLimit(
        env.SESSIONS_KV,
        `rate_limit:${clientIP}`,
        100, // 100 requests
        300  // per 5 minutes
      );

      if (!rateLimit.allowed) {
        return CloudflareWorkers.jsonResponse(
          {
            error: 'Rate limit exceeded',
            resetTime: rateLimit.resetTime,
          },
          429,
          origin
        );
      }

      // Routes
      switch (url.pathname) {
        case '/auth/google':
          return handleOAuthInitiation('google', env, statesKV, url.origin);

        case '/auth/github':
          return handleOAuthInitiation('github', env, statesKV, url.origin);

        case '/auth/google/callback':
          return handleOAuthCallback('google', request, env, statesKV, jwtManager, origin);

        case '/auth/github/callback':
          return handleOAuthCallback('github', request, env, statesKV, jwtManager, origin);

        case '/auth/me':
          return handleGetUser(request, jwtManager, origin);

        case '/auth/refresh':
          return handleTokenRefresh(request, jwtManager, origin);

        case '/auth/logout':
          return handleLogout(request, sessionsKV, origin);

        default:
          return CloudflareWorkers.jsonResponse(
            { error: 'Not found' },
            404,
            origin
          );
      }
    } catch (error) {
      console.error('Worker error:', error);
      return CloudflareWorkers.jsonResponse(
        { error: 'Internal server error' },
        500,
        origin
      );
    }
  },
};

async function handleOAuthInitiation(
  provider: string,
  env: Env,
  statesKV: CloudflareKV,
  origin: string
): Promise<Response> {
  const state = crypto.randomUUID();
  const nonce = crypto.randomUUID();

  // Store state for verification
  await statesKV.setOAuthState(state, {
    provider,
    nonce,
    createdAt: Date.now(),
  }, 600); // 10 minutes

  const authUrls = {
    google: 'https://accounts.google.com/o/oauth2/v2/auth',
    github: 'https://github.com/login/oauth/authorize',
  };

  const clientIds = {
    google: env.GOOGLE_CLIENT_ID,
    github: env.GITHUB_CLIENT_ID,
  };

  const scopes = {
    google: 'openid email profile',
    github: 'user:email',
  };

  const redirectUris = {
    google: `${origin}/auth/google/callback`,
    github: `${origin}/auth/github/callback`,
  };

  const authUrl = new URL(authUrls[provider as keyof typeof authUrls]);
  authUrl.searchParams.set('client_id', clientIds[provider as keyof typeof clientIds]);
  authUrl.searchParams.set('redirect_uri', redirectUris[provider as keyof typeof redirectUris]);
  authUrl.searchParams.set('scope', scopes[provider as keyof typeof scopes]);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('state', state);

  if (provider === 'google') {
    authUrl.searchParams.set('nonce', nonce);
  }

  return Response.redirect(authUrl.toString(), 302);
}

async function handleOAuthCallback(
  provider: string,
  request: Request,
  env: Env,
  statesKV: CloudflareKV,
  jwtManager: ErifyJWT,
  origin: string | null
): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const error = url.searchParams.get('error');

  if (error) {
    return CloudflareWorkers.jsonResponse(
      { error: `OAuth error: ${error}` },
      400,
      origin
    );
  }

  if (!code || !state) {
    return CloudflareWorkers.jsonResponse(
      { error: 'Missing code or state parameter' },
      400,
      origin
    );
  }

  // Verify state
  const stateData = await statesKV.consumeOAuthState(state);
  if (!stateData || stateData.provider !== provider) {
    return CloudflareWorkers.jsonResponse(
      { error: 'Invalid state parameter' },
      400,
      origin
    );
  }

  try {
    // Exchange code for token
    const tokenResponse = await exchangeCodeForToken(provider, code, env, url.origin);
    const userInfo = await getUserInfo(provider, tokenResponse.access_token);

    // Generate JWT tokens
    const tokens = jwtManager.generateTokenPair({
      userId: userInfo.id || userInfo.login,
      email: userInfo.email,
      name: userInfo.name,
      provider,
    });

    // Create session response
    const response = CloudflareWorkers.jsonResponse(
      {
        success: true,
        user: {
          id: userInfo.id || userInfo.login,
          email: userInfo.email,
          name: userInfo.name,
          avatar: userInfo.picture || userInfo.avatar_url,
        },
        tokens,
      },
      200,
      origin
    );

    // Set secure cookies
    const cookieOptions = {
      httpOnly: true,
      secure: true,
      sameSite: 'strict' as const,
      path: '/',
    };

    response.headers.append(
      'Set-Cookie',
      `auth_token=${tokens.accessToken}; ${Object.entries(cookieOptions)
        .map(([k, v]) => `${k}=${v}`)
        .join('; ')}; Max-Age=900` // 15 minutes
    );

    response.headers.append(
      'Set-Cookie',
      `refresh_token=${tokens.refreshToken}; ${Object.entries(cookieOptions)
        .map(([k, v]) => `${k}=${v}`)
        .join('; ')}; Max-Age=604800` // 7 days
    );

    return response;
  } catch (error) {
    console.error('OAuth callback error:', error);
    return CloudflareWorkers.jsonResponse(
      { error: 'Authentication failed' },
      400,
      origin
    );
  }
}

async function handleGetUser(
  request: Request,
  jwtManager: ErifyJWT,
  origin: string | null
): Promise<Response> {
  try {
    const token = CloudflareWorkers.extractBearerToken(request);
    if (!token) {
      return CloudflareWorkers.jsonResponse(
        { error: 'No authorization token provided' },
        401,
        origin
      );
    }

    const user = jwtManager.verifyToken(token);
    return CloudflareWorkers.jsonResponse(
      { user },
      200,
      origin
    );
  } catch (error) {
    return CloudflareWorkers.jsonResponse(
      { error: 'Invalid or expired token' },
      401,
      origin
    );
  }
}

async function handleTokenRefresh(
  request: Request,
  jwtManager: ErifyJWT,
  origin: string | null
): Promise<Response> {
  try {
    const body = await request.json() as { refreshToken: string };
    
    if (!body.refreshToken) {
      return CloudflareWorkers.jsonResponse(
        { error: 'Refresh token required' },
        400,
        origin
      );
    }

    // Verify refresh token
    const tokenData = jwtManager.verifyToken(body.refreshToken);
    
    // Generate new access token
    const newAccessToken = jwtManager.generateAccessToken({
      userId: tokenData.userId,
      email: tokenData.email,
      name: tokenData.name,
      provider: tokenData.provider,
    });

    return CloudflareWorkers.jsonResponse(
      { accessToken: newAccessToken },
      200,
      origin
    );
  } catch (error) {
    return CloudflareWorkers.jsonResponse(
      { error: 'Invalid refresh token' },
      401,
      origin
    );
  }
}

async function handleLogout(
  request: Request,
  sessionsKV: CloudflareKV,
  origin: string | null
): Promise<Response> {
  const response = CloudflareWorkers.jsonResponse(
    { success: true, message: 'Logged out successfully' },
    200,
    origin
  );

  // Clear cookies
  response.headers.append(
    'Set-Cookie',
    'auth_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT'
  );
  response.headers.append(
    'Set-Cookie',
    'refresh_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT'
  );

  return response;
}

async function exchangeCodeForToken(
  provider: string,
  code: string,
  env: Env,
  origin: string
): Promise<any> {
  const tokenUrls = {
    google: 'https://oauth2.googleapis.com/token',
    github: 'https://github.com/login/oauth/access_token',
  };

  const clientIds = {
    google: env.GOOGLE_CLIENT_ID,
    github: env.GITHUB_CLIENT_ID,
  };

  const clientSecrets = {
    google: env.GOOGLE_CLIENT_SECRET,
    github: env.GITHUB_CLIENT_SECRET,
  };

  const redirectUris = {
    google: `${origin}/auth/google/callback`,
    github: `${origin}/auth/github/callback`,
  };

  const response = await fetch(tokenUrls[provider as keyof typeof tokenUrls], {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: new URLSearchParams({
      client_id: clientIds[provider as keyof typeof clientIds],
      client_secret: clientSecrets[provider as keyof typeof clientSecrets],
      code,
      redirect_uri: redirectUris[provider as keyof typeof redirectUris],
      grant_type: 'authorization_code',
    }),
  });

  if (!response.ok) {
    throw new Error(`Token exchange failed: ${response.statusText}`);
  }

  return response.json();
}

async function getUserInfo(provider: string, accessToken: string): Promise<any> {
  const userInfoUrls = {
    google: 'https://www.googleapis.com/oauth2/v2/userinfo',
    github: 'https://api.github.com/user',
  };

  const response = await fetch(userInfoUrls[provider as keyof typeof userInfoUrls], {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  if (!response.ok) {
    throw new Error(`Failed to get user info: ${response.statusText}`);
  }

  return response.json();
}