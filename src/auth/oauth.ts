import { OAuthConfig, OAuthProvider, AuthError } from '../types';

/**
 * ERIFY™ OAuth Flow Implementation
 * Supports Google, GitHub, Microsoft, Discord, and custom providers
 */

export class ErifyOAuth {
  private config: OAuthConfig;

  constructor(config: OAuthConfig) {
    this.config = config;
  }

  /**
   * Generate OAuth authorization URL
   */
  getAuthUrl(provider: string, state?: string): string {
    const providerConfig = this.config[provider];
    if (!providerConfig) {
      throw new AuthError(`Provider ${provider} not configured`);
    }

    const authUrls = {
      google: 'https://accounts.google.com/o/oauth2/v2/auth',
      github: 'https://github.com/login/oauth/authorize',
      microsoft: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
      discord: 'https://discord.com/api/oauth2/authorize',
    };

    const baseUrl = authUrls[provider as keyof typeof authUrls];
    if (!baseUrl) {
      throw new AuthError(`Unsupported provider: ${provider}`);
    }

    const params = new URLSearchParams({
      client_id: providerConfig.clientId,
      redirect_uri: providerConfig.redirectUri,
      scope: providerConfig.scopes.join(' '),
      response_type: 'code',
      ...(state && { state }),
    });

    return `${baseUrl}?${params.toString()}`;
  }

  /**
   * Exchange authorization code for access token
   */
  async exchangeCodeForToken(
    provider: string,
    code: string
  ): Promise<{ accessToken: string; refreshToken?: string }> {
    const providerConfig = this.config[provider];
    if (!providerConfig) {
      throw new AuthError(`Provider ${provider} not configured`);
    }

    const tokenUrls = {
      google: 'https://oauth2.googleapis.com/token',
      github: 'https://github.com/login/oauth/access_token',
      microsoft: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
      discord: 'https://discord.com/api/oauth2/token',
    };

    const tokenUrl = tokenUrls[provider as keyof typeof tokenUrls];
    if (!tokenUrl) {
      throw new AuthError(`Unsupported provider: ${provider}`);
    }

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: new URLSearchParams({
        client_id: providerConfig.clientId,
        client_secret: providerConfig.clientSecret!,
        code,
        redirect_uri: providerConfig.redirectUri,
        grant_type: 'authorization_code',
      }),
    });

    if (!response.ok) {
      throw new AuthError(`Token exchange failed: ${response.statusText}`);
    }

    const data = await response.json() as { access_token: string; refresh_token?: string };
    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
    };
  }

  /**
   * Get user info from OAuth provider
   */
  async getUserInfo(provider: string, accessToken: string): Promise<any> {
    const userInfoUrls = {
      google: 'https://www.googleapis.com/oauth2/v2/userinfo',
      github: 'https://api.github.com/user',
      microsoft: 'https://graph.microsoft.com/v1.0/me',
      discord: 'https://discord.com/api/users/@me',
    };

    const userInfoUrl = userInfoUrls[provider as keyof typeof userInfoUrls];
    if (!userInfoUrl) {
      throw new AuthError(`Unsupported provider: ${provider}`);
    }

    const response = await fetch(userInfoUrl, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    if (!response.ok) {
      throw new AuthError(`Failed to get user info: ${response.statusText}`);
    }

    return response.json();
  }
}

/**
 * Quick OAuth setup for common providers
 */
export const createOAuthConfig = (
  providers: Partial<Record<string, Partial<OAuthProvider>>>
): OAuthConfig => {
  const defaultScopes = {
    google: ['openid', 'email', 'profile'],
    github: ['user:email'],
    microsoft: ['openid', 'email', 'profile'],
    discord: ['identify', 'email'],
  };

  const config: OAuthConfig = {};

  Object.entries(providers).forEach(([name, provider]) => {
    if (provider?.clientId && provider?.redirectUri) {
      config[name] = {
        name,
        clientId: provider.clientId,
        clientSecret: provider.clientSecret,
        redirectUri: provider.redirectUri,
        scopes: provider.scopes || defaultScopes[name as keyof typeof defaultScopes] || [],
      };
    }
  });

  return config;
};

/**
 * Example usage snippets
 */
export const oauthExamples = {
  // Basic setup
  basicSetup: `
const oauthConfig = createOAuthConfig({
  google: {
    clientId: process.env.GOOGLE_CLIENT_ID!,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
    redirectUri: 'https://yourapp.com/auth/google/callback',
  },
  github: {
    clientId: process.env.GITHUB_CLIENT_ID!,
    clientSecret: process.env.GITHUB_CLIENT_SECRET!,
    redirectUri: 'https://yourapp.com/auth/github/callback',
  },
});

const oauth = new ErifyOAuth(oauthConfig);
  `,

  // Express.js integration
  expressIntegration: `
app.get('/auth/:provider', (req, res) => {
  const { provider } = req.params;
  const state = generateRandomState();
  req.session.oauthState = state;
  
  const authUrl = oauth.getAuthUrl(provider, state);
  res.redirect(authUrl);
});

app.get('/auth/:provider/callback', async (req, res) => {
  const { provider } = req.params;
  const { code, state } = req.query;
  
  if (state !== req.session.oauthState) {
    return res.status(400).json({ error: 'Invalid state' });
  }
  
  try {
    const tokens = await oauth.exchangeCodeForToken(provider, code);
    const userInfo = await oauth.getUserInfo(provider, tokens.accessToken);
    
    // Store user info in session or database
    req.session.user = userInfo;
    res.redirect('/dashboard');
  } catch (error) {
    res.status(401).json({ error: error.message });
  }
});
  `,
};