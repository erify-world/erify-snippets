/**
 * ERIFY™ Cloudflare Integration
 * Workers, KV Storage, R2, and edge computing utilities
 */

// Type augmentation for better compatibility
type CFHeadersInit = Record<string, string> | Headers;

/**
 * Cloudflare Workers utilities
 */
export class CloudflareWorkers {
  /**
   * Create CORS headers for Workers
   */
  static createCORSHeaders(origin?: string): CFHeadersInit {
    return {
      'Access-Control-Allow-Origin': origin || '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400',
    };
  }

  /**
   * Handle CORS preflight requests
   */
  static handleCORS(request: Request): Response | null {
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 200,
        headers: CloudflareWorkers.createCORSHeaders(request.headers.get('Origin') || undefined),
      });
    }
    return null;
  }

  /**
   * Create JSON response with CORS headers
   */
  static jsonResponse(data: any, status = 200, origin?: string): Response {
    return new Response(JSON.stringify(data), {
      status,
      headers: {
        'Content-Type': 'application/json',
        ...CloudflareWorkers.createCORSHeaders(origin),
      },
    });
  }

  /**
   * Extract JWT token from Authorization header
   */
  static extractBearerToken(request: Request): string | null {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return null;
    }
    return authHeader.substring(7);
  }

  /**
   * Get client IP address from Cloudflare headers
   */
  static getClientIP(request: Request): string {
    return request.headers.get('CF-Connecting-IP') || 
           request.headers.get('X-Forwarded-For') || 
           'unknown';
  }

  /**
   * Get Cloudflare country code
   */
  static getCountryCode(request: Request): string | null {
    return request.headers.get('CF-IPCountry');
  }

  /**
   * Rate limiting using Cloudflare Workers
   */
  static async rateLimit(
    kv: any, // KVNamespace type not available in all contexts
    identifier: string,
    limit: number,
    window: number
  ): Promise<{ allowed: boolean; remaining: number; resetTime: number }> {
    const key = `rate_limit:${identifier}`;
    const now = Date.now();
    const windowStart = Math.floor(now / (window * 1000)) * (window * 1000);
    const windowKey = `${key}:${windowStart}`;

    const current = await kv.get(windowKey);
    const count = current ? parseInt(current) : 0;

    if (count >= limit) {
      return {
        allowed: false,
        remaining: 0,
        resetTime: windowStart + (window * 1000),
      };
    }

    await kv.put(windowKey, (count + 1).toString(), { expirationTtl: window });

    return {
      allowed: true,
      remaining: limit - count - 1,
      resetTime: windowStart + (window * 1000),
    };
  }
}

/**
 * Cloudflare KV Storage wrapper
 */
export class CloudflareKV {
  constructor(private kv: any) {} // KVNamespace

  /**
   * Store session data in KV
   */
  async setSession(sessionId: string, data: any, ttl: number): Promise<void> {
    await this.kv.put(`session:${sessionId}`, JSON.stringify(data), {
      expirationTtl: ttl,
    });
  }

  /**
   * Get session data from KV
   */
  async getSession(sessionId: string): Promise<any | null> {
    const data = await this.kv.get(`session:${sessionId}`);
    return data ? JSON.parse(data) : null;
  }

  /**
   * Delete session from KV
   */
  async deleteSession(sessionId: string): Promise<void> {
    await this.kv.delete(`session:${sessionId}`);
  }

  /**
   * Store OAuth state
   */
  async setOAuthState(state: string, data: any, ttl = 600): Promise<void> {
    await this.kv.put(`oauth_state:${state}`, JSON.stringify(data), {
      expirationTtl: ttl,
    });
  }

  /**
   * Get and delete OAuth state (one-time use)
   */
  async consumeOAuthState(state: string): Promise<any | null> {
    const data = await this.kv.get(`oauth_state:${state}`);
    if (data) {
      await this.kv.delete(`oauth_state:${state}`);
      return JSON.parse(data);
    }
    return null;
  }

  /**
   * Cache API responses
   */
  async cacheResponse(key: string, data: any, ttl: number): Promise<void> {
    await this.kv.put(`cache:${key}`, JSON.stringify(data), {
      expirationTtl: ttl,
    });
  }

  /**
   * Get cached response
   */
  async getCachedResponse(key: string): Promise<any | null> {
    const data = await this.kv.get(`cache:${key}`);
    return data ? JSON.parse(data) : null;
  }
}

/**
 * Cloudflare R2 Storage wrapper
 */
export class CloudflareR2 {
  constructor(private r2: any) {} // R2Bucket

  /**
   * Upload file to R2
   */
  async uploadFile(
    key: string,
    file: ArrayBuffer | Uint8Array | string,
    options: {
      contentType?: string;
      metadata?: Record<string, string>;
    } = {}
  ): Promise<void> {
    await this.r2.put(key, file, {
      httpMetadata: {
        contentType: options.contentType,
      },
      customMetadata: options.metadata,
    });
  }

  /**
   * Download file from R2
   */
  async downloadFile(key: string): Promise<any | null> { // R2Object
    return await this.r2.get(key);
  }

  /**
   * Delete file from R2
   */
  async deleteFile(key: string): Promise<void> {
    await this.r2.delete(key);
  }

  /**
   * Get file metadata
   */
  async getFileMetadata(key: string): Promise<any | null> { // R2Object
    return await this.r2.head(key);
  }

  /**
   * List files in bucket
   */
  async listFiles(prefix?: string, limit = 1000): Promise<any> { // R2Objects
    return await this.r2.list({
      prefix,
      limit,
    });
  }
}

/**
 * Cloudflare Durable Objects utilities
 */
export class DurableObjectHelper {
  /**
   * Create WebSocket connection handler
   */
  static createWebSocketHandler() {
    return class {
      connections = new Set<any>(); // WebSocket

      async fetch(request: Request): Promise<Response> {
        if (request.headers.get('Upgrade') === 'websocket') {
          // Note: This is a simplified example. In actual Cloudflare Workers,
          // WebSocketPair is available in the runtime.
          const response = new Response(null, { status: 101 });
          return response;
        }

        return new Response('Expected WebSocket', { status: 400 });
      }

      handleSession(webSocket: any) { // WebSocket
        this.connections.add(webSocket);

        webSocket.addEventListener('message', (event: any) => {
          const data = JSON.parse(event.data as string);
          this.handleMessage(webSocket, data);
        });

        webSocket.addEventListener('close', () => {
          this.connections.delete(webSocket);
        });
      }

      handleMessage(webSocket: any, data: any) { // WebSocket
        // Broadcast to all connections
        this.connections.forEach((conn) => {
          if (conn !== webSocket && conn.readyState === 1) { // OPEN
            conn.send(JSON.stringify(data));
          }
        });
      }

      broadcast(message: any) {
        const data = JSON.stringify(message);
        this.connections.forEach((conn) => {
          if (conn.readyState === 1) { // OPEN
            conn.send(data);
          }
        });
      }
    };
  }
}

/**
 * Example Cloudflare Workers
 */
export const cloudflareWorkerExamples = {
  // Basic OAuth Worker
  oauthWorker: `
export default {
  async fetch(request: Request, env: any): Promise<Response> {
    const corsResponse = CloudflareWorkers.handleCORS(request);
    if (corsResponse) return corsResponse;

    const url = new URL(request.url);
    const kv = new CloudflareKV(env.SESSIONS_KV);

    if (url.pathname === '/auth/google') {
      const state = crypto.randomUUID();
      await kv.setOAuthState(state, { provider: 'google' });
      
      const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
      authUrl.searchParams.set('client_id', env.GOOGLE_CLIENT_ID);
      authUrl.searchParams.set('redirect_uri', env.GOOGLE_REDIRECT_URI);
      authUrl.searchParams.set('scope', 'openid email profile');
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('state', state);

      return Response.redirect(authUrl.toString(), 302);
    }

    if (url.pathname === '/auth/callback') {
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');
      
      if (!code || !state) {
        return CloudflareWorkers.jsonResponse({ error: 'Missing parameters' }, 400);
      }

      const stateData = await kv.consumeOAuthState(state);
      if (!stateData) {
        return CloudflareWorkers.jsonResponse({ error: 'Invalid state' }, 400);
      }

      // Exchange code for token and create session
      // ... token exchange logic ...

      return CloudflareWorkers.jsonResponse({ success: true });
    }

    return CloudflareWorkers.jsonResponse({ error: 'Not found' }, 404);
  }
};
  `,

  // Rate-limited API Worker
  rateLimitedWorker: `
export default {
  async fetch(request: Request, env: any): Promise<Response> {
    const ip = CloudflareWorkers.getClientIP(request);
    const rateLimit = await CloudflareWorkers.rateLimit(
      env.RATE_LIMIT_KV,
      ip,
      100, // 100 requests
      60   // per minute
    );

    if (!rateLimit.allowed) {
      return CloudflareWorkers.jsonResponse(
        { 
          error: 'Rate limit exceeded',
          resetTime: rateLimit.resetTime 
        },
        429
      );
    }

    // Add rate limit headers
    const response = CloudflareWorkers.jsonResponse({ data: 'API response' });
    response.headers.set('X-RateLimit-Remaining', rateLimit.remaining.toString());
    response.headers.set('X-RateLimit-Reset', rateLimit.resetTime.toString());

    return response;
  }
};
  `,

  // File upload to R2 Worker
  fileUploadWorker: `
export default {
  async fetch(request: Request, env: any): Promise<Response> {
    if (request.method !== 'POST') {
      return CloudflareWorkers.jsonResponse({ error: 'Method not allowed' }, 405);
    }

    const token = CloudflareWorkers.extractBearerToken(request);
    if (!token) {
      return CloudflareWorkers.jsonResponse({ error: 'Unauthorized' }, 401);
    }

    const formData = await request.formData();
    const file = formData.get('file') as File;
    
    if (!file) {
      return CloudflareWorkers.jsonResponse({ error: 'No file provided' }, 400);
    }

    const r2 = new CloudflareR2(env.FILES_BUCKET);
    const key = \`uploads/\${crypto.randomUUID()}-\${file.name}\`;
    
    await r2.uploadFile(key, await file.arrayBuffer(), {
      contentType: file.type,
      metadata: {
        originalName: file.name,
        uploadedAt: new Date().toISOString(),
      },
    });

    return CloudflareWorkers.jsonResponse({
      success: true,
      key,
      size: file.size,
    });
  }
};
  `,
};