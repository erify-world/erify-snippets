# ERIFY™ Snippets

[![npm version](https://badge.fury.io/js/%40erify%2Fsnippets.svg)](https://badge.fury.io/js/%40erify%2Fsnippets)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-orange.svg)](https://workers.cloudflare.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Luxury ERIFY™ Snippets Library**: World-class OAuth flows, session management, payment processing, and validation for Cloudflare, Node.js, and Fintech ecosystems. Built for ERIFY™ Technologies, ERIVOX™, AVERIZY™, and modern applications.

## ✨ Features

- 🔐 **Complete OAuth Integration** - Google, GitHub, Microsoft, Discord + custom providers
- 🍪 **Advanced Session Management** - JWT, cookies, secure storage with multiple backends
- 💳 **Multi-Provider Payments** - Stripe, PayPal with webhook handling
- ✅ **Comprehensive Validation** - Zod schemas, input sanitization, file uploads
- ⚡ **Cloudflare Workers Ready** - Edge computing, KV storage, R2 integration
- 🛡️ **Security First** - Rate limiting, CORS, security headers, authentication middleware
- 📦 **TypeScript Native** - Full type safety and IntelliSense support
- 🎯 **Production Ready** - Battle-tested patterns for fintech and enterprise

## 🚀 Quick Start

```bash
npm install @erify/snippets
```

### OAuth Flow (Express.js)

```typescript
import { ErifyOAuth, createOAuthConfig } from '@erify/snippets';

const oauthConfig = createOAuthConfig({
  google: {
    clientId: process.env.GOOGLE_CLIENT_ID!,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
    redirectUri: 'https://yourapp.com/auth/google/callback',
  },
});

const oauth = new ErifyOAuth(oauthConfig);

// Initiate OAuth flow
app.get('/auth/google', (req, res) => {
  const authUrl = oauth.getAuthUrl('google', 'random-state');
  res.redirect(authUrl);
});

// Handle callback
app.get('/auth/google/callback', async (req, res) => {
  const tokens = await oauth.exchangeCodeForToken('google', req.query.code);
  const userInfo = await oauth.getUserInfo('google', tokens.accessToken);
  // Create session and redirect...
});
```

### JWT Authentication

```typescript
import { ErifyJWT, createJWTConfig } from '@erify/snippets';

const jwtConfig = createJWTConfig(process.env.JWT_SECRET!);
const jwtManager = new ErifyJWT(jwtConfig);

// Generate tokens
const tokens = jwtManager.generateTokenPair({
  userId: 'user123',
  email: 'user@example.com',
  roles: ['user'],
});

// Verify token
const user = jwtManager.verifyToken(tokens.accessToken);
```

### Payment Processing

```typescript
import { 
  ErifyPaymentManager, 
  StripePaymentProvider,
  PayPalPaymentProvider 
} from '@erify/snippets';

const paymentManager = new ErifyPaymentManager();
paymentManager.addProvider('stripe', new StripePaymentProvider(process.env.STRIPE_SECRET_KEY!));

// Create payment
const payment = await paymentManager.createPayment('stripe', {
  amount: 29.99,
  currency: 'usd',
  description: 'Premium subscription',
});
```

### Validation

```typescript
import { ErifyValidator, validateEmail, validatePassword } from '@erify/snippets';

// Schema validation
const result = ErifyValidator.validate(
  ErifyValidator.userRegistrationSchema,
  userData
);

// Individual validators
const emailResult = validateEmail('user@example.com');
const passwordResult = validatePassword('SecurePass123!');
```

### Cloudflare Workers

```typescript
import { CloudflareWorkers, CloudflareKV } from '@erify/snippets';

export default {
  async fetch(request: Request, env: any): Promise<Response> {
    // Handle CORS
    const corsResponse = CloudflareWorkers.handleCORS(request);
    if (corsResponse) return corsResponse;

    // Rate limiting
    const rateLimit = await CloudflareWorkers.rateLimit(
      env.KV_NAMESPACE,
      CloudflareWorkers.getClientIP(request),
      100, // requests
      60   // per minute
    );

    if (!rateLimit.allowed) {
      return CloudflareWorkers.jsonResponse(
        { error: 'Rate limit exceeded' },
        429
      );
    }

    return CloudflareWorkers.jsonResponse({ message: 'Hello World!' });
  }
};
```

## 📚 Complete Examples

### Express.js Full Authentication App
- [Complete OAuth + JWT implementation](./src/examples/express-auth.ts)
- Registration, login, protected routes
- Session management and security middleware

### Payment Processing Server
- [Multi-provider payment handling](./src/examples/payment-flow.ts)
- Stripe and PayPal integration
- Webhook processing and analytics

### Cloudflare Workers OAuth
- [Edge OAuth implementation](./src/examples/cloudflare-oauth-worker.ts)
- KV storage for sessions
- Rate limiting and security

## 🏗️ Architecture

```
@erify/snippets
├── auth/                 # OAuth, JWT, middleware
├── session/             # Session management
├── payments/            # Multi-provider payments
├── validation/          # Input validation & schemas
├── cloudflare/          # Workers, KV, R2 utilities
├── types/               # TypeScript definitions
└── examples/            # Complete applications
```

## 🔧 API Reference

### Authentication

#### `ErifyOAuth`
Complete OAuth 2.0 implementation supporting multiple providers.

```typescript
class ErifyOAuth {
  constructor(config: OAuthConfig)
  getAuthUrl(provider: string, state?: string): string
  exchangeCodeForToken(provider: string, code: string): Promise<TokenResponse>
  getUserInfo(provider: string, accessToken: string): Promise<UserInfo>
}
```

#### `ErifyJWT`
Secure JWT token management with refresh token support.

```typescript
class ErifyJWT {
  constructor(config: JWTConfig)
  generateAccessToken(payload: SessionData): string
  generateRefreshToken(payload: Pick<SessionData, 'userId'>): string
  generateTokenPair(payload: SessionData): TokenPair
  verifyToken(token: string): SessionData
  refreshAccessToken(refreshToken: string, newPayload: SessionData): string
}
```

### Session Management

#### `ErifySessionManager`
Flexible session management with multiple storage backends.

```typescript
class ErifySessionManager {
  constructor(config: SessionConfig, store: SessionStore)
  createSession(data: SessionData): Promise<string>
  getSession(sessionId: string): Promise<SessionData | null>
  updateSession(sessionId: string, data: Partial<SessionData>): Promise<void>
  destroySession(sessionId: string): Promise<void>
  regenerateSession(oldSessionId: string): Promise<string>
}
```

Storage options:
- `MemorySessionStore` - Development/testing
- `RedisSessionStore` - Production Redis backend
- `DatabaseSessionStore` - SQL database storage

### Payments

#### `ErifyPaymentManager`
Unified payment processing across multiple providers.

```typescript
class ErifyPaymentManager {
  addProvider(name: string, provider: PaymentProvider): void
  createPayment(provider: string, intent: PaymentIntent): Promise<PaymentResult>
  confirmPayment(provider: string, paymentId: string): Promise<PaymentResult>
  handleWebhook(provider: string, payload: any, signature?: string): Promise<any>
}
```

Supported providers:
- **Stripe** - Credit cards, wallets, bank transfers
- **PayPal** - PayPal accounts, credit cards
- **Custom** - Extensible provider interface

### Validation

#### `ErifyValidator`
Schema-based validation with Zod integration.

```typescript
class ErifyValidator {
  static userRegistrationSchema: ZodSchema
  static paymentSchema: ZodSchema
  static oauthCallbackSchema: ZodSchema
  static validate<T>(schema: ZodSchema<T>, data: unknown): ValidationResult
  static sanitize(input: string): string
  static createValidationMiddleware<T>(schema: ZodSchema<T>): Middleware
}
```

Individual validators:
- `validateEmail(email: string)`
- `validatePassword(password: string, options?)`
- `validatePhoneNumber(phone: string, countryCode?)`
- `validateURL(url: string, options?)`
- `validateCreditCard(cardNumber: string)`
- `validateFileUpload(file, options?)`

### Cloudflare Integration

#### `CloudflareWorkers`
Edge computing utilities for Cloudflare Workers.

```typescript
class CloudflareWorkers {
  static createCORSHeaders(origin?: string): HeadersInit
  static handleCORS(request: Request): Response | null
  static jsonResponse(data: any, status?: number, origin?: string): Response
  static extractBearerToken(request: Request): string | null
  static getClientIP(request: Request): string
  static getCountryCode(request: Request): string | null
  static rateLimit(kv: KVNamespace, identifier: string, limit: number, window: number): Promise<RateResult>
}
```

#### `CloudflareKV`
Key-value storage wrapper for sessions and caching.

```typescript
class CloudflareKV {
  constructor(kv: KVNamespace)
  setSession(sessionId: string, data: any, ttl: number): Promise<void>
  getSession(sessionId: string): Promise<any | null>
  deleteSession(sessionId: string): Promise<void>
  setOAuthState(state: string, data: any, ttl?: number): Promise<void>
  consumeOAuthState(state: string): Promise<any | null>
  cacheResponse(key: string, data: any, ttl: number): Promise<void>
  getCachedResponse(key: string): Promise<any | null>
}
```

#### `CloudflareR2`
Object storage for file uploads and assets.

```typescript
class CloudflareR2 {
  constructor(r2: R2Bucket)
  uploadFile(key: string, file: ArrayBuffer | Uint8Array | string, options?): Promise<void>
  downloadFile(key: string): Promise<R2Object | null>
  deleteFile(key: string): Promise<void>
  getFileMetadata(key: string): Promise<R2Object | null>
  listFiles(prefix?: string, limit?: number): Promise<R2Objects>
}
```

## 🛡️ Security Features

- **CORS Protection** - Configurable origin validation
- **Rate Limiting** - IP-based and user-based limits
- **Security Headers** - HSTS, CSP, X-Frame-Options
- **JWT Security** - Secure token generation and validation
- **Input Sanitization** - XSS and injection protection
- **Password Validation** - Strength requirements and hashing
- **OAuth State Protection** - CSRF protection for OAuth flows
- **Session Security** - Secure cookie configuration

## 🌍 Production Deployment

### Environment Variables

```bash
# Authentication
JWT_SECRET=your-super-secure-jwt-secret
SESSION_SECRET=your-session-secret

# OAuth Providers
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# Payment Providers
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
PAYPAL_CLIENT_ID=your-paypal-client-id
PAYPAL_CLIENT_SECRET=your-paypal-client-secret

# Cloudflare
CLOUDFLARE_ACCOUNT_ID=your-account-id
CLOUDFLARE_API_TOKEN=your-api-token
```

### Cloudflare Workers Setup

```bash
# Install Wrangler CLI
npm install -g wrangler

# Configure your worker
wrangler init my-erify-worker
cp src/examples/cloudflare-oauth-worker.ts my-erify-worker/src/index.ts

# Deploy
wrangler publish
```

### Express.js Deployment

```bash
# Build the project
npm run build

# Start production server
NODE_ENV=production npm start
```

## 📊 Performance & Scalability

- **Edge Deployment** - Deploy on Cloudflare's global network
- **Caching Strategies** - Built-in response caching
- **Connection Pooling** - Efficient database connections
- **Rate Limiting** - Protect against abuse
- **Session Optimization** - Multiple storage backends
- **Payment Webhooks** - Reliable async processing

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md).

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙋‍♂️ Support

- **Documentation**: [Full API docs](https://docs.erify.world/snippets)
- **Examples**: See `/src/examples/` directory
- **Issues**: [GitHub Issues](https://github.com/erify-world/erify-snippets/issues)
- **Discord**: [ERIFY™ Community](https://discord.gg/erify)

---

**Built with ❤️ by ERIFY™ Technologies**

For ERIVOX™, AVERIZY™, and the modern web.
