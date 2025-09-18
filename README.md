# ERIFY™ Snippets

**Luxury ERIFY™ Snippets Library: World-class OAuth, session, payments, and validation for Cloudflare, Node.js, and Fintech ecosystems.**

[![TypeScript](https://img.shields.io/badge/TypeScript-5.3+-blue.svg)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![ERIFY™](https://img.shields.io/badge/Built%20by-ERIFY™%20Technologies-luxury.svg)](https://erify.world)

> Production-ready TypeScript snippets for the ERIFY™ Technologies ecosystem, designed for luxury fintech applications with enterprise-grade security and scalability.

## 🚀 Features

- **OAuth 2.0 + PKCE**: Secure authentication flows with token refresh
- **Session Management**: Strong session creation and validation with encryption  
- **Payment Processing**: PCI-compliant checkout and verification
- **Cloudflare Workers**: Optimized for edge computing and serverless
- **TypeScript**: Full type safety with strict compilation
- **Security First**: Built with fintech security standards in mind

## 📦 Installation

```bash
npm install @erify/snippets
```

## 🏗️ Quick Start

### OAuth Authentication

```typescript
import { ERIFYOAuthLogin } from '@erify/snippets';

const oauthConfig = {
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
  redirectUri: 'https://app.erify.world/auth/callback',
  authorizationUrl: 'https://auth.erify.world/oauth/authorize',
  tokenUrl: 'https://auth.erify.world/oauth/token',
  scopes: ['read:profile', 'write:payments'],
  audience: 'erify-api'
};

const oauth = new ERIFYOAuthLogin(oauthConfig);

// Initiate login
const authRequest = await oauth.initiateLogin();
console.log('Redirect to:', authRequest.authUrl);

// Complete login (in callback handler)
const tokens = await oauth.completeLogin(
  code, 
  state, 
  receivedState, 
  codeVerifier
);
```

### Session Management

```typescript
import { ERIFYSessionCreator, ERIFYSessionValidator } from '@erify/snippets';

const sessionConfig = {
  secret: 'your-session-secret',
  expirationMs: 24 * 60 * 60 * 1000, // 24 hours
  secureCookies: true,
  sameSite: 'strict' as const
};

const sessionCreator = new ERIFYSessionCreator(sessionConfig);
const sessionValidator = new ERIFYSessionValidator(sessionConfig);

// Create session
const session = await sessionCreator.createSession({
  userId: 'user123',
  email: 'user@erify.world',
  role: 'premium',
  permissions: ['read:profile', 'write:data'],
  ipAddress: undefined,
  userAgent: undefined,
  metadata: undefined
});

// Validate session
const validation = await sessionValidator.validateSession(session);
if (validation.isValid) {
  console.log('Welcome back!', validation.sessionData?.email);
}
```

### Payment Processing

```typescript
import { ERIFYPaymentCheckout, ERIFYPaymentVerifier } from '@erify/snippets';

const paymentConfig = {
  apiKey: 'pk_live_...',
  secretKey: 'sk_live_...',
  environment: 'production' as const,
  currency: 'USD',
  webhookSecret: 'whsec_...'
};

const checkout = new ERIFYPaymentCheckout(paymentConfig);
const verifier = new ERIFYPaymentVerifier(paymentConfig);

// Create checkout session
const checkoutSession = await checkout.createCheckoutSession({
  amount: 2999, // $29.99 in cents
  currency: 'USD',
  description: 'ERIFY™ Premium Subscription',
  customerEmail: 'user@erify.world',
  paymentMethods: ['card', 'digital_wallet']
});

// Verify payment
const verification = await verifier.verifyPaymentIntent(
  checkoutSession.paymentIntentId
);
```

## 🌐 Cloudflare Workers

This library is optimized for Cloudflare Workers:

```typescript
// worker.ts
import { ERIFYOAuthLogin, ERIFYSessionCreator } from '@erify/snippets';

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    
    if (url.pathname === '/auth/login') {
      const oauth = new ERIFYOAuthLogin({
        clientId: env.OAUTH_CLIENT_ID,
        clientSecret: env.OAUTH_CLIENT_SECRET,
        redirectUri: 'https://app.erify.world/auth/callback',
        authorizationUrl: 'https://auth.erify.world/oauth/authorize',
        tokenUrl: 'https://auth.erify.world/oauth/token',
        scopes: ['read:profile'],
        audience: 'erify-api'
      });
      
      const authRequest = await oauth.initiateLogin();
      return Response.redirect(authRequest.authUrl);
    }
    
    return new Response('ERIFY™ API', { status: 200 });
  }
};
```

## 🔒 Security Features

- **PKCE Support**: Prevents authorization code interception
- **Token Rotation**: Automatic refresh token rotation
- **Session Encryption**: AES-GCM encryption for session data
- **Signature Verification**: HMAC signatures for data integrity
- **Rate Limiting**: Built-in protection against abuse
- **PCI Compliance**: Payment data sanitization and validation

## 📚 API Reference

### OAuth Module

- `ERIFYOAuthLogin` - Complete OAuth 2.0 login flow
- `ERIFYTokenRefresh` - Token refresh and validation
- `generateCodeVerifier()` - PKCE code verifier generation
- `createCodeChallenge()` - SHA256 code challenge creation

### Session Module

- `ERIFYSessionCreator` - Secure session creation
- `ERIFYSessionValidator` - Session validation and security checks
- `generateSecureSessionId()` - Cryptographically secure session IDs
- `encryptSessionData()` - AES-GCM session encryption

### Payment Module

- `ERIFYPaymentCheckout` - Payment processing and checkout
- `ERIFYPaymentVerifier` - Payment verification and webhooks
- `validatePaymentAmount()` - Fintech-grade amount validation
- `analyzeFraudRisk()` - Fraud detection and scoring

## 🏢 Enterprise Features

- **Multi-tenant Architecture**: Isolated data per organization
- **Audit Logging**: Comprehensive activity tracking
- **Compliance**: SOC2, PCI DSS, and GDPR ready
- **Monitoring**: Built-in performance and error tracking
- **Scalability**: Designed for high-throughput applications

## 📖 Documentation

- [Validation & Security Guide](./docs/validation.md) - Complete security patterns and best practices
- [Cloudflare Workers Setup](./docs/cloudflare.md) - Edge deployment guide
- [API Reference](./docs/api.md) - Complete API documentation
- [Examples](./examples/) - Real-world usage examples

## 🧪 Development

```bash
# Install dependencies
npm install

# Build the library
npm run build

# Run linting
npm run lint

# Fix linting issues
npm run lint:fix
```

## 🌟 ERIFY™ Ecosystem

This library is part of the luxury ERIFY™ Technologies ecosystem:

- **[ERIFY™ Core](https://erify.world)** - Primary verification platform
- **[ERIVOX™](https://erivox.com)** - Voice verification and communication
- **[AVERIZY™](https://averizy.tech)** - Advanced identity verification

## 🤝 Contributing

We welcome contributions to the ERIFY™ Snippets library! Please read our contributing guidelines and submit pull requests to our repository.

## 📄 License

MIT © 2025 Yahaya Ibrahim | ERIFY™ Founder

## 🏆 Built with Luxury Standards

ERIFY™ Technologies is committed to delivering world-class financial technology solutions with uncompromising security, performance, and developer experience.

---

**For enterprise support and custom implementations, contact our team at [enterprise@erify.world](mailto:enterprise@erify.world)**
