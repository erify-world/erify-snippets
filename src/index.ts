/**
 * ERIFY™ Snippets Library
 * 
 * Luxury collection of production-ready TypeScript snippets for OAuth, session management,
 * payments, and validation designed for Cloudflare Workers, Node.js, and fintech ecosystems.
 * 
 * @author Yahaya Ibrahim | ERIFY™ Founder
 * @license MIT
 * @version 1.0.0
 */

// OAuth implementations
export {
  OAuth2Config,
  PKCEPair,
  AuthorizationRequest,
  TokenResponse,
  generateCodeVerifier,
  createCodeChallenge,
  generateState,
  createPKCEPair,
  buildAuthorizationUrl,
  exchangeCodeForToken,
  createSecureJWT,
  ERIFYOAuthLogin
} from './oauth/login.js';

export {
  RefreshTokenConfig,
  RefreshTokenResponse,
  TokenValidationResult,
  refreshAccessToken,
  validateJWTToken,
  isTokenExpiringSoon,
  encryptTokenData,
  decryptTokenData,
  ERIFYTokenRefresh
} from './oauth/refresh.js';

// Session management
export {
  SessionConfig,
  SessionData,
  EncryptedSession,
  generateSecureSessionId,
  createSessionSignature,
  encryptSessionData,
  createSessionCookie,
  validateSessionData,
  ERIFYSessionCreator
} from './session/create.js';

export {
  ValidationResult,
  SecurityCheck,
  verifySessionSignature,
  decryptSessionData,
  performSecurityChecks,
  validateSessionStructure,
  extractSessionId,
  ERIFYSessionValidator
} from './session/validate.js';

// Payment processing
export {
  PaymentConfig,
  CheckoutRequest,
  CheckoutSession,
  PaymentMethod,
  generatePaymentSessionId,
  validatePaymentAmount,
  createPaymentHash,
  sanitizeCustomerData,
  ERIFYPaymentCheckout
} from './payments/checkout.js';

export {
  PaymentVerificationResult,
  WebhookEvent,
  PaymentIntent,
  Charge,
  Subscription,
  PaymentStatus,
  ChargeStatus,
  SubscriptionStatus,
  verifyWebhookSignature,
  analyzeFraudRisk,
  validatePaymentIntent,
  ERIFYPaymentVerifier
} from './payments/verify.js';

// Version information
export const ERIFY_SNIPPETS_VERSION = '1.0.0';
export const ERIFY_SNIPPETS_NAME = '@erify/snippets';

/**
 * Library information and metadata
 */
export const ERIFY_LIBRARY_INFO = {
  name: ERIFY_SNIPPETS_NAME,
  version: ERIFY_SNIPPETS_VERSION,
  description: 'Luxury ERIFY™ Snippets Library: World-class OAuth, session, payments, and validation',
  author: 'Yahaya Ibrahim | ERIFY™ Founder',
  ecosystem: 'ERIFY™ Technologies',
  platforms: ['Cloudflare Workers', 'Node.js', 'Fintech'],
  license: 'MIT',
  repository: 'https://github.com/erify-world/erify-snippets'
} as const;