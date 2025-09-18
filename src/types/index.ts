// Core types for ERIFY™ Snippets Library

// OAuth Provider types
export interface OAuthProvider {
  name: string;
  clientId: string;
  clientSecret?: string;
  redirectUri: string;
  scopes: string[];
}

export interface OAuthConfig {
  google?: OAuthProvider;
  github?: OAuthProvider;
  microsoft?: OAuthProvider;
  discord?: OAuthProvider;
  [key: string]: OAuthProvider | undefined;
}

// Session types
export interface SessionConfig {
  secret: string;
  expiresIn: number;
  secure: boolean;
  httpOnly: boolean;
  sameSite: 'strict' | 'lax' | 'none';
}

export interface SessionData {
  userId: string;
  email?: string;
  roles?: string[];
  [key: string]: any;
}

// Payment types
export interface PaymentProvider {
  name: string;
  apiKey: string;
  webhookSecret?: string;
  environment: 'sandbox' | 'production';
}

export interface PaymentConfig {
  stripe?: PaymentProvider;
  paypal?: PaymentProvider;
  [key: string]: PaymentProvider | undefined;
}

export interface PaymentIntent {
  amount: number;
  currency: string;
  description?: string;
  metadata?: Record<string, string>;
}

// Validation types
export interface ValidationRule {
  field: string;
  type: 'string' | 'number' | 'email' | 'url' | 'date' | 'boolean';
  required?: boolean;
  min?: number;
  max?: number;
  pattern?: RegExp;
}

export interface ValidationResult {
  isValid: boolean;
  errors: string[];
  data?: any;
}

// Cloudflare types
export interface CloudflareConfig {
  accountId: string;
  apiToken: string;
  zoneId?: string;
}

export interface CloudflareKVConfig {
  namespaceId: string;
  preview?: boolean;
}

// Error types
export class ErifyError extends Error {
  constructor(
    message: string,
    public code: string,
    public statusCode: number = 500
  ) {
    super(message);
    this.name = 'ErifyError';
  }
}

export class AuthError extends ErifyError {
  constructor(message: string) {
    super(message, 'AUTH_ERROR', 401);
  }
}

export class ValidationError extends ErifyError {
  constructor(message: string) {
    super(message, 'VALIDATION_ERROR', 400);
  }
}

export class PaymentError extends ErifyError {
  constructor(message: string) {
    super(message, 'PAYMENT_ERROR', 402);
  }
}