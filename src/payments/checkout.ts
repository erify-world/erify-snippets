/**
 * ERIFY™ Payment Checkout Implementation
 * 
 * Secure payment processing with PCI compliance and fintech best practices
 * Designed for Cloudflare Workers, Node.js, and fintech ecosystems
 * 
 * @author Yahaya Ibrahim | ERIFY™ Founder
 * @license MIT
 */

export interface PaymentConfig {
  readonly apiKey: string;
  readonly secretKey: string;
  readonly environment: 'sandbox' | 'production';
  readonly currency: string;
  readonly webhookSecret?: string;
  readonly returnUrl?: string;
  readonly cancelUrl?: string;
}

export interface CheckoutRequest {
  readonly amount: number; // Amount in smallest currency unit (cents)
  readonly currency: string;
  readonly description: string;
  readonly customerEmail?: string;
  readonly customerId?: string;
  readonly paymentMethods: readonly string[];
  readonly metadata?: Record<string, string>;
  readonly expiresAt?: Date;
  readonly captureMethod?: 'automatic' | 'manual';
}

export interface CheckoutSession {
  readonly sessionId: string;
  readonly paymentIntentId: string;
  readonly clientSecret: string;
  readonly checkoutUrl: string;
  readonly status: 'pending' | 'processing' | 'completed' | 'failed' | 'expired';
  readonly amount: number;
  readonly currency: string;
  readonly createdAt: Date;
  readonly expiresAt: Date;
  readonly metadata: Record<string, string> | undefined;
}

export interface PaymentMethod {
  readonly type: 'card' | 'bank_transfer' | 'digital_wallet' | 'crypto';
  readonly provider: string;
  readonly enabled: boolean;
  readonly fees?: {
    readonly percentage: number;
    readonly fixed: number;
  };
}

/**
 * Generates secure payment session ID
 */
export function generatePaymentSessionId(): string {
  const timestamp = Date.now().toString(36);
  const randomBytes = new Uint8Array(16);
  crypto.getRandomValues(randomBytes);
  
  const randomString = Array.from(randomBytes, byte => 
    byte.toString(36).padStart(2, '0')
  ).join('');
  
  return `erify_ps_${timestamp}_${randomString}`;
}

/**
 * Validates payment amount according to fintech regulations
 */
export function validatePaymentAmount(
  amount: number,
  currency: string,
  limits?: {
    min?: number;
    max?: number;
  }
): { isValid: boolean; errors: string[] } {
  const errors: string[] = [];

  // Basic validation
  if (amount <= 0) {
    errors.push('Amount must be greater than zero');
  }

  if (!Number.isInteger(amount)) {
    errors.push('Amount must be an integer (smallest currency unit)');
  }

  // Currency-specific validation
  const currencyLimits = {
    USD: { min: 50, max: 999999999 }, // $0.50 - $9,999,999.99
    EUR: { min: 50, max: 999999999 },
    GBP: { min: 30, max: 999999999 },
    BTC: { min: 1000, max: 10000000000 } // Satoshis
  };

  const defaultLimits = currencyLimits[currency as keyof typeof currencyLimits] || 
                       { min: 1, max: 999999999 };

  const effectiveLimits = { ...defaultLimits, ...limits };

  if (amount < effectiveLimits.min) {
    errors.push(`Amount below minimum: ${effectiveLimits.min} ${currency}`);
  }

  if (amount > effectiveLimits.max) {
    errors.push(`Amount above maximum: ${effectiveLimits.max} ${currency}`);
  }

  return { isValid: errors.length === 0, errors };
}

/**
 * Creates payment hash for integrity verification
 */
export async function createPaymentHash(
  checkoutData: CheckoutRequest,
  secretKey: string
): Promise<string> {
  const encoder = new TextEncoder();
  const data = JSON.stringify({
    amount: checkoutData.amount,
    currency: checkoutData.currency,
    timestamp: Date.now()
  });

  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secretKey),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  return Array.from(new Uint8Array(signature), byte => 
    byte.toString(16).padStart(2, '0')
  ).join('');
}

/**
 * Sanitizes and validates customer data for PCI compliance
 */
export function sanitizeCustomerData(data: {
  email?: string;
  name?: string;
  phone?: string;
  address?: Record<string, string>;
}): Record<string, unknown> {
  const sanitized: Record<string, unknown> = {};

  // Email validation and sanitization
  if (data.email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (emailRegex.test(data.email)) {
      sanitized.email = data.email.toLowerCase().trim();
    }
  }

  // Name sanitization (remove potentially dangerous characters)
  if (data.name) {
    sanitized.name = data.name.replace(/[<>"']/g, '').trim().substring(0, 100);
  }

  // Phone sanitization
  if (data.phone) {
    sanitized.phone = data.phone.replace(/[^\d+\-\s()]/g, '').trim().substring(0, 20);
  }

  // Address sanitization
  if (data.address) {
    sanitized.address = {};
    for (const [key, value] of Object.entries(data.address)) {
      if (typeof value === 'string') {
        (sanitized.address as Record<string, string>)[key] = 
          value.replace(/[<>"']/g, '').trim().substring(0, 200);
      }
    }
  }

  return sanitized;
}

/**
 * Complete payment checkout implementation for ERIFY™ ecosystems
 * 
 * @example Cloudflare Workers usage:
 * ```typescript
 * export default {
 *   async fetch(request: Request, env: Env): Promise<Response> {
 *     const paymentProcessor = new ERIFYPaymentCheckout({
 *       apiKey: env.PAYMENT_API_KEY,
 *       secretKey: env.PAYMENT_SECRET_KEY,
 *       environment: 'production',
 *       currency: 'USD',
 *       webhookSecret: env.WEBHOOK_SECRET
 *     });
 *     
 *     const checkoutSession = await paymentProcessor.createCheckoutSession({
 *       amount: 2999, // $29.99
 *       currency: 'USD',
 *       description: 'ERIFY™ Premium Subscription',
 *       customerEmail: 'user@erify.world',
 *       paymentMethods: ['card', 'digital_wallet']
 *     });
 *     
 *     return Response.json(checkoutSession);
 *   }
 * };
 * ```
 */
export class ERIFYPaymentCheckout {
  private readonly baseUrl: string;

  constructor(private readonly config: PaymentConfig) {
    this.baseUrl = config.environment === 'production' 
      ? 'https://api.erify.world/payments'
      : 'https://sandbox-api.erify.world/payments';
  }

  async createCheckoutSession(request: CheckoutRequest): Promise<CheckoutSession> {
    // Validate amount
    const amountValidation = validatePaymentAmount(request.amount, request.currency);
    if (!amountValidation.isValid) {
      throw new Error(`ERIFY™ Payment: ${amountValidation.errors.join(', ')}`);
    }

    const sessionId = generatePaymentSessionId();
    const expiresAt = request.expiresAt || new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
    const paymentHash = await createPaymentHash(request, this.config.secretKey);

    // Create payment intent
    const paymentIntentPayload = {
      amount: request.amount,
      currency: request.currency,
      description: request.description,
      customer_email: request.customerEmail,
      customer_id: request.customerId,
      payment_methods: request.paymentMethods,
      capture_method: request.captureMethod || 'automatic',
      metadata: {
        ...request.metadata,
        session_id: sessionId,
        hash: paymentHash
      }
    };

    const response = await fetch(`${this.baseUrl}/payment-intents`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.config.apiKey}`,
        'Content-Type': 'application/json',
        'User-Agent': 'ERIFY-Snippets/1.0.0',
        'Idempotency-Key': sessionId
      },
      body: JSON.stringify(paymentIntentPayload)
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`ERIFY™ Payment: Failed to create payment intent: ${response.status} ${errorText}`);
    }

    const paymentIntent = await response.json() as {
      id: string;
      client_secret: string;
      status: string;
    };

    // Create checkout URL
    const checkoutParams = new URLSearchParams({
      payment_intent: paymentIntent.id,
      session_id: sessionId,
      return_url: this.config.returnUrl || 'https://app.erify.world/payment/success',
      cancel_url: this.config.cancelUrl || 'https://app.erify.world/payment/cancel'
    });

    const checkoutUrl = `${this.baseUrl}/checkout?${checkoutParams.toString()}`;

    return {
      sessionId,
      paymentIntentId: paymentIntent.id,
      clientSecret: paymentIntent.client_secret,
      checkoutUrl,
      status: 'pending',
      amount: request.amount,
      currency: request.currency,
      createdAt: new Date(),
      expiresAt,
      metadata: request.metadata
    };
  }

  async getCheckoutSession(sessionId: string): Promise<CheckoutSession | null> {
    const response = await fetch(`${this.baseUrl}/checkout-sessions/${sessionId}`, {
      headers: {
        'Authorization': `Bearer ${this.config.apiKey}`,
        'User-Agent': 'ERIFY-Snippets/1.0.0'
      }
    });

    if (response.status === 404) {
      return null;
    }

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`ERIFY™ Payment: Failed to get checkout session: ${response.status} ${errorText}`);
    }

    const sessionData = await response.json() as CheckoutSession;
    return {
      ...sessionData,
      createdAt: new Date(sessionData.createdAt),
      expiresAt: new Date(sessionData.expiresAt)
    };
  }

  async cancelCheckoutSession(sessionId: string): Promise<boolean> {
    const response = await fetch(`${this.baseUrl}/checkout-sessions/${sessionId}/cancel`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.config.apiKey}`,
        'User-Agent': 'ERIFY-Snippets/1.0.0'
      }
    });

    return response.ok;
  }

  /**
   * Creates a secure payment link for email/SMS distribution
   */
  async createPaymentLink(
    request: CheckoutRequest,
    options?: {
      expiresInHours?: number;
      maxUses?: number;
      requireAuthentication?: boolean;
    }
  ): Promise<{ paymentLink: string; linkId: string }> {
    const linkId = generatePaymentSessionId();
    const expiresAt = new Date(
      Date.now() + (options?.expiresInHours || 24) * 60 * 60 * 1000
    );

    const linkPayload = {
      ...request,
      link_id: linkId,
      expires_at: expiresAt.toISOString(),
      max_uses: options?.maxUses || 1,
      require_authentication: options?.requireAuthentication || false
    };

    const response = await fetch(`${this.baseUrl}/payment-links`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.config.apiKey}`,
        'Content-Type': 'application/json',
        'User-Agent': 'ERIFY-Snippets/1.0.0'
      },
      body: JSON.stringify(linkPayload)
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`ERIFY™ Payment: Failed to create payment link: ${response.status} ${errorText}`);
    }

    const linkData = await response.json() as { url: string; id: string };

    return {
      paymentLink: linkData.url,
      linkId: linkData.id
    };
  }

  /**
   * Supports subscription-based recurring payments
   */
  async createSubscriptionCheckout(
    request: CheckoutRequest & {
      interval: 'day' | 'week' | 'month' | 'year';
      intervalCount?: number;
      trialPeriodDays?: number;
    }
  ): Promise<CheckoutSession> {
    // Remove unused variable
    // const subscriptionPayload = {
    //   ...request,
    //   payment_type: 'subscription',
    //   billing_cycle: {
    //     interval: request.interval,
    //     interval_count: request.intervalCount || 1
    //   },
    //   trial_period_days: request.trialPeriodDays
    // };

    // Remove interval properties from the base request
    const { interval, intervalCount, trialPeriodDays, ...baseRequest } = request;
    
    return this.createCheckoutSession({
      ...baseRequest,
      metadata: {
        ...baseRequest.metadata,
        payment_type: 'subscription',
        billing_interval: interval,
        billing_interval_count: String(intervalCount || 1),
        trial_days: String(trialPeriodDays || 0)
      }
    });
  }

  /**
   * Validates payment methods availability for region/currency
   */
  async getAvailablePaymentMethods(
    currency: string,
    countryCode?: string
  ): Promise<PaymentMethod[]> {
    const params = new URLSearchParams({ currency });
    if (countryCode) {
      params.set('country', countryCode);
    }

    const response = await fetch(`${this.baseUrl}/payment-methods?${params.toString()}`, {
      headers: {
        'Authorization': `Bearer ${this.config.apiKey}`,
        'User-Agent': 'ERIFY-Snippets/1.0.0'
      }
    });

    if (!response.ok) {
      throw new Error(`ERIFY™ Payment: Failed to get payment methods: ${response.status}`);
    }

    return await response.json() as PaymentMethod[];
  }
}