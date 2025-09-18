/**
 * ERIFY™ Payment Verification Implementation
 * 
 * Secure payment verification with webhook handling and fraud detection
 * Designed for Cloudflare Workers, Node.js, and fintech ecosystems
 * 
 * @author Yahaya Ibrahim | ERIFY™ Founder
 * @license MIT
 */

import type { PaymentConfig } from './checkout.js';

export interface PaymentVerificationResult {
  readonly isValid: boolean;
  readonly paymentId: string;
  readonly status: PaymentStatus;
  readonly amount: number;
  readonly currency: string;
  readonly customerId: string | undefined;
  readonly metadata: Record<string, string> | undefined;
  readonly fraudScore: number | undefined;
  readonly errors: readonly string[];
  readonly warnings: readonly string[];
}

export interface WebhookEvent {
  readonly id: string;
  readonly type: string;
  readonly created: number;
  readonly data: {
    readonly object: PaymentIntent | Charge | Subscription;
  };
  readonly livemode: boolean;
  readonly apiVersion: string;
}

export interface PaymentIntent {
  readonly id: string;
  readonly object: 'payment_intent';
  readonly amount: number;
  readonly currency: string;
  readonly status: PaymentStatus;
  readonly client_secret: string;
  readonly created: number;
  readonly customer?: string;
  readonly metadata: Record<string, string>;
  readonly charges: {
    readonly data: readonly Charge[];
  };
}

export interface Charge {
  readonly id: string;
  readonly object: 'charge';
  readonly amount: number;
  readonly currency: string;
  readonly status: ChargeStatus;
  readonly created: number;
  readonly customer?: string;
  readonly payment_intent: string;
  readonly payment_method: string;
  readonly receipt_url?: string;
  readonly fraud_details?: Record<string, unknown>;
  readonly outcome?: {
    readonly network_status: string;
    readonly reason?: string;
    readonly risk_level: 'normal' | 'elevated' | 'highest';
    readonly risk_score: number;
  };
}

export interface Subscription {
  readonly id: string;
  readonly object: 'subscription';
  readonly status: SubscriptionStatus;
  readonly customer: string;
  readonly current_period_start: number;
  readonly current_period_end: number;
  readonly created: number;
  readonly metadata: Record<string, string>;
}

export type PaymentStatus = 
  | 'requires_payment_method'
  | 'requires_confirmation'
  | 'requires_action'
  | 'processing'
  | 'requires_capture'
  | 'canceled'
  | 'succeeded';

export type ChargeStatus = 
  | 'pending'
  | 'succeeded'
  | 'failed';

export type SubscriptionStatus = 
  | 'incomplete'
  | 'incomplete_expired'
  | 'trialing'
  | 'active'
  | 'past_due'
  | 'canceled'
  | 'unpaid'
  | 'paused';

/**
 * Verifies webhook signature for security
 */
export async function verifyWebhookSignature(
  payload: string,
  signature: string,
  secret: string
): Promise<boolean> {
  try {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    // Extract timestamp and signature from header
    const elements = signature.split(',');
    const timestampElement = elements.find(el => el.startsWith('t='));
    const signatureElement = elements.find(el => el.startsWith('v1='));

    if (!timestampElement || !signatureElement) {
      return false;
    }

    const timestamp = timestampElement.split('=')[1];
    const expectedSignature = signatureElement.split('=')[1];

    if (!timestamp || !expectedSignature) {
      return false;
    }

    // Check timestamp freshness (within 5 minutes)
    const eventTime = parseInt(timestamp, 10) * 1000;
    const currentTime = Date.now();
    if (Math.abs(currentTime - eventTime) > 5 * 60 * 1000) {
      return false;
    }

    // Verify signature
    const signedPayload = `${timestamp}.${payload}`;
    const expectedSignatureBytes = new Uint8Array(
      expectedSignature.match(/.{1,2}/g)?.map(byte => parseInt(byte, 16)) || []
    );

    return await crypto.subtle.verify(
      'HMAC',
      key,
      expectedSignatureBytes,
      encoder.encode(signedPayload)
    );
  } catch {
    return false;
  }
}

/**
 * Analyzes payment for fraud indicators
 */
export function analyzeFraudRisk(
  charge: Charge,
  additionalData?: {
    ipAddress?: string;
    userAgent?: string;
    billingAddress?: Record<string, unknown>;
    shippingAddress?: Record<string, unknown>;
  }
): { riskScore: number; riskFactors: string[] } {
  let riskScore = 0;
  const riskFactors: string[] = [];

  // Base risk from payment processor
  if (charge.outcome?.risk_score) {
    riskScore += charge.outcome.risk_score;
  }

  if (charge.outcome?.risk_level === 'elevated') {
    riskScore += 30;
    riskFactors.push('Elevated risk from processor');
  }

  if (charge.outcome?.risk_level === 'highest') {
    riskScore += 50;
    riskFactors.push('Highest risk from processor');
  }

  // Fraud details analysis
  if (charge.fraud_details) {
    riskScore += 40;
    riskFactors.push('Fraud details present');
  }

  // Amount-based risk
  if (charge.amount > 100000) { // $1000+
    riskScore += 10;
    riskFactors.push('High transaction amount');
  }

  if (charge.amount > 500000) { // $5000+
    riskScore += 20;
    riskFactors.push('Very high transaction amount');
  }

  // Additional data analysis
  if (additionalData?.billingAddress && additionalData?.shippingAddress) {
    const billing = additionalData.billingAddress as Record<string, string>;
    const shipping = additionalData.shippingAddress as Record<string, string>;
    
    if (billing.country !== shipping.country) {
      riskScore += 15;
      riskFactors.push('Billing and shipping country mismatch');
    }
  }

  return {
    riskScore: Math.min(riskScore, 100), // Cap at 100
    riskFactors
  };
}

/**
 * Validates payment status and details
 */
export function validatePaymentIntent(paymentIntent: PaymentIntent): {
  isValid: boolean;
  errors: string[];
  warnings: string[];
} {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Status validation
  if (!['succeeded', 'requires_capture'].includes(paymentIntent.status)) {
    errors.push(`Invalid payment status: ${paymentIntent.status}`);
  }

  // Amount validation
  if (paymentIntent.amount <= 0) {
    errors.push('Invalid payment amount');
  }

  // Currency validation
  const validCurrencies = ['usd', 'eur', 'gbp', 'cad', 'aud', 'jpy'];
  if (!validCurrencies.includes(paymentIntent.currency.toLowerCase())) {
    warnings.push(`Unusual currency: ${paymentIntent.currency}`);
  }

  // Charges validation
  if (paymentIntent.charges.data.length === 0) {
    errors.push('No charges found for payment intent');
  }

  return { isValid: errors.length === 0, errors, warnings };
}

/**
 * Complete payment verification for ERIFY™ ecosystems
 * 
 * @example Cloudflare Workers webhook handler:
 * ```typescript
 * export default {
 *   async fetch(request: Request, env: Env): Promise<Response> {
 *     const verifier = new ERIFYPaymentVerifier({
 *       apiKey: env.PAYMENT_API_KEY,
 *       secretKey: env.PAYMENT_SECRET_KEY,
 *       environment: 'production',
 *       currency: 'USD',
 *       webhookSecret: env.WEBHOOK_SECRET
 *     });
 *     
 *     const signature = request.headers.get('stripe-signature');
 *     const payload = await request.text();
 *     
 *     const result = await verifier.verifyWebhookPayment(payload, signature);
 *     if (!result.isValid) {
 *       return new Response('Invalid payment', { status: 400 });
 *     }
 *     
 *     // Process successful payment
 *     await processPayment(result);
 *     
 *     return new Response('OK');
 *   }
 * };
 * ```
 */
export class ERIFYPaymentVerifier {
  private readonly baseUrl: string;

  constructor(private readonly config: PaymentConfig) {
    this.baseUrl = config.environment === 'production' 
      ? 'https://api.erify.world/payments'
      : 'https://sandbox-api.erify.world/payments';
  }

  async verifyPaymentIntent(paymentIntentId: string): Promise<PaymentVerificationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      const response = await fetch(`${this.baseUrl}/payment-intents/${paymentIntentId}`, {
        headers: {
          'Authorization': `Bearer ${this.config.apiKey}`,
          'User-Agent': 'ERIFY-Snippets/1.0.0'
        }
      });

      if (!response.ok) {
        errors.push(`Failed to fetch payment intent: ${response.status}`);
        return {
          isValid: false,
          paymentId: paymentIntentId,
          status: 'canceled',
          amount: 0,
          currency: 'unknown',
          customerId: undefined,
          metadata: undefined,
          fraudScore: undefined,
          errors,
          warnings
        };
      }

      const paymentIntent = await response.json() as PaymentIntent;
      const validation = validatePaymentIntent(paymentIntent);
      
      errors.push(...validation.errors);
      warnings.push(...validation.warnings);

      // Fraud analysis on charges
      let fraudScore: number | undefined = undefined;
      if (paymentIntent.charges.data.length > 0) {
        const charge = paymentIntent.charges.data[0];
        if (charge) {
          const fraudAnalysis = analyzeFraudRisk(charge);
          fraudScore = fraudAnalysis.riskScore;
          
          if (fraudScore > 70) {
            warnings.push(`High fraud risk score: ${fraudScore}`);
          }
        }
      }

      return {
        isValid: validation.isValid,
        paymentId: paymentIntent.id,
        status: paymentIntent.status,
        amount: paymentIntent.amount,
        currency: paymentIntent.currency,
        customerId: paymentIntent.customer,
        metadata: paymentIntent.metadata,
        fraudScore,
        errors,
        warnings
      };

    } catch (error) {
      errors.push(`Verification error: ${error instanceof Error ? error.message : 'unknown'}`);
      
      return {
        isValid: false,
        paymentId: paymentIntentId,
        status: 'canceled',
        amount: 0,
        currency: 'unknown',
        customerId: undefined,
        metadata: undefined,
        fraudScore: undefined,
        errors,
        warnings
      };
    }
  }

  async verifyWebhookPayment(
    payload: string,
    signature: string | null
  ): Promise<PaymentVerificationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Verify webhook signature
    if (!signature || !this.config.webhookSecret) {
      errors.push('Missing webhook signature or secret');
      return {
        isValid: false,
        paymentId: 'unknown',
        status: 'canceled',
        amount: 0,
        currency: 'unknown',
        customerId: undefined,
        metadata: undefined,
        fraudScore: undefined,
        errors,
        warnings
      };
    }

    const signatureValid = await verifyWebhookSignature(
      payload,
      signature,
      this.config.webhookSecret
    );

    if (!signatureValid) {
      errors.push('Invalid webhook signature');
      return {
        isValid: false,
        paymentId: 'unknown',
        status: 'canceled',
        amount: 0,
        currency: 'unknown',
        customerId: undefined,
        metadata: undefined,
        fraudScore: undefined,
        errors,
        warnings
      };
    }

    try {
      const event = JSON.parse(payload) as WebhookEvent;
      
      // Handle different event types
      switch (event.type) {
        case 'payment_intent.succeeded':
        case 'payment_intent.payment_failed':
        case 'charge.succeeded':
        case 'charge.failed': {
          const paymentObject = event.data.object as PaymentIntent | Charge;
          
          let paymentId: string;
          let amount: number;
          let currency: string;
          let status: PaymentStatus;
          let customerId: string | undefined;
          let metadata: Record<string, string> | undefined;

          if (paymentObject.object === 'payment_intent') {
            paymentId = paymentObject.id;
            amount = paymentObject.amount;
            currency = paymentObject.currency;
            status = paymentObject.status;
            customerId = paymentObject.customer;
            metadata = paymentObject.metadata;
          } else {
            paymentId = paymentObject.id;
            amount = paymentObject.amount;
            currency = paymentObject.currency;
            status = paymentObject.status === 'succeeded' ? 'succeeded' : 'canceled';
            customerId = paymentObject.customer;
          }

          // Additional verification for critical events
          if (event.type.includes('succeeded') && amount > 100000) { // $1000+
            const verification = await this.verifyPaymentIntent(paymentId);
            if (!verification.isValid) {
              errors.push('High-value payment failed additional verification');
            }
          }

          return {
            isValid: errors.length === 0,
            paymentId,
            status,
            amount,
            currency,
            customerId,
            metadata,
            fraudScore: undefined,
            errors,
            warnings
          };
        }

        default:
          warnings.push(`Unhandled webhook event type: ${event.type}`);
          return {
            isValid: true,
            paymentId: 'webhook_event',
            status: 'processing',
            amount: 0,
            currency: 'unknown',
            customerId: undefined,
            metadata: undefined,
            fraudScore: undefined,
            errors,
            warnings
          };
      }

    } catch (error) {
      errors.push(`Webhook parsing error: ${error instanceof Error ? error.message : 'unknown'}`);
      
      return {
        isValid: false,
        paymentId: 'parse_error',
        status: 'canceled',
        amount: 0,
        currency: 'unknown',
        customerId: undefined,
        metadata: undefined,
        fraudScore: undefined,
        errors,
        warnings
      };
    }
  }

  /**
   * Batch verification for multiple payments
   */
  async verifyMultiplePayments(
    paymentIntentIds: readonly string[]
  ): Promise<PaymentVerificationResult[]> {
    const results = await Promise.all(
      paymentIntentIds.map(id => this.verifyPaymentIntent(id))
    );

    return results;
  }

  /**
   * Verify and capture authorized payment
   */
  async capturePayment(
    paymentIntentId: string,
    amountToCapture?: number
  ): Promise<{ success: boolean; capturedAmount?: number; error?: string }> {
    try {
      const capturePayload: Record<string, unknown> = {};
      if (amountToCapture !== undefined) {
        capturePayload.amount_to_capture = amountToCapture;
      }

      const response = await fetch(`${this.baseUrl}/payment-intents/${paymentIntentId}/capture`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.config.apiKey}`,
          'Content-Type': 'application/json',
          'User-Agent': 'ERIFY-Snippets/1.0.0'
        },
        body: Object.keys(capturePayload).length > 0 ? JSON.stringify(capturePayload) : null
      });

      if (!response.ok) {
        const errorText = await response.text();
        return { success: false, error: `Capture failed: ${errorText}` };
      }

      const result = await response.json() as { amount_captured: number };
      
      return {
        success: true,
        capturedAmount: result.amount_captured
      };

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  /**
   * Refund a payment with optional partial amount
   */
  async refundPayment(
    paymentIntentId: string,
    refundAmount?: number,
    reason?: 'duplicate' | 'fraudulent' | 'requested_by_customer'
  ): Promise<{ success: boolean; refundId?: string; error?: string }> {
    try {
      const refundPayload: Record<string, unknown> = {
        payment_intent: paymentIntentId
      };

      if (refundAmount !== undefined) {
        refundPayload.amount = refundAmount;
      }

      if (reason) {
        refundPayload.reason = reason;
      }

      const response = await fetch(`${this.baseUrl}/refunds`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.config.apiKey}`,
          'Content-Type': 'application/json',
          'User-Agent': 'ERIFY-Snippets/1.0.0'
        },
        body: JSON.stringify(refundPayload)
      });

      if (!response.ok) {
        const errorText = await response.text();
        return { success: false, error: `Refund failed: ${errorText}` };
      }

      const result = await response.json() as { id: string };
      
      return {
        success: true,
        refundId: result.id
      };

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }
}