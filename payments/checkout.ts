/**
 * ERIFY™ Payment Checkout
 * Production-ready payment processing for Cloudflare Workers and Node.js
 * Enterprise-grade fintech integrations with security and compliance
 */

interface PaymentAmount {
  /** Amount in smallest currency unit (e.g., cents for USD) */
  amount: number;
  /** ISO 4217 currency code */
  currency: string;
  /** Optional amount breakdown for transparency */
  breakdown?: {
    /** Subtotal before taxes and fees */
    subtotal?: number;
    /** Tax amount */
    tax?: number;
    /** Shipping cost */
    shipping?: number;
    /** Discount amount (negative) */
    discount?: number;
    /** Processing fee */
    fee?: number;
  };
}

interface PaymentMethod {
  /** Payment method type */
  type: 'card' | 'bank_account' | 'digital_wallet' | 'crypto' | 'other';
  /** Card details (for card payments) */
  card?: {
    /** Tokenized card number or token */
    token: string;
    /** Last 4 digits for display */
    last4?: string;
    /** Card brand */
    brand?: string;
    /** Expiration month */
    expMonth?: number;
    /** Expiration year */
    expYear?: number;
  };
  /** Bank account details (for ACH/bank transfers) */
  bankAccount?: {
    /** Account token */
    token: string;
    /** Account type */
    accountType?: 'checking' | 'savings';
    /** Bank name */
    bankName?: string;
    /** Last 4 digits of account */
    last4?: string;
  };
  /** Digital wallet details */
  digitalWallet?: {
    /** Wallet type */
    type: 'apple_pay' | 'google_pay' | 'paypal' | 'other';
    /** Wallet token */
    token: string;
    /** Wallet email (if applicable) */
    email?: string;
  };
  /** Cryptocurrency details */
  crypto?: {
    /** Cryptocurrency type */
    type: 'bitcoin' | 'ethereum' | 'litecoin' | 'other';
    /** Wallet address */
    address: string;
    /** Network (mainnet, testnet, etc.) */
    network?: string;
  };
}

interface CustomerInfo {
  /** Customer ID */
  id: string;
  /** Customer email */
  email: string;
  /** Customer name */
  name?: string;
  /** Billing address */
  billingAddress?: {
    line1: string;
    line2?: string;
    city: string;
    state?: string;
    postalCode: string;
    country: string;
  };
  /** Shipping address (if different from billing) */
  shippingAddress?: {
    line1: string;
    line2?: string;
    city: string;
    state?: string;
    postalCode: string;
    country: string;
  };
  /** Customer phone number */
  phone?: string;
}

interface CheckoutOptions {
  /** Payment processor configuration */
  processor: {
    /** Processor name */
    name: 'stripe' | 'square' | 'paypal' | 'coinbase' | 'custom';
    /** API endpoint */
    apiUrl: string;
    /** API key or token */
    apiKey: string;
    /** Webhook secret for verification */
    webhookSecret?: string;
    /** Environment (sandbox/production) */
    environment: 'sandbox' | 'production';
  };
  /** Security options */
  security: {
    /** Enable 3D Secure verification */
    require3DS?: boolean;
    /** Enable fraud detection */
    fraudDetection?: boolean;
    /** Risk tolerance level */
    riskTolerance?: 'low' | 'medium' | 'high';
    /** Enable address verification */
    addressVerification?: boolean;
    /** Enable CVV verification */
    cvvVerification?: boolean;
  };
  /** Compliance settings */
  compliance: {
    /** PCI DSS compliance level */
    pciLevel?: 1 | 2 | 3 | 4;
    /** KYC requirements */
    kycRequired?: boolean;
    /** AML checks */
    amlChecks?: boolean;
    /** Regulatory jurisdiction */
    jurisdiction?: string;
  };
  /** Request timeout in milliseconds */
  timeout?: number;
  /** Retry configuration */
  retry?: {
    /** Maximum retry attempts */
    maxAttempts?: number;
    /** Retry delay in milliseconds */
    delayMs?: number;
  };
}

interface CheckoutRequest {
  /** Unique idempotency key */
  idempotencyKey: string;
  /** Payment amount */
  amount: PaymentAmount;
  /** Payment method */
  paymentMethod: PaymentMethod;
  /** Customer information */
  customer: CustomerInfo;
  /** Transaction description */
  description?: string;
  /** Merchant reference */
  merchantReference?: string;
  /** Success return URL */
  successUrl?: string;
  /** Failure return URL */
  failureUrl?: string;
  /** Webhook URL for notifications */
  webhookUrl?: string;
  /** Additional metadata */
  metadata?: Record<string, any>;
}

interface CheckoutResponse {
  /** Transaction success status */
  success: boolean;
  /** Transaction ID */
  transactionId?: string;
  /** Payment processor transaction ID */
  processorTransactionId?: string;
  /** Payment status */
  status: 'pending' | 'succeeded' | 'failed' | 'canceled' | 'requires_action';
  /** Amount processed */
  amount?: PaymentAmount;
  /** Payment method used */
  paymentMethod?: PaymentMethod;
  /** Error information */
  error?: {
    /** Error code */
    code: string;
    /** Error message */
    message: string;
    /** Error type */
    type: 'card_error' | 'rate_limit_error' | 'invalid_request_error' | 'api_error' | 'authentication_error';
    /** Additional error details */
    details?: Record<string, any>;
  };
  /** Next action required (for 3DS, etc.) */
  nextAction?: {
    /** Action type */
    type: 'redirect' | 'use_stripe_sdk' | 'authenticate';
    /** Redirect URL */
    redirectUrl?: string;
    /** Client secret for SDK */
    clientSecret?: string;
  };
  /** Fraud assessment */
  fraudAssessment?: {
    /** Risk score (0-100) */
    riskScore: number;
    /** Risk level */
    riskLevel: 'low' | 'medium' | 'high';
    /** Fraud checks performed */
    checks: {
      /** CVV check result */
      cvv?: 'pass' | 'fail' | 'unavailable';
      /** Address verification result */
      addressLine1?: 'pass' | 'fail' | 'unavailable';
      /** Postal code verification result */
      postalCode?: 'pass' | 'fail' | 'unavailable';
    };
  };
  /** Processing fees */
  fees?: {
    /** Processing fee amount */
    amount: number;
    /** Fee currency */
    currency: string;
    /** Fee breakdown */
    breakdown?: Record<string, number>;
  };
  /** Created timestamp */
  createdAt: number;
  /** Updated timestamp */
  updatedAt: number;
}

/**
 * Validates payment amount and currency
 */
function validatePaymentAmount(amount: PaymentAmount): void {
  if (!amount.amount || amount.amount <= 0) {
    throw new Error('ERIFY™ Payments: Amount must be greater than 0');
  }

  if (!amount.currency || !/^[A-Z]{3}$/.test(amount.currency)) {
    throw new Error('ERIFY™ Payments: Currency must be a valid 3-letter ISO code');
  }

  // Validate amount doesn't exceed reasonable limits
  if (amount.amount > 99999999999) { // $999,999,999.99 for most currencies
    throw new Error('ERIFY™ Payments: Amount exceeds maximum allowed limit');
  }

  // Validate breakdown if provided
  if (amount.breakdown) {
    const breakdown = amount.breakdown;
    const calculatedTotal = (breakdown.subtotal || 0) + 
                          (breakdown.tax || 0) + 
                          (breakdown.shipping || 0) + 
                          (breakdown.discount || 0) + 
                          (breakdown.fee || 0);
    
    if (Math.abs(calculatedTotal - amount.amount) > 1) { // Allow 1 cent rounding difference
      throw new Error('ERIFY™ Payments: Amount breakdown does not sum to total amount');
    }
  }
}

/**
 * Validates payment method details
 */
function validatePaymentMethod(paymentMethod: PaymentMethod): void {
  if (!paymentMethod.type) {
    throw new Error('ERIFY™ Payments: Payment method type is required');
  }

  switch (paymentMethod.type) {
    case 'card':
      if (!paymentMethod.card?.token) {
        throw new Error('ERIFY™ Payments: Card token is required for card payments');
      }
      break;
    case 'bank_account':
      if (!paymentMethod.bankAccount?.token) {
        throw new Error('ERIFY™ Payments: Bank account token is required for bank payments');
      }
      break;
    case 'digital_wallet':
      if (!paymentMethod.digitalWallet?.token) {
        throw new Error('ERIFY™ Payments: Digital wallet token is required');
      }
      break;
    case 'crypto':
      if (!paymentMethod.crypto?.address) {
        throw new Error('ERIFY™ Payments: Cryptocurrency address is required');
      }
      break;
  }
}

/**
 * Validates customer information
 */
function validateCustomerInfo(customer: CustomerInfo): void {
  if (!customer.id?.trim()) {
    throw new Error('ERIFY™ Payments: Customer ID is required');
  }

  if (!customer.email?.trim() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(customer.email)) {
    throw new Error('ERIFY™ Payments: Valid customer email is required');
  }

  // Validate billing address if provided
  if (customer.billingAddress) {
    const addr = customer.billingAddress;
    if (!addr.line1?.trim() || !addr.city?.trim() || !addr.postalCode?.trim() || !addr.country?.trim()) {
      throw new Error('ERIFY™ Payments: Complete billing address is required when provided');
    }
  }
}

/**
 * Creates processor-specific request payload
 */
function createProcessorRequest(
  request: CheckoutRequest,
  options: CheckoutOptions
): { url: string; headers: Record<string, string>; body: any } {
  const { processor } = options;

  switch (processor.name) {
    case 'stripe':
      return createStripeRequest(request, options);
    case 'square':
      return createSquareRequest(request, options);
    case 'paypal':
      return createPayPalRequest(request, options);
    case 'coinbase':
      return createCoinbaseRequest(request, options);
    default:
      throw new Error(`ERIFY™ Payments: Unsupported processor: ${processor.name}`);
  }
}

/**
 * Creates Stripe-specific request
 */
function createStripeRequest(request: CheckoutRequest, options: CheckoutOptions) {
  const { processor } = options;
  
  return {
    url: `${processor.apiUrl}/payment_intents`,
    headers: {
      'Authorization': `Bearer ${processor.apiKey}`,
      'Content-Type': 'application/x-www-form-urlencoded',
      'Idempotency-Key': request.idempotencyKey,
      'Stripe-Version': '2023-10-16',
    },
    body: new URLSearchParams({
      amount: request.amount.amount.toString(),
      currency: request.amount.currency.toLowerCase(),
      payment_method: request.paymentMethod.card?.token || '',
      customer: request.customer.id,
      description: request.description || '',
      confirmation_method: 'manual',
      confirm: 'true',
      metadata: JSON.stringify(request.metadata || {}),
    }).toString(),
  };
}

/**
 * Creates Square-specific request
 */
function createSquareRequest(request: CheckoutRequest, options: CheckoutOptions) {
  const { processor } = options;
  
  return {
    url: `${processor.apiUrl}/payments`,
    headers: {
      'Authorization': `Bearer ${processor.apiKey}`,
      'Content-Type': 'application/json',
      'Square-Version': '2023-10-18',
    },
    body: JSON.stringify({
      idempotency_key: request.idempotencyKey,
      amount_money: {
        amount: request.amount.amount,
        currency: request.amount.currency,
      },
      source_id: request.paymentMethod.card?.token,
      customer_id: request.customer.id,
      note: request.description,
    }),
  };
}

/**
 * Creates PayPal-specific request
 */
function createPayPalRequest(request: CheckoutRequest, options: CheckoutOptions) {
  const { processor } = options;
  
  return {
    url: `${processor.apiUrl}/payments/payment`,
    headers: {
      'Authorization': `Bearer ${processor.apiKey}`,
      'Content-Type': 'application/json',
      'PayPal-Request-Id': request.idempotencyKey,
    },
    body: JSON.stringify({
      intent: 'sale',
      payer: {
        payment_method: 'paypal',
      },
      transactions: [{
        amount: {
          total: (request.amount.amount / 100).toFixed(2),
          currency: request.amount.currency,
        },
        description: request.description,
      }],
      redirect_urls: {
        return_url: request.successUrl,
        cancel_url: request.failureUrl,
      },
    }),
  };
}

/**
 * Creates Coinbase-specific request
 */
function createCoinbaseRequest(request: CheckoutRequest, options: CheckoutOptions) {
  const { processor } = options;
  
  return {
    url: `${processor.apiUrl}/charges`,
    headers: {
      'Authorization': `Bearer ${processor.apiKey}`,
      'Content-Type': 'application/json',
      'X-CC-Api-Key': processor.apiKey,
      'X-CC-Version': '2018-03-22',
    },
    body: JSON.stringify({
      name: request.description,
      description: request.description,
      local_price: {
        amount: (request.amount.amount / 100).toFixed(2),
        currency: request.amount.currency,
      },
      pricing_type: 'fixed_price',
      metadata: {
        customer_id: request.customer.id,
        idempotency_key: request.idempotencyKey,
        ...request.metadata,
      },
    }),
  };
}

/**
 * Processes payment through the configured processor
 * 
 * @param request Checkout request details
 * @param options Payment processor and security options
 * @returns Promise resolving to checkout response
 */
export async function processPayment(
  request: CheckoutRequest,
  options: CheckoutOptions
): Promise<CheckoutResponse> {
  const startTime = Date.now();

  try {
    // Validate request
    if (!request.idempotencyKey?.trim()) {
      throw new Error('ERIFY™ Payments: Idempotency key is required');
    }

    validatePaymentAmount(request.amount);
    validatePaymentMethod(request.paymentMethod);
    validateCustomerInfo(request.customer);

    // Validate options
    if (!options.processor?.apiKey?.trim()) {
      throw new Error('ERIFY™ Payments: Processor API key is required');
    }

    if (!options.processor?.apiUrl?.trim()) {
      throw new Error('ERIFY™ Payments: Processor API URL is required');
    }

    // Create processor-specific request
    const processorRequest = createProcessorRequest(request, options);
    
    // Set up request with timeout
    const timeout = options.timeout || 30000;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      // Make payment request
      const response = await fetch(processorRequest.url, {
        method: 'POST',
        headers: processorRequest.headers,
        body: typeof processorRequest.body === 'string' 
          ? processorRequest.body 
          : JSON.stringify(processorRequest.body),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      // Parse response
      let responseData: any;
      try {
        responseData = await response.json();
      } catch (parseError) {
        throw new Error('ERIFY™ Payments: Invalid JSON response from processor');
      }

      // Handle response based on processor
      return parseProcessorResponse(
        response,
        responseData,
        request,
        options,
        startTime
      );

    } catch (fetchError) {
      clearTimeout(timeoutId);
      
      if (fetchError.name === 'AbortError') {
        throw new Error(`ERIFY™ Payments: Request timeout after ${timeout}ms`);
      }
      
      throw fetchError;
    }

  } catch (error) {
    // Return error response
    return {
      success: false,
      status: 'failed',
      error: {
        code: 'processing_error',
        message: error.message || 'Payment processing failed',
        type: 'api_error',
      },
      createdAt: startTime,
      updatedAt: Date.now(),
    };
  }
}

/**
 * Parses processor response into standardized format
 */
function parseProcessorResponse(
  response: Response,
  data: any,
  request: CheckoutRequest,
  options: CheckoutOptions,
  startTime: number
): CheckoutResponse {
  const { processor } = options;
  const now = Date.now();

  // Handle success responses
  if (response.ok) {
    switch (processor.name) {
      case 'stripe':
        return parseStripeResponse(data, request, startTime, now);
      case 'square':
        return parseSquareResponse(data, request, startTime, now);
      case 'paypal':
        return parsePayPalResponse(data, request, startTime, now);
      case 'coinbase':
        return parseCoinbaseResponse(data, request, startTime, now);
      default:
        return {
          success: true,
          status: 'succeeded',
          transactionId: data.id || data.transaction_id,
          amount: request.amount,
          paymentMethod: request.paymentMethod,
          createdAt: startTime,
          updatedAt: now,
        };
    }
  }

  // Handle error responses
  return {
    success: false,
    status: 'failed',
    error: {
      code: data.error?.code || 'unknown_error',
      message: data.error?.message || data.message || 'Payment failed',
      type: determineErrorType(data.error?.type || response.status),
      details: data.error,
    },
    createdAt: startTime,
    updatedAt: now,
  };
}

/**
 * Parses Stripe response
 */
function parseStripeResponse(data: any, request: CheckoutRequest, startTime: number, now: number): CheckoutResponse {
  return {
    success: data.status === 'succeeded',
    transactionId: data.id,
    processorTransactionId: data.id,
    status: mapStripeStatus(data.status),
    amount: request.amount,
    paymentMethod: request.paymentMethod,
    nextAction: data.next_action ? {
      type: data.next_action.type,
      redirectUrl: data.next_action.redirect_to_url?.url,
      clientSecret: data.client_secret,
    } : undefined,
    createdAt: startTime,
    updatedAt: now,
  };
}

/**
 * Parses Square response
 */
function parseSquareResponse(data: any, request: CheckoutRequest, startTime: number, now: number): CheckoutResponse {
  const payment = data.payment;
  return {
    success: payment?.status === 'COMPLETED',
    transactionId: payment?.id,
    processorTransactionId: payment?.id,
    status: mapSquareStatus(payment?.status),
    amount: request.amount,
    paymentMethod: request.paymentMethod,
    createdAt: startTime,
    updatedAt: now,
  };
}

/**
 * Parses PayPal response
 */
function parsePayPalResponse(data: any, request: CheckoutRequest, startTime: number, now: number): CheckoutResponse {
  return {
    success: data.state === 'approved',
    transactionId: data.id,
    processorTransactionId: data.id,
    status: mapPayPalStatus(data.state),
    amount: request.amount,
    paymentMethod: request.paymentMethod,
    nextAction: data.links?.find((link: any) => link.rel === 'approval_url') ? {
      type: 'redirect',
      redirectUrl: data.links.find((link: any) => link.rel === 'approval_url').href,
    } : undefined,
    createdAt: startTime,
    updatedAt: now,
  };
}

/**
 * Parses Coinbase response
 */
function parseCoinbaseResponse(data: any, request: CheckoutRequest, startTime: number, now: number): CheckoutResponse {
  return {
    success: data.timeline?.some((event: any) => event.status === 'COMPLETED'),
    transactionId: data.id,
    processorTransactionId: data.id,
    status: mapCoinbaseStatus(data.timeline?.[data.timeline.length - 1]?.status),
    amount: request.amount,
    paymentMethod: request.paymentMethod,
    createdAt: startTime,
    updatedAt: now,
  };
}

/**
 * Maps processor-specific status to standardized status
 */
function mapStripeStatus(status: string): CheckoutResponse['status'] {
  switch (status) {
    case 'succeeded': return 'succeeded';
    case 'requires_action': return 'requires_action';
    case 'canceled': return 'canceled';
    case 'processing': return 'pending';
    default: return 'failed';
  }
}

function mapSquareStatus(status: string): CheckoutResponse['status'] {
  switch (status) {
    case 'COMPLETED': return 'succeeded';
    case 'PENDING': return 'pending';
    case 'CANCELED': return 'canceled';
    default: return 'failed';
  }
}

function mapPayPalStatus(status: string): CheckoutResponse['status'] {
  switch (status) {
    case 'approved': return 'succeeded';
    case 'created': return 'pending';
    case 'canceled': return 'canceled';
    default: return 'failed';
  }
}

function mapCoinbaseStatus(status: string): CheckoutResponse['status'] {
  switch (status) {
    case 'COMPLETED': return 'succeeded';
    case 'PENDING': return 'pending';
    case 'CANCELED': return 'canceled';
    default: return 'failed';
  }
}

/**
 * Determines error type from processor error
 */
function determineErrorType(errorType: string | number): CheckoutResponse['error']['type'] {
  if (typeof errorType === 'number') {
    if (errorType === 429) return 'rate_limit_error';
    if (errorType >= 400 && errorType < 500) return 'invalid_request_error';
    if (errorType >= 500) return 'api_error';
  }

  if (typeof errorType === 'string') {
    if (errorType.includes('card') || errorType.includes('payment')) return 'card_error';
    if (errorType.includes('rate') || errorType.includes('limit')) return 'rate_limit_error';
    if (errorType.includes('auth')) return 'authentication_error';
  }

  return 'api_error';
}

/**
 * Payment processing with retry logic for production reliability
 * 
 * @param request Checkout request
 * @param options Payment options
 * @returns Promise resolving to checkout response
 */
export async function processPaymentWithRetry(
  request: CheckoutRequest,
  options: CheckoutOptions
): Promise<CheckoutResponse> {
  const maxAttempts = options.retry?.maxAttempts || 3;
  const delayMs = options.retry?.delayMs || 1000;
  
  let lastResponse: CheckoutResponse;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    lastResponse = await processPayment(request, options);
    
    // Don't retry successful payments or client errors
    if (lastResponse.success || 
        lastResponse.error?.type === 'card_error' ||
        lastResponse.error?.type === 'invalid_request_error' ||
        lastResponse.error?.type === 'authentication_error') {
      return lastResponse;
    }
    
    // Wait before retry (exponential backoff with jitter)
    if (attempt < maxAttempts) {
      const delay = delayMs * Math.pow(2, attempt - 1) + Math.random() * 1000;
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  return lastResponse;
}