/**
 * ERIFY™ Payment Processing Example
 * Complete payment flow with Stripe and PayPal integration
 */

import express from 'express';
import { 
  ErifyPaymentManager,
  StripePaymentProvider,
  PayPalPaymentProvider,
  formatCurrency,
  validatePaymentAmount,
  PaymentIntent
} from '../index';

const app = express();

// Raw body parser for Stripe webhooks
app.use('/webhooks', express.raw({ type: 'application/json' }));
app.use(express.json());

// Initialize payment providers
const paymentManager = new ErifyPaymentManager();

// Add Stripe provider
const stripeProvider = new StripePaymentProvider(
  process.env.STRIPE_SECRET_KEY!,
  { apiVersion: '2023-10-16' }
);
paymentManager.addProvider('stripe', stripeProvider);

// Add PayPal provider
const paypalProvider = new PayPalPaymentProvider(
  process.env.PAYPAL_CLIENT_ID!,
  process.env.PAYPAL_CLIENT_SECRET!,
  process.env.NODE_ENV === 'production' ? 'production' : 'sandbox'
);
paymentManager.addProvider('paypal', paypalProvider);

// Create payment intent
app.post('/api/payments/create', async (req, res) => {
  try {
    const { amount, currency, provider, description, orderId } = req.body;
    
    // Validate payment amount
    if (!validatePaymentAmount(amount, currency)) {
      return res.status(400).json({
        error: 'Invalid payment amount',
        minimum: formatCurrency(0.50, currency),
      });
    }
    
    // Create payment intent
    const paymentIntent: PaymentIntent = {
      amount,
      currency: currency.toLowerCase(),
      description: description || `Order #${orderId}`,
      metadata: {
        orderId,
        userId: req.user?.userId || 'anonymous',
        timestamp: new Date().toISOString(),
      },
    };
    
    const result = await paymentManager.createPayment(provider, paymentIntent);
    
    // Log payment creation
    console.log(`Payment created: ${result.id} for ${formatCurrency(amount, currency)}`);
    
    res.json({
      paymentId: result.id,
      clientSecret: result.clientSecret,
      amount: result.amount,
      currency: result.currency,
      status: result.status,
    });
  } catch (error) {
    console.error('Payment creation failed:', error);
    res.status(400).json({ error: error.message });
  }
});

// Confirm payment
app.post('/api/payments/:paymentId/confirm', async (req, res) => {
  try {
    const { paymentId } = req.params;
    const { provider } = req.body;
    
    const result = await paymentManager.confirmPayment(provider, paymentId);
    
    if (result.status === 'succeeded') {
      // Handle successful payment
      await handleSuccessfulPayment(result);
      
      res.json({
        success: true,
        paymentId: result.id,
        status: result.status,
        receiptUrl: result.receiptUrl,
      });
    } else {
      res.status(400).json({
        success: false,
        status: result.status,
        error: 'Payment not successful',
      });
    }
  } catch (error) {
    console.error('Payment confirmation failed:', error);
    res.status(400).json({ error: error.message });
  }
});

// Get payment status
app.get('/api/payments/:paymentId', async (req, res) => {
  try {
    const { paymentId } = req.params;
    const { provider } = req.query;
    
    // In a real implementation, you'd fetch from your database
    // For now, we'll simulate a payment status check
    const payment = await getPaymentFromDatabase(paymentId);
    
    if (!payment) {
      return res.status(404).json({ error: 'Payment not found' });
    }
    
    res.json({
      id: payment.id,
      status: payment.status,
      amount: payment.amount,
      currency: payment.currency,
      createdAt: payment.createdAt,
      confirmedAt: payment.confirmedAt,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Stripe webhook handler
app.post('/webhooks/stripe', async (req, res) => {
  try {
    const signature = req.headers['stripe-signature'] as string;
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET!;
    
    const event = await paymentManager.handleWebhook('stripe', req.body, signature);
    
    console.log(`Stripe webhook received: ${event.type}`);
    
    switch (event.type) {
      case 'payment_intent.succeeded':
        await handlePaymentSuccess(event.data);
        break;
      case 'payment_intent.payment_failed':
        await handlePaymentFailure(event.data);
        break;
      case 'charge.dispute.created':
        await handleDispute(event.data);
        break;
      default:
        console.log(`Unhandled event type: ${event.type}`);
    }
    
    res.json({ received: true });
  } catch (error) {
    console.error('Stripe webhook error:', error);
    res.status(400).json({ error: error.message });
  }
});

// PayPal webhook handler
app.post('/webhooks/paypal', async (req, res) => {
  try {
    const event = await paymentManager.handleWebhook('paypal', req.body);
    
    console.log(`PayPal webhook received: ${event.event_type}`);
    
    switch (event.event_type) {
      case 'PAYMENT.CAPTURE.COMPLETED':
        await handlePaymentSuccess(event.resource);
        break;
      case 'PAYMENT.CAPTURE.DENIED':
        await handlePaymentFailure(event.resource);
        break;
      default:
        console.log(`Unhandled PayPal event: ${event.event_type}`);
    }
    
    res.json({ received: true });
  } catch (error) {
    console.error('PayPal webhook error:', error);
    res.status(400).json({ error: error.message });
  }
});

// Refund payment
app.post('/api/payments/:paymentId/refund', async (req, res) => {
  try {
    const { paymentId } = req.params;
    const { amount, reason } = req.body;
    
    // Implement refund logic based on provider
    const refund = await processRefund(paymentId, amount, reason);
    
    res.json({
      success: true,
      refundId: refund.id,
      amount: refund.amount,
      status: refund.status,
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Get payment analytics
app.get('/api/payments/analytics', async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    
    const analytics = await getPaymentAnalytics(startDate as string, endDate as string);
    
    res.json(analytics);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Helper functions (implement based on your business logic)

async function handleSuccessfulPayment(payment: any) {
  console.log(`Payment successful: ${payment.id}`);
  
  // Update order status
  await updateOrderStatus(payment.metadata?.orderId, 'paid');
  
  // Send confirmation email
  await sendPaymentConfirmationEmail(payment);
  
  // Update user account
  await updateUserAccount(payment.metadata?.userId, payment);
}

async function handlePaymentSuccess(paymentData: any) {
  console.log('Processing successful payment:', paymentData.id);
  // Implement success handling logic
}

async function handlePaymentFailure(paymentData: any) {
  console.log('Processing failed payment:', paymentData.id);
  // Implement failure handling logic
}

async function handleDispute(disputeData: any) {
  console.log('Processing payment dispute:', disputeData.id);
  // Implement dispute handling logic
}

async function getPaymentFromDatabase(paymentId: string) {
  // Implement database lookup
  return {
    id: paymentId,
    status: 'succeeded',
    amount: 29.99,
    currency: 'usd',
    createdAt: new Date().toISOString(),
    confirmedAt: new Date().toISOString(),
  };
}

async function processRefund(paymentId: string, amount?: number, reason?: string) {
  // Implement refund processing
  return {
    id: `re_${Math.random().toString(36).substr(2, 16)}`,
    amount: amount || 0,
    status: 'pending',
  };
}

async function updateOrderStatus(orderId: string, status: string) {
  console.log(`Updating order ${orderId} to status: ${status}`);
}

async function sendPaymentConfirmationEmail(payment: any) {
  console.log(`Sending confirmation email for payment: ${payment.id}`);
}

async function updateUserAccount(userId: string, payment: any) {
  console.log(`Updating account for user ${userId}`);
}

async function getPaymentAnalytics(startDate: string, endDate: string) {
  // Implement analytics calculation
  return {
    totalRevenue: 15420.50,
    totalTransactions: 342,
    averageOrderValue: 45.09,
    topPaymentMethods: [
      { method: 'stripe', count: 200, revenue: 9000.00 },
      { method: 'paypal', count: 142, revenue: 6420.50 },
    ],
  };
}

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`ERIFY™ Payment server running on port ${PORT}`);
});

export default app;