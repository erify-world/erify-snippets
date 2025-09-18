/**
 * ERIFY™ Simple Usage Examples
 * Basic usage patterns that compile cleanly
 */

// OAuth Example
export const oauthExample = `
import { ErifyOAuth, createOAuthConfig } from '@erify/snippets';

const config = createOAuthConfig({
  google: {
    clientId: 'your-client-id',
    clientSecret: 'your-client-secret',
    redirectUri: 'https://yourapp.com/callback',
  },
});

const oauth = new ErifyOAuth(config);
const authUrl = oauth.getAuthUrl('google', 'state123');
`;

// JWT Example
export const jwtExample = `
import { ErifyJWT, createJWTConfig } from '@erify/snippets';

const jwtConfig = createJWTConfig('your-secret-key');
const jwtManager = new ErifyJWT(jwtConfig);

const tokens = jwtManager.generateTokenPair({
  userId: 'user123',
  email: 'user@example.com',
  roles: ['user'],
});
`;

// Validation Example
export const validationExample = `
import { validateEmail, validatePassword } from '@erify/snippets';

const emailResult = validateEmail('user@example.com');
const passwordResult = validatePassword('SecurePass123!');

if (emailResult.isValid && passwordResult.isValid) {
  console.log('Valid credentials');
}
`;

// Payment Example
export const paymentExample = `
import { 
  ErifyPaymentManager, 
  StripePaymentProvider 
} from '@erify/snippets';

const paymentManager = new ErifyPaymentManager();
const stripeProvider = new StripePaymentProvider('sk_test_...');
paymentManager.addProvider('stripe', stripeProvider);

const payment = await paymentManager.createPayment('stripe', {
  amount: 29.99,
  currency: 'usd',
  description: 'Premium subscription',
});
`;

export const examples = {
  oauth: oauthExample,
  jwt: jwtExample,
  validation: validationExample,
  payment: paymentExample,
};