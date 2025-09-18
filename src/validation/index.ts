import { z } from 'zod';
import { ValidationResult } from '../types';

/**
 * ERIFY™ Validation Library
 * Comprehensive input validation, schema validation, and data sanitization
 */

/**
 * Email validation
 */
export const validateEmail = (email: string): ValidationResult => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const isValid = emailRegex.test(email);
  
  return {
    isValid,
    errors: isValid ? [] : ['Invalid email format'],
    data: isValid ? email.toLowerCase().trim() : undefined,
  };
};

/**
 * Password strength validation
 */
export const validatePassword = (
  password: string,
  options: {
    minLength?: number;
    requireUppercase?: boolean;
    requireLowercase?: boolean;
    requireNumbers?: boolean;
    requireSpecialChars?: boolean;
  } = {}
): ValidationResult => {
  const {
    minLength = 8,
    requireUppercase = true,
    requireLowercase = true,
    requireNumbers = true,
    requireSpecialChars = true,
  } = options;

  const errors: string[] = [];

  if (password.length < minLength) {
    errors.push(`Password must be at least ${minLength} characters long`);
  }

  if (requireUppercase && !/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }

  if (requireLowercase && !/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }

  if (requireNumbers && !/\d/.test(password)) {
    errors.push('Password must contain at least one number');
  }

  if (requireSpecialChars && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }

  return {
    isValid: errors.length === 0,
    errors,
    data: errors.length === 0 ? password : undefined,
  };
};

/**
 * Phone number validation
 */
export const validatePhoneNumber = (phone: string, countryCode?: string): ValidationResult => {
  // Remove all non-digit characters
  const cleaned = phone.replace(/\D/g, '');
  
  // Basic validation patterns by country
  const patterns = {
    US: /^1?[2-9]\d{2}[2-9]\d{2}\d{4}$/,
    UK: /^44[1-9]\d{8,9}$/,
    CA: /^1[2-9]\d{2}[2-9]\d{2}\d{4}$/,
    // Add more country patterns as needed
  };

  const pattern = countryCode ? patterns[countryCode as keyof typeof patterns] : null;
  
  if (pattern) {
    const isValid = pattern.test(cleaned);
    return {
      isValid,
      errors: isValid ? [] : [`Invalid ${countryCode} phone number format`],
      data: isValid ? cleaned : undefined,
    };
  }

  // Generic validation (10-15 digits)
  const isValid = cleaned.length >= 10 && cleaned.length <= 15;
  return {
    isValid,
    errors: isValid ? [] : ['Invalid phone number format'],
    data: isValid ? cleaned : undefined,
  };
};

/**
 * URL validation
 */
export const validateURL = (url: string, options: { requireHttps?: boolean } = {}): ValidationResult => {
  try {
    const urlObj = new URL(url);
    
    if (options.requireHttps && urlObj.protocol !== 'https:') {
      return {
        isValid: false,
        errors: ['URL must use HTTPS protocol'],
      };
    }

    return {
      isValid: true,
      errors: [],
      data: urlObj.toString(),
    };
  } catch (error) {
    return {
      isValid: false,
      errors: ['Invalid URL format'],
    };
  }
};

/**
 * Credit card validation (Luhn algorithm)
 */
export const validateCreditCard = (cardNumber: string): ValidationResult => {
  const cleaned = cardNumber.replace(/\D/g, '');
  
  if (cleaned.length < 13 || cleaned.length > 19) {
    return {
      isValid: false,
      errors: ['Invalid credit card number length'],
    };
  }

  // Luhn algorithm
  let sum = 0;
  let isEven = false;

  for (let i = cleaned.length - 1; i >= 0; i--) {
    let digit = parseInt(cleaned[i]);

    if (isEven) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }

    sum += digit;
    isEven = !isEven;
  }

  const isValid = sum % 10 === 0;
  return {
    isValid,
    errors: isValid ? [] : ['Invalid credit card number'],
    data: isValid ? cleaned : undefined,
  };
};

/**
 * Zod-based schema validator
 */
export class ErifyValidator {
  /**
   * Create user registration schema
   */
  static userRegistrationSchema = z.object({
    email: z.string().email('Invalid email address'),
    password: z.string()
      .min(8, 'Password must be at least 8 characters')
      .regex(/[A-Z]/, 'Password must contain uppercase letter')
      .regex(/[a-z]/, 'Password must contain lowercase letter')
      .regex(/\d/, 'Password must contain a number')
      .regex(/[!@#$%^&*]/, 'Password must contain special character'),
    firstName: z.string().min(1, 'First name is required').max(50, 'First name too long'),
    lastName: z.string().min(1, 'Last name is required').max(50, 'Last name too long'),
    phone: z.string().optional(),
    dateOfBirth: z.string().datetime().optional(),
    agreeToTerms: z.boolean().refine(val => val === true, 'Must agree to terms'),
  });

  /**
   * Create payment schema
   */
  static paymentSchema = z.object({
    amount: z.number().positive('Amount must be positive'),
    currency: z.string().length(3, 'Currency must be 3 characters'),
    provider: z.enum(['stripe', 'paypal'], {
      errorMap: () => ({ message: 'Invalid payment provider' }),
    }),
    description: z.string().optional(),
    metadata: z.record(z.string()).optional(),
  });

  /**
   * Create OAuth callback schema
   */
  static oauthCallbackSchema = z.object({
    code: z.string().min(1, 'Authorization code is required'),
    state: z.string().optional(),
    error: z.string().optional(),
    error_description: z.string().optional(),
  });

  /**
   * Validate data against schema
   */
  static validate<T>(schema: z.ZodSchema<T>, data: unknown): ValidationResult & { data?: T } {
    try {
      const validatedData = schema.parse(data);
      return {
        isValid: true,
        errors: [],
        data: validatedData,
      };
    } catch (error) {
      if (error instanceof z.ZodError) {
        return {
          isValid: false,
          errors: error.errors.map(err => `${err.path.join('.')}: ${err.message}`),
        };
      }
      return {
        isValid: false,
        errors: ['Validation failed'],
      };
    }
  }

  /**
   * Sanitize user input
   */
  static sanitize(input: string): string {
    return input
      .trim()
      .replace(/[<>]/g, '') // Remove potential HTML tags
      .replace(/javascript:/gi, '') // Remove javascript: protocols
      .replace(/on\w+=/gi, ''); // Remove event handlers
  }

  /**
   * Create custom validation middleware for Express
   */
  static createValidationMiddleware<T>(schema: z.ZodSchema<T>) {
    return (req: any, res: any, next: any) => {
      const result = ErifyValidator.validate(schema, req.body);
      
      if (!result.isValid) {
        return res.status(400).json({
          error: 'Validation failed',
          details: result.errors,
        });
      }

      req.validatedData = result.data;
      next();
    };
  }
}

/**
 * Rate limiting validator
 */
export class RateLimitValidator {
  private attempts = new Map<string, { count: number; resetTime: number }>();

  validate(
    identifier: string,
    maxAttempts: number,
    windowMs: number
  ): ValidationResult {
    const now = Date.now();
    const attempt = this.attempts.get(identifier) || { count: 0, resetTime: now + windowMs };

    if (now > attempt.resetTime) {
      attempt.count = 0;
      attempt.resetTime = now + windowMs;
    }

    if (attempt.count >= maxAttempts) {
      return {
        isValid: false,
        errors: [`Too many attempts. Try again in ${Math.ceil((attempt.resetTime - now) / 1000)} seconds`],
      };
    }

    attempt.count++;
    this.attempts.set(identifier, attempt);

    return {
      isValid: true,
      errors: [],
      data: { remaining: maxAttempts - attempt.count },
    };
  }
}

/**
 * File upload validation
 */
export const validateFileUpload = (
  file: { mimetype: string; size: number; originalname: string },
  options: {
    allowedTypes?: string[];
    maxSize?: number; // in bytes
    allowedExtensions?: string[];
  } = {}
): ValidationResult => {
  const {
    allowedTypes = ['image/jpeg', 'image/png', 'image/gif'],
    maxSize = 5 * 1024 * 1024, // 5MB
    allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif'],
  } = options;

  const errors: string[] = [];

  // Check file type
  if (!allowedTypes.includes(file.mimetype)) {
    errors.push(`File type ${file.mimetype} not allowed`);
  }

  // Check file size
  if (file.size > maxSize) {
    errors.push(`File size ${file.size} exceeds maximum ${maxSize} bytes`);
  }

  // Check file extension
  const extension = file.originalname.toLowerCase().substring(file.originalname.lastIndexOf('.'));
  if (!allowedExtensions.includes(extension)) {
    errors.push(`File extension ${extension} not allowed`);
  }

  return {
    isValid: errors.length === 0,
    errors,
    data: errors.length === 0 ? file : undefined,
  };
};

/**
 * Example usage snippets
 */
export const validationExamples = {
  // Basic validation
  basicValidation: `
const emailResult = validateEmail('user@example.com');
const passwordResult = validatePassword('SecurePass123!');
const phoneResult = validatePhoneNumber('+1234567890', 'US');

if (!emailResult.isValid) {
  console.log('Email errors:', emailResult.errors);
}
  `,

  // Schema validation
  schemaValidation: `
const registrationData = {
  email: 'user@example.com',
  password: 'SecurePass123!',
  firstName: 'John',
  lastName: 'Doe',
  agreeToTerms: true,
};

const result = ErifyValidator.validate(
  ErifyValidator.userRegistrationSchema,
  registrationData
);

if (result.isValid) {
  console.log('Valid user data:', result.data);
} else {
  console.log('Validation errors:', result.errors);
}
  `,

  // Express middleware
  expressMiddleware: `
const validateRegistration = ErifyValidator.createValidationMiddleware(
  ErifyValidator.userRegistrationSchema
);

app.post('/register', validateRegistration, (req, res) => {
  // req.validatedData contains the validated and typed data
  const userData = req.validatedData;
  // Proceed with registration logic
});
  `,
};