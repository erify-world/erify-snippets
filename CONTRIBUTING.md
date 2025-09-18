# Contributing to ERIFY™ Snippets

Thank you for your interest in contributing to ERIFY™ Snippets! This document provides guidelines for contributing to this project.

## Development Setup

1. **Fork and Clone**
   ```bash
   git clone https://github.com/your-username/erify-snippets.git
   cd erify-snippets
   ```

2. **Install Dependencies**
   ```bash
   npm install
   ```

3. **Development Commands**
   ```bash
   npm run build     # Build TypeScript
   npm run dev       # Watch mode for development
   npm test          # Run tests
   npm run lint      # Run linter
   npm run format    # Format code
   ```

## Project Structure

```
src/
├── auth/           # OAuth, JWT, middleware
├── session/        # Session management
├── payments/       # Payment providers
├── validation/     # Input validation
├── cloudflare/     # Cloudflare Workers utilities
├── types/          # TypeScript definitions
└── examples/       # Usage examples
```

## Coding Standards

- **TypeScript**: Use strict type checking
- **ESLint**: Follow the configured rules
- **Prettier**: Code formatting is automated
- **Tests**: Write tests for new functionality
- **Documentation**: Update README for new features

## Adding New Features

1. **Create Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Implement Changes**
   - Add TypeScript types in `src/types/`
   - Implement functionality in appropriate module
   - Add comprehensive JSDoc comments
   - Include usage examples

3. **Testing**
   ```bash
   npm test           # Run existing tests
   npm run build      # Ensure builds successfully
   npm run lint       # Check code quality
   ```

4. **Documentation**
   - Update README.md if needed
   - Add examples to showcase new features
   - Update type definitions

## Pull Request Process

1. **Before Submitting**
   - Ensure all tests pass
   - Build completes without errors
   - Linting passes
   - Documentation is updated

2. **PR Description**
   - Clear description of changes
   - Link to related issues
   - Breaking changes noted
   - Examples of new functionality

3. **Review Process**
   - Maintainers will review code
   - Address feedback promptly
   - Ensure CI/CD passes

## Adding New Payment Providers

1. **Create Provider Class**
   ```typescript
   export class YourPaymentProvider {
     async createPaymentIntent(intent: PaymentIntent): Promise<PaymentResult> {
       // Implementation
     }
     
     async confirmPayment(paymentId: string): Promise<PaymentResult> {
       // Implementation
     }
   }
   ```

2. **Add to Examples**
   - Include setup example
   - Show integration pattern
   - Document configuration

## Adding New OAuth Providers

1. **Update OAuth Configuration**
   - Add provider to `createOAuthConfig`
   - Include auth/token/user info URLs
   - Define default scopes

2. **Test Integration**
   - Test auth flow
   - Verify token exchange
   - Validate user info retrieval

## Security Guidelines

- **No Secrets**: Never commit API keys or secrets
- **Input Validation**: Always validate user input
- **Error Handling**: Don't expose sensitive information
- **Dependencies**: Keep dependencies updated
- **Rate Limiting**: Implement appropriate limits

## Testing Guidelines

- **Unit Tests**: Test individual functions
- **Integration Tests**: Test provider integrations
- **Mock External APIs**: Don't make real API calls in tests
- **Coverage**: Aim for high test coverage
- **Edge Cases**: Test error conditions

## Release Process

1. **Version Bump**
   ```bash
   npm version patch|minor|major
   ```

2. **Build and Test**
   ```bash
   npm run build
   npm test
   ```

3. **Publish**
   ```bash
   npm publish
   ```

## Getting Help

- **Issues**: GitHub Issues for bugs/features
- **Discussions**: GitHub Discussions for questions
- **Discord**: [ERIFY™ Community](https://discord.gg/erify)
- **Email**: support@erify.world

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow
- Maintain professional communication

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to ERIFY™ Snippets!** 🚀