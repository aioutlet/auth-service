# Copilot Instructions — auth-service

## Service Identity

- **Name**: auth-service
- **Purpose**: Authentication gateway — login, registration, JWT token management, session handling
- **Port**: 8004
- **Language**: Node.js 20+ (JavaScript ESM)
- **Framework**: Express 5.1+
- **Database**: Stateless — delegates user storage to user-service via Dapr
- **Dapr App ID**: `auth-service`

## Architecture

- **Pattern**: Stateless authentication gateway — no own database
- **API Style**: RESTful JSON APIs
- **Authentication**: Issues and validates JWT access + refresh tokens
- **Password Hashing**: bcrypt
- **Messaging**: Dapr pub/sub for auth events (login, register, logout)
- **Event Format**: CloudEvents 1.0 specification
- **Service Calls**: Calls user-service via Dapr service invocation for user lookup/creation

## Project Structure

```
auth-service/
├── src/
│   ├── controllers/     # Auth endpoint handlers
│   ├── middlewares/      # Auth middleware, logging, tracing
│   ├── validators/      # Input validation
│   ├── routes/          # Route definitions
│   ├── clients/         # Dapr service invocation clients (user-service)
│   └── core/            # Config, logger, errors
├── tests/
│   ├── unit/
│   ├── integration/
│   └── e2e/
├── .dapr/components/
└── package.json
```

## Code Conventions

- **ESM modules** (`import/export`)
- **Express 5.1+** with async error handling
- Structured logging via **Winston**
- Use **bcrypt** for password hashing (salt rounds = 12)
- JWT tokens: access token (short-lived) + refresh token (long-lived)
- Error handling: custom `ErrorResponse` class
- Correlation IDs propagated via `X-Correlation-ID` header

## Key Patterns

- **No database** — auth-service is stateless; user data fetched from user-service
- Token generation: `jsonwebtoken` library
- Token payload: `{ id, email, roles, iat, exp }`
- Refresh token rotation pattern
- Rate limiting on login endpoint

## Testing Requirements

- All new controllers MUST have unit tests
- All new routes MUST have integration or e2e tests
- Use **Jest** as the test framework
- Mock Dapr calls and user-service invocations in unit tests via `jest.mock()`
- Do NOT call real user-service or Dapr in unit tests
- Test valid inputs, invalid inputs, missing authentication, and service failures
- Run: `npm test`, `npm run test:unit`, `npm run test:coverage`

## Dapr Integration

- **Pub/Sub**: Publishes `auth.login`, `auth.register`, `auth.logout` events
- **Service Invocation**: Calls `user-service` to validate credentials and create users
- **Ports**: Dapr HTTP 3500, Dapr gRPC 50001

## Security Rules

- All request bodies MUST be validated using input validators before reaching controller logic
- Rate limiting MUST be applied to the login endpoint to prevent brute-force attacks
- Passwords MUST be hashed using **bcrypt** with 12 salt rounds — never store or compare plain-text passwords
- JWT payload MUST only contain `{ id, email, roles, iat, exp }` — never include sensitive data
- Refresh token rotation MUST be enforced: invalidate old token on each use
- Never log JWT tokens, refresh tokens, or plain-text passwords
- Sanitize all inputs before processing

## Error Handling Contract

All errors MUST follow this JSON structure:

```json
{
  "error": {
    "code": "STRING_CODE",
    "message": "Human readable message",
    "correlationId": "uuid"
  }
}
```

- Never expose stack traces in production
- Use centralized error middleware only

## Logging Rules

- Use structured JSON logging only
- Include:
  - timestamp
  - level
  - serviceName
  - correlationId
  - message
- Never log JWT tokens
- Never log secrets or plain-text passwords

## Non-Goals

- This service is NOT responsible for user profile management — handled by user-service
- This service does NOT enforce admin roles or admin operations — handled by admin-service
- This service does NOT store persistent user state — stateless, delegates to user-service
- This service does NOT directly manage database records for user profiles

## Environment Variables

```
PORT=8004
NODE_ENV=development
JWT_SECRET=<shared-secret>
JWT_EXPIRES_IN=1h
JWT_REFRESH_EXPIRES_IN=7d
USER_SERVICE_URL=http://localhost:8002
DAPR_HTTP_PORT=3500
```

## Common Commands

```bash
npm run dev              # Dev with hot reload
npm run dev:dapr         # Dev with Dapr sidecar
npm test                 # All tests
npm run test:coverage    # Coverage report
```
