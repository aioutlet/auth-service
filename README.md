# Auth Service !!!!

`auth service` is a microservice responsible for handling user authentication and authorization for the AIOutlet platform. It supports both traditional username/password login and social login via OAuth2 providers such as Google, Facebook, and Twitter. Upon successful authentication, it issues JWT tokens that can be used to access other microservices within the platform.

---

## Features

- User login with email and password
- Social login with Google, Facebook, and Twitter OAuth2
- Unified JWT token issuance for both local and social authentication flows
- Role-based access control (e.g., roles like `user`, `admin`)
- MongoDB for secure credential and session data storage
- Secure password hashing with bcrypt
- JWT validation middleware for protecting API routes
- Support for account linking (link social accounts to existing user profiles)
- Refresh token mechanism for improved security and session management
- Multi-factor authentication (MFA) support for enhanced account security
- Integration hooks for API Gateway to manage authentication and routing

---

## Architecture

This service is built with Node.js and Express, using Passport.js for authentication strategies and Mongoose for MongoDB object modeling.

The microservice is designed to be deployed independently and can run locally, via Docker, or in Kubernetes (AKS).

---

## Getting Started

### Prerequisites

- Node.js v16+
- MongoDB instance (local, Docker, or cloud)
- OAuth2 credentials for Google, Facebook, and Twitter (for social login)

### Environment Variables

Create a `.env` file in the root with the following variables:

```env
PORT=4000
MONGO_URI=mongodb://localhost:27017/auth-service-db
JWT_SECRET=your_jwt_secret_key
SESSION_SECRET=your_session_secret_key

GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_CALLBACK_URL=http://localhost:4000/auth/google/callback

FACEBOOK_APP_ID=your_facebook_app_id
FACEBOOK_APP_SECRET=your_facebook_app_secret
FACEBOOK_CALLBACK_URL=http://localhost:4000/auth/facebook/callback

TWITTER_CONSUMER_KEY=your_twitter_consumer_key
TWITTER_CONSUMER_SECRET=your_twitter_consumer_secret
TWITTER_CALLBACK_URL=http://localhost:4000/auth/twitter/callback
```

### Installation

```bash
git clone https://github.com/aioutlet/auth-service.git
cd auth-service
npm install
```

### Running Locally

```bash
npm start
```

The service will be available at `http://localhost:4000`.

---

## API Endpoints

| Method | Endpoint                  | Description                                |
| ------ | ------------------------- | ------------------------------------------ |
| POST   | `/auth/login`             | Login with email/password                  |
| POST   | `/auth/logout`            | Logout user / invalidate session           |
| POST   | `/auth/refresh-token`     | Refresh JWT token                          |
| POST   | `/auth/forgot-password`   | Initiate password reset (send reset email) |
| POST   | `/auth/reset-password`    | Reset password using reset token           |
| POST   | `/auth/change-password`   | Change password (authenticated user)       |
| POST   | `/auth/verify-email`      | Verify user email using verification token |
| GET    | `/auth/google`            | Redirect to Google OAuth login             |
| GET    | `/auth/google/callback`   | Google OAuth callback                      |
| GET    | `/auth/facebook`          | Redirect to Facebook OAuth login           |
| GET    | `/auth/facebook/callback` | Facebook OAuth callback                    |
| GET    | `/auth/twitter`           | Redirect to Twitter OAuth login            |
| GET    | `/auth/twitter/callback`  | Twitter OAuth callback                     |
| GET    | `/auth/me`                | Get current user info (requires JWT)       |

---

## Folder Structure

```text
auth-service/
├── src/
│   ├── app.js
│   ├── config/
│   │   ├── passport.js            # Passport strategies & OAuth config
│   │   ├── mfa.config.js          # MFA settings & config
│   │   └── apiGateway.config.js   # API Gateway integration config
│   ├── controllers/
│   │   ├── auth.controller.js     # Auth route handlers (login, logout, etc.)
│   │   ├── mfa.controller.js      # MFA endpoints (verify code, enable/disable)
│   │   └── accountLink.controller.js  # Social/local account linking handlers
│   ├── middlewares/
│   │   ├── auth.middleware.js     # JWT validation middleware
│   │   ├── refreshToken.middleware.js # Refresh token validation
│   │   └── mfa.middleware.js      # MFA verification middleware
│   ├── models/
│   │   ├── user.model.js          # User schema with social accounts, MFA fields
│   │   ├── refreshToken.model.js # Refresh tokens schema/storage
│   │   └── mfa.model.js           # (Optional) MFA device/session model
│   ├── routes/
│   │   ├── auth.routes.js         # Auth routes (login, logout, forgot/reset password)
│   │   ├── mfa.routes.js          # Routes for MFA enable/verify/reset
│   │   └── accountLink.routes.js  # Routes for linking/unlinking accounts
│   ├── services/
│   │   ├── auth.service.js        # Auth business logic (login, register, social login)
│   │   ├── mfa.service.js         # MFA business logic (generate/validate codes)
│   │   └── accountLink.service.js # Account linking logic
│   ├── utils/
│   │   ├── jwt.js                 # JWT sign/verify helpers
│   │   ├── email.js               # Email sending helpers (for verification, reset)
│   │   ├── oauth.js               # OAuth helper functions
│   │   └── logger.js              # Centralized logging utility
│   └── validators/
│       ├── auth.validator.js     # Input validation for auth endpoints
│       ├── mfa.validator.js      # Validation for MFA related input
│       └── accountLink.validator.js # Validation for account linking input
├── tests/
│   ├── auth.test.js              # Unit and integration tests for auth
│   ├── mfa.test.js               # Tests for MFA flows
│   └── accountLink.test.js       # Tests for account linking
├── .env.example                  # Sample environment variables file
├── Dockerfile                   # Dockerfile to containerize the service
├── docker-compose.yml           # Optional: to run auth-service with dependencies
├── package.json                 # Node.js dependencies and scripts
├── README.md                    # Service documentation
└── LICENSE                      # License file

```

---

## Contributing

Contributions are welcome! Please open issues or submit pull requests.

---

## License

MIT License

---

## Contact

For questions or support, reach out to the AIOutlet dev team.
