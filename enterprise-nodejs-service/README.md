# Enterprise Node.js Service

A secure, enterprise-grade Node.js REST API service built with Express, MongoDB, and JWT authentication. This service implements industry best practices for security, error handling, logging, and scalability.

## 🚀 Features

- **Secure Authentication**: JWT-based authentication with bcrypt password hashing
- **Role-Based Access Control**: User and admin roles with proper authorization
- **Input Validation**: Comprehensive validation using express-validator
- **Rate Limiting**: Configurable rate limiting to prevent abuse
- **Security Headers**: Helmet.js for security headers and CORS protection
- **Error Handling**: Centralized error handling with detailed logging
- **Health Checks**: Multiple health check endpoints for monitoring
- **Logging**: Structured logging with Winston
- **Database**: MongoDB with Mongoose ODM
- **Modular Architecture**: Clean separation of concerns

## 📋 Prerequisites

- Node.js >= 16.0.0
- npm >= 8.0.0
- MongoDB >= 4.4

## 🛠️ Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd enterprise-nodejs-service
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables**
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` file with your configuration:
   ```env
   PORT=3000
   NODE_ENV=development
   MONGODB_URI=mongodb://localhost:27017/enterprise_service
   JWT_SECRET=your-super-secure-jwt-secret-key
   JWT_EXPIRES_IN=15m
   ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001
   ADMIN_EMAIL=admin@enterprise.com
   ADMIN_PASSWORD=SecureAdminPassword123!
   ```

4. **Start MongoDB**
   ```bash
   # Using MongoDB service
   sudo systemctl start mongod
   
   # Or using Docker
   docker run -d -p 27017:27017 --name mongodb mongo:latest
   ```

5. **Run the application**
   ```bash
   # Development mode with auto-reload
   npm run dev
   
   # Production mode
   npm start
   ```

## 📚 API Documentation

### Base URL
```
http://localhost:3000/api
```

### Authentication Endpoints

#### Register User
```http
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "confirmPassword": "SecurePassword123!"
}
```

#### Login User
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

#### Get Profile
```http
GET /api/auth/profile
Authorization: Bearer <jwt_token>
```

#### Update Profile
```http
PUT /api/auth/profile
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "email": "newemail@example.com"
}
```

#### Change Password
```http
PUT /api/auth/change-password
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "currentPassword": "OldPassword123!",
  "newPassword": "NewPassword123!",
  "confirmNewPassword": "NewPassword123!"
}
```

### Admin Endpoints

#### Get All Users
```http
GET /api/admin/users?page=1&limit=10&role=user&isActive=true
Authorization: Bearer <admin_jwt_token>
```

#### Get User by ID
```http
GET /api/admin/users/:id
Authorization: Bearer <admin_jwt_token>
```

#### Update User
```http
PUT /api/admin/users/:id
Authorization: Bearer <admin_jwt_token>
Content-Type: application/json

{
  "email": "updated@example.com",
  "role": "admin",
  "isActive": true
}
```

#### Delete User
```http
DELETE /api/admin/users/:id
Authorization: Bearer <admin_jwt_token>
```

#### Create User
```http
POST /api/admin/create-user
Authorization: Bearer <admin_jwt_token>
Content-Type: application/json

{
  "email": "newuser@example.com",
  "password": "SecurePassword123!",
  "role": "user",
  "isActive": true
}
```

#### Get System Stats
```http
GET /api/admin/stats
Authorization: Bearer <admin_jwt_token>
```

### Health Check Endpoints

#### Basic Health Check
```http
GET /api/health
```

#### Detailed Health Check
```http
GET /api/health/detailed
```

#### Database Health Check
```http
GET /api/health/database
```

#### Readiness Probe
```http
GET /api/health/readiness
```

#### Liveness Probe
```http
GET /api/health/liveness
```

## 🔒 Security Features

### Password Security
- Bcrypt hashing with configurable salt rounds
- Password strength validation (minimum 8 characters, uppercase, lowercase, number, special character)
- Account lockout after failed login attempts

### JWT Security
- Short token expiration (15 minutes default)
- Secure algorithm (HS256 only)
- Token validation on every request
- No sensitive data in token payload

### Rate Limiting
- Global rate limiting (100 requests per 15 minutes)
- Stricter auth endpoint limiting (5 attempts per 15 minutes)
- IP-based tracking

### CORS Protection
- Configurable allowed origins
- Credential support
- Proper preflight handling

### Security Headers
- Helmet.js for security headers
- Content Security Policy
- XSS protection
- CSRF protection

## 📊 Monitoring & Logging

### Log Files
- `logs/app.log` - General application logs
- `logs/error.log` - Error logs only
- `logs/access.log` - HTTP access logs (production)

### Log Levels
- `error` - Error messages
- `warn` - Warning messages
- `info` - Informational messages
- `http` - HTTP request logs
- `debug` - Debug messages

### Health Monitoring
The service provides multiple health check endpoints for monitoring:
- Basic health status
- Database connectivity
- System metrics
- Kubernetes probes

## 🏗️ Project Structure

```
enterprise-nodejs-service/
├── config/
│   └── db.js                 # Database configuration
├── middleware/
│   ├── auth.js              # Authentication middleware
│   └── errorHandler.js      # Error handling middleware
├── models/
│   └── User.js              # User model
├── routes/
│   ├── auth.js              # Authentication routes
│   ├── admin.js             # Admin routes
│   └── health.js            # Health check routes
├── utils/
│   └── logger.js            # Logging utility
├── logs/                    # Log files directory
├── .env                     # Environment variables
├── .env.example            # Environment variables template
├── package.json            # Dependencies and scripts
├── server.js               # Main application file
└── README.md               # This file
```

## 🚀 Deployment

### Environment Variables for Production

```env
NODE_ENV=production
PORT=3000
MONGODB_URI=mongodb://your-production-db/enterprise_service
JWT_SECRET=your-super-secure-production-jwt-secret
JWT_EXPIRES_IN=15m
ALLOWED_ORIGINS=https://yourdomain.com,https://app.yourdomain.com
BCRYPT_SALT_ROUNDS=12
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
LOG_LEVEL=info
ADMIN_EMAIL=admin@yourdomain.com
ADMIN_PASSWORD=YourSecureAdminPassword
```

### Docker Deployment

```dockerfile
FROM node:16-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3000
CMD ["npm", "start"]
```

### PM2 Deployment

```bash
# Install PM2
npm install -g pm2

# Start application
pm2 start server.js --name "enterprise-service"

# Monitor
pm2 monit

# Logs
pm2 logs enterprise-service
```

## 🧪 Testing

### Manual Testing with curl

```bash
# Register a new user
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPassword123!",
    "confirmPassword": "TestPassword123!"
  }'

# Login
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPassword123!"
  }'

# Access protected route
curl -X GET http://localhost:3000/api/auth/profile \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|----------|
| `PORT` | Server port | `3000` |
| `NODE_ENV` | Environment | `development` |
| `MONGODB_URI` | MongoDB connection string | Required |
| `JWT_SECRET` | JWT signing secret | Required |
| `JWT_EXPIRES_IN` | JWT expiration time | `15m` |
| `ALLOWED_ORIGINS` | CORS allowed origins | `http://localhost:3000` |
| `BCRYPT_SALT_ROUNDS` | Bcrypt salt rounds | `12` |
| `RATE_LIMIT_WINDOW_MS` | Rate limit window | `900000` (15 min) |
| `RATE_LIMIT_MAX_REQUESTS` | Max requests per window | `100` |
| `LOG_LEVEL` | Logging level | `info` |
| `ADMIN_EMAIL` | Default admin email | Optional |
| `ADMIN_PASSWORD` | Default admin password | Optional |

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue in the repository
- Check the logs in the `logs/` directory
- Review the health check endpoints for system status

## 🔄 Changelog

### v1.0.0
- Initial release
- JWT authentication
- User management
- Admin panel
- Health checks
- Security features
- Comprehensive logging