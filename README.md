# CodeSaviour - AI-Powered Code Analysis Platform

<div align="center">
  <h3>🚀 Enterprise-Grade Code Analysis & Security Platform</h3>
  <p>Revolutionizing code quality with AI-powered analysis, real-time security scanning, and intelligent debugging assistance.</p>
</div>

---

## 🌟 Overview

CodeSaviour is a comprehensive code analysis platform that combines the power of artificial intelligence with industry-standard security tools to provide developers with:

- **🔍 Advanced Code Analysis** - Deep static analysis using Semgrep and custom AI models
- **🛡️ Security Vulnerability Detection** - Real-time security scanning and threat identification
- **🤖 AI-Powered Code Generation** - Intelligent code completion and bug fixing
- **📊 Performance Monitoring** - Comprehensive metrics and performance insights
- **🔄 Real-time Collaboration** - WebSocket-based live code analysis
- **📈 Enterprise Dashboard** - Professional analytics and reporting

## 🏗️ Architecture

CodeSaviour consists of three main components:

```
┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│                     │    │                     │    │                     │
│   Frontend (React)  │◄──►│  AI Server (Python) │◄──►│ Enterprise Service  │
│                     │    │                     │    │     (Node.js)       │
│  • Landing Page     │    │  • Code Analysis    │    │  • Authentication   │
│  • Dashboard        │    │  • AI Generation    │    │  • User Management  │
│  • Real-time UI     │    │  • Security Scan    │    │  • Audit Logging    │
│                     │    │  • WebSocket API    │    │  • Performance     │
└─────────────────────┘    └─────────────────────┘    └─────────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- **Node.js** 18+ and npm
- **Python** 3.9+ with pip
- **MongoDB** 4.4+
- **Git** for version control

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd CodeSaviour
   ```

2. **Setup Frontend**
   ```bash
   cd code-savior-landing
   npm install
   cp .env.example .env
   # Configure your environment variables
   npm run dev
   ```

3. **Setup AI Server**
   ```bash
   cd ai-server
   pip install -r requirements.txt
   cp .env.example .env
   # Configure your AI model settings
   python main.py
   ```

4. **Setup Enterprise Service**
   ```bash
   cd enterprise-nodejs-service
   npm install
   cp .env.example .env
   # Configure MongoDB and JWT settings
   npm start
   ```

### Development Mode

Run all services simultaneously:

```bash
# Terminal 1 - Frontend
cd code-savior-landing && npm run dev

# Terminal 2 - AI Server
cd ai-server && python main.py

# Terminal 3 - Enterprise Service
cd enterprise-nodejs-service && npm start
```

## 📁 Project Structure

```
CodeSaviour/
├── 📂 code-savior-landing/          # React Frontend Application
│   ├── 📂 src/
│   │   ├── 📂 components/           # Reusable UI components
│   │   ├── 📂 pages/               # Application pages
│   │   ├── 📂 hooks/               # Custom React hooks
│   │   └── 📂 lib/                 # Utility libraries
│   ├── 📄 package.json
│   └── 📄 vite.config.ts
│
├── 📂 ai-server/                    # Python AI Analysis Server
│   ├── 📄 main.py                  # FastAPI application entry
│   ├── 📄 semgrep_analyzer.py      # Security analysis engine
│   ├── 📄 advanced_analyzer.py     # AI-powered analysis
│   ├── 📄 websocket_service.py     # Real-time communication
│   ├── 📄 requirements.txt         # Python dependencies
│   └── 📂 config/                  # Configuration files
│
├── 📂 enterprise-nodejs-service/    # Node.js Enterprise Backend
│   ├── 📄 server.js                # Express application entry
│   ├── 📂 routes/                  # API route handlers
│   ├── 📂 middleware/              # Custom middleware
│   ├── 📂 models/                  # Database models
│   ├── 📂 services/                # Business logic services
│   └── 📄 package.json
│
├── 📄 README.md                     # This file
├── 📄 .gitignore                    # Git ignore rules
└── 📄 DEPLOYMENT.md                 # Deployment instructions
```

## 🔧 Configuration

### Environment Variables

Each service requires specific environment variables:

#### Frontend (.env)
```env
VITE_CLERK_PUBLISHABLE_KEY=your_clerk_key
VITE_API_URL=http://localhost:8000
VITE_ENTERPRISE_API_URL=http://localhost:3000
```

#### AI Server (.env)
```env
FASTAPI_ENV=development
CORS_ORIGINS=http://localhost:5173
REDIS_URL=redis://localhost:6379
MODEL_PATH=./models/
```

#### Enterprise Service (.env)
```env
JWT_SECRET=your_super_secret_jwt_key
MONGODB_URI=mongodb://localhost:27017/codesaviour
PORT=3000
NODE_ENV=development
```

## 🛡️ Security Features

- **🔐 JWT Authentication** - Secure token-based authentication
- **🛡️ Helmet.js Protection** - Security headers and CSRF protection
- **⚡ Rate Limiting** - API abuse prevention
- **🔍 Input Validation** - Comprehensive request validation
- **📝 Audit Logging** - Complete activity tracking
- **🚫 CORS Configuration** - Secure cross-origin requests
- **🔒 Password Hashing** - bcrypt encryption for user passwords

## 🚀 API Documentation

### AI Server Endpoints

- `POST /analyze` - Analyze code for security vulnerabilities
- `POST /generate` - Generate code using AI models
- `GET /health` - Health check and system status
- `WS /ws` - WebSocket for real-time analysis

### Enterprise Service Endpoints

- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User authentication
- `GET /api/admin/users` - Admin user management
- `GET /api/health` - Service health check
- `GET /api/performance/metrics` - Performance metrics

## 🧪 Testing

### Frontend Testing
```bash
cd code-savior-landing
npm run test
npm run test:coverage
```

### Backend Testing
```bash
cd enterprise-nodejs-service
npm test
npm run test:security
```

### AI Server Testing
```bash
cd ai-server
python -m pytest tests/
python -m pytest --cov=. tests/
```

## 📊 Performance Monitoring

CodeSaviour includes comprehensive performance monitoring:

- **Response Time Tracking** - API endpoint performance
- **Memory Usage Monitoring** - Real-time memory consumption
- **Error Rate Analysis** - Error tracking and alerting
- **Database Performance** - Query optimization insights
- **WebSocket Connection Health** - Real-time connection monitoring

## 🚀 Deployment

### Production Deployment

1. **Build Frontend**
   ```bash
   cd code-savior-landing
   npm run build
   ```

2. **Deploy Services**
   ```bash
   # Use the provided deployment script
   ./deploy.ps1
   ```

3. **Environment Setup**
   - Configure production environment variables
   - Set up MongoDB cluster
   - Configure Redis for caching
   - Set up SSL certificates

### Docker Deployment

```bash
# Build and run with Docker Compose
docker-compose up -d
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow ESLint and Prettier configurations
- Write comprehensive tests for new features
- Update documentation for API changes
- Follow semantic versioning for releases

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

For support and questions:

- 📧 Email: support@codesaviour.com
- 💬 Discord: [CodeSaviour Community](https://discord.gg/codesaviour)
- 📖 Documentation: [docs.codesaviour.com](https://docs.codesaviour.com)
- 🐛 Issues: [GitHub Issues](https://github.com/codesaviour/issues)

## 🙏 Acknowledgments

- **Semgrep** - Static analysis engine
- **FastAPI** - High-performance Python web framework
- **React** - Frontend user interface library
- **Express.js** - Node.js web application framework
- **MongoDB** - Document database
- **Clerk** - Authentication and user management

---

<div align="center">
  <p>Made with ❤️ by the CodeSaviour Team</p>
  <p>⭐ Star us on GitHub if you find this project useful!</p>
</div>