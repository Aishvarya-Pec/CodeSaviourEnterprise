# CodeSaviour Microservices Architecture

A scalable, containerized microservices architecture for the CodeSaviour AI-powered code analysis platform.

## Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │  API Gateway    │    │  Monitoring     │
│   (React)       │◄──►│   (Nginx)       │◄──►│ (Prometheus)    │
│   Port: 3000    │    │   Port: 8080    │    │   Port: 9090    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                                ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   AI Server     │    │ Enterprise      │    │    Database     │
│   (Python)      │    │   Service       │    │ (PostgreSQL)    │
│   Port: 5000    │    │  (Node.js)      │    │   Port: 5432    │
└─────────────────┘    │   Port: 3000    │    └─────────────────┘
                       └─────────────────┘
                                │
                                ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│     Redis       │    │   Grafana       │    │  Elasticsearch  │
│    (Cache)      │    │ (Dashboards)    │    │   (Logging)     │
│   Port: 6379    │    │   Port: 3001    │    │   Port: 9200    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Services

### Core Services

1. **Frontend** - React application with modern UI
2. **API Gateway** - Nginx-based routing and load balancing
3. **AI Server** - Python-based AI analysis service with GraphQL
4. **Enterprise Service** - Node.js authentication and admin service

### Infrastructure Services

5. **PostgreSQL** - Primary database
6. **Redis** - Caching and session storage
7. **Prometheus** - Metrics collection
8. **Grafana** - Monitoring dashboards
9. **ELK Stack** - Centralized logging

## Quick Start

### Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- 8GB+ RAM recommended
- 20GB+ disk space

### Environment Setup

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd CodeSaviour
   ```

2. **Configure environment variables:**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Start all services:**
   ```bash
   docker-compose up -d
   ```

4. **Verify deployment:**
   ```bash
   docker-compose ps
   ```

### Service URLs

- **Frontend:** http://localhost:3000
- **API Gateway:** http://localhost:8080
- **GraphQL Playground:** http://localhost:8080/graphql
- **Grafana:** http://localhost:3001 (admin/password from .env)
- **Prometheus:** http://localhost:9090
- **Kibana:** http://localhost:5601

## API Endpoints

### Through API Gateway (Port 8080)

```
GET  /health                    # Health check
POST /api/v1/analyze           # Code analysis
POST /graphql                  # GraphQL endpoint
WS   /ws                       # WebSocket connection
POST /api/v1/auth/login        # Authentication
GET  /api/v1/users             # User management
GET  /metrics                  # Prometheus metrics
```

## Development

### Local Development

1. **Start infrastructure services only:**
   ```bash
   docker-compose up -d postgres redis
   ```

2. **Run services locally:**
   ```bash
   # AI Server
   cd code-savior-landing/ai-server
   pip install -r requirements.txt
   python main.py

   # Enterprise Service
   cd enterprise-nodejs-service
   npm install
   npm start

   # Frontend
   cd code-savior-landing
   npm install
   npm run dev
   ```

### Building Images

```bash
# Build all images
docker-compose build

# Build specific service
docker-compose build ai-server
```

### Scaling Services

```bash
# Scale AI server to 3 instances
docker-compose up -d --scale ai-server=3

# Scale enterprise service
docker-compose up -d --scale enterprise-service=2
```

## Monitoring

### Prometheus Metrics

- **Application metrics:** Custom business metrics
- **System metrics:** CPU, memory, disk usage
- **Container metrics:** Docker container statistics
- **Network metrics:** Request rates, response times

### Grafana Dashboards

- **System Overview:** Infrastructure health
- **Application Performance:** Service-specific metrics
- **Business Metrics:** User activity, analysis requests
- **Alerts:** Critical system notifications

### Log Aggregation

- **Centralized logging** via ELK stack
- **Structured JSON logs** from all services
- **Log correlation** across microservices
- **Search and analytics** in Kibana

## Security

### Network Security

- **Internal network:** Services communicate via Docker network
- **Rate limiting:** Nginx-based request throttling
- **CORS protection:** Configured origins
- **Security headers:** XSS, CSRF protection

### Authentication

- **JWT tokens:** Stateless authentication
- **Refresh tokens:** Secure token renewal
- **Role-based access:** Admin and user roles
- **API key management:** External service authentication

## Deployment

### Production Deployment

1. **Configure production environment:**
   ```bash
   cp .env.example .env.production
   # Set production values
   ```

2. **Deploy with production compose:**
   ```bash
   docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
   ```

### Health Checks

All services include health checks:
- **Startup probes:** Service initialization
- **Liveness probes:** Service availability
- **Readiness probes:** Traffic acceptance

### Backup Strategy

```bash
# Database backup
docker-compose exec postgres pg_dump -U postgres codesaviour > backup.sql

# Redis backup
docker-compose exec redis redis-cli BGSAVE
```

## Troubleshooting

### Common Issues

1. **Port conflicts:**
   ```bash
   # Check port usage
   netstat -tulpn | grep :8080
   ```

2. **Memory issues:**
   ```bash
   # Monitor resource usage
   docker stats
   ```

3. **Service logs:**
   ```bash
   # View specific service logs
   docker-compose logs -f ai-server
   ```

### Performance Tuning

- **Database:** Connection pooling, query optimization
- **Redis:** Memory management, persistence settings
- **Nginx:** Worker processes, connection limits
- **Python:** Gunicorn workers, async processing

## Contributing

1. **Fork the repository**
2. **Create feature branch:** `git checkout -b feature/amazing-feature`
3. **Commit changes:** `git commit -m 'Add amazing feature'`
4. **Push to branch:** `git push origin feature/amazing-feature`
5. **Open Pull Request**

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:
- **Documentation:** [Wiki](wiki-url)
- **Issues:** [GitHub Issues](issues-url)
- **Discussions:** [GitHub Discussions](discussions-url)