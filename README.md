# PMS Backend Service

Core business logic and API endpoints for the Property Management System.

## Features

- RESTful API endpoints
- Database integration with Prisma ORM
- Redis caching
- JWT authentication
- Input validation with Zod
- Comprehensive error handling
- Health check endpoints
- Docker containerization

## Quick Start

```bash
# Install dependencies
npm install

# Set up environment variables
cp .env.example .env

# Run in development mode
npm run dev

# Build for production
npm run build

# Start production server
npm start
```

## API Endpoints

### Health Check
- `GET /health` - Service health status
- `GET /ready` - Kubernetes readiness probe
- `GET /live` - Kubernetes liveness probe

### Authentication
- `POST /auth/login` - User login
- `POST /auth/register` - User registration
- `POST /auth/refresh` - Refresh JWT token

### Properties
- `GET /properties` - List properties
- `POST /properties` - Create property
- `GET /properties/:id` - Get property details
- `PUT /properties/:id` - Update property
- `DELETE /properties/:id` - Delete property

### Bookings
- `GET /bookings` - List bookings
- `POST /bookings` - Create booking
- `GET /bookings/:id` - Get booking details
- `PUT /bookings/:id` - Update booking
- `DELETE /bookings/:id` - Cancel booking

## Environment Variables

```env
NODE_ENV=development
PORT=5000
DATABASE_URL=postgresql://user:password@localhost:5432/pms
REDIS_URL=redis://localhost:6379
JWT_SECRET=your-jwt-secret
JWT_EXPIRES_IN=7d
```

## Development

```bash
# Run tests
npm test

# Run tests in watch mode
npm run test:watch

# Check types
npm run type-check

# Lint code
npm run lint

# Fix linting issues
npm run lint:fix
```

## Docker

```bash
# Build image
docker build -t pms-backend .

# Run container
docker run -p 5000:5000 pms-backend
```

## Part of PMS Platform

This service is part of the complete Property Management System by Cosmos Order Ltd.

- **Main Repository**: [pms-platform](https://github.com/Cosmos-Order-Ltd/pms-platform)
- **Documentation**: [pms-docs](https://github.com/Cosmos-Order-Ltd/pms-docs)
- **Infrastructure**: [pms-infrastructure](https://github.com/Cosmos-Order-Ltd/pms-infrastructure)