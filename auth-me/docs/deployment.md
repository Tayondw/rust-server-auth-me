# Deployment Guide

This guide covers deploying the Auth-Me authentication system to various environments.

## Prerequisites

- Docker and Docker Compose
- PostgreSQL 13+
- Redis 6+
- SSL certificate (for production)
- Email service (SMTP)

## Environment Configuration

### Production Environment Variables

Create a `.env.production` file:

```bash
# Database
DATABASE_URL=postgresql://username:password@db-host:5432/auth_me_prod
SCHEMA=public

# JWT Secrets (Generate with: openssl rand -base64 32)
JWT_SECRET=your-super-secure-32-char-secret-here
JWT_REFRESH_SECRET=different-32-char-refresh-secret
JWT_EXPIRES_IN=15
JWT_REFRESH_EXPIRES_IN=10080

# Server
PORT=8080
ENVIRONMENT=production
RUST_LOG=info,diesel=warn

# Redis
REDIS_URL=redis://redis-host:6379
RATE_LIMIT_RPM=100

# Email (Example with SendGrid)
SMTP_SERVER=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USERNAME=apikey
SMTP_PASSWORD=your-sendgrid-api-key
SMTP_FROM_ADDRESS=noreply@yourdomain.com

# AWS S3 (Optional)
AWS_S3_BUCKET_NAME=your-production-bucket
AWS_S3_KEY=AKIA...
AWS_S3_SECRET=your-secret-key
AWS_REGION=us-east-1

# Admin User
INITIAL_ADMIN_EMAIL=admin@yourdomain.com
INITIAL_ADMIN_USERNAME=admin
INITIAL_ADMIN_PASSWORD=secure-admin-password
INITIAL_ADMIN_NAME=System Administrator
```

### Security Considerations

1. **JWT Secrets**: Generate cryptographically secure secrets
2. **Database**: Use connection pooling and SSL
3. **Redis**: Enable authentication and use SSL
4. **HTTPS**: Always use HTTPS in production
5. **Firewall**: Restrict access to necessary ports only

## Docker Deployment

### Single Server Deployment

**docker-compose.prod.yml:**

```yaml
version: '3.8'

services:
  app:
    image: your-registry/auth-me:latest
    container_name: auth-me-prod
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=${DATABASE_URL}
      - REDIS_URL=${REDIS_URL}
      - JWT_SECRET=${JWT_SECRET}
      - JWT_REFRESH_SECRET=${JWT_REFRESH_SECRET}
      - ENVIRONMENT=production
    env_file:
      - .env.production
    depends_on:
      - postgres
      - redis
    networks:
      - auth-me-network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  postgres:
    image: postgres:15-alpine
    container_name: auth-me-postgres-prod
    restart: unless-stopped
    environment:
      POSTGRES_DB: auth_me_prod
      POSTGRES_USER: ${DB_USER}
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./backups:/backups
    networks:
      - auth-me-network
    ports:
      - "5432:5432"

  redis:
    image: redis:7-alpine
    container_name: auth-me-redis-prod
    restart: unless-stopped
    command: redis-server --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    networks:
      - auth-me-network
    ports:
      - "6379:6379"

  nginx:
    image: nginx:alpine
    container_name: auth-me-nginx
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - app
    networks:
      - auth-me-network

volumes:
  postgres_data:
  redis_data:

networks:
  auth-me-network:
    driver: bridge
```

**Deploy:**

```bash
# Build and push image
docker build -t your-registry/auth-me:latest .
docker push your-registry/auth-me:latest

# Deploy
docker-compose -f docker-compose.prod.yml up -d

# Run migrations
docker-compose -f docker-compose.prod.yml exec app diesel migration run
```

### Nginx Configuration

**nginx.conf:**

```nginx
events {
    worker_connections 1024;
}

http {
    upstream auth_me {
        server app:8080;
    }

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;

    server {
        listen 80;
        server_name yourdomain.com;
        return 301 https://$server_name$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name yourdomain.com;

        # SSL Configuration
        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
        ssl_prefer_server_ciphers off;

        # Security Headers
        add_header X-Frame-Options DENY;
        add_header X-Content-Type-Options nosniff;
        add_header X-XSS-Protection "1; mode=block";
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

        # API Routes
        location /api/ {
            limit_req zone=api burst=20 nodelay;
            proxy_pass http://auth_me;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Auth Routes (stricter rate limiting)
        location /auth/login {
            limit_req zone=login burst=5 nodelay;
            proxy_pass http://auth_me;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Health Check
        location /health {
            proxy_pass http://auth_me;
            access_log off;
        }

        # All other routes
        location / {
            proxy_pass http://auth_me;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
}
```

## Kubernetes Deployment

### Namespace and ConfigMap

**k8s/namespace.yaml:**

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: auth-me
```

**k8s/configmap.yaml:**

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: auth-me-config
  namespace: auth-me
data:
  ENVIRONMENT: "production"
  RUST_LOG: "info,diesel=warn"
  PORT: "8080"
  SCHEMA: "public"
  JWT_EXPIRES_IN: "15"
  JWT_REFRESH_EXPIRES_IN: "10080"
  RATE_LIMIT_RPM: "100"
  SMTP_SERVER: "smtp.sendgrid.net"
  SMTP_PORT: "587"
  SMTP_USERNAME: "apikey"
  SMTP_FROM_ADDRESS: "noreply@yourdomain.com"
  AWS_REGION: "us-east-1"
```

### Secrets

**k8s/secrets.yaml:**

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: auth-me-secrets
  namespace: auth-me
type: Opaque
data:
  DATABASE_URL: <base64-encoded-database-url>
  REDIS_URL: <base64-encoded-redis-url>
  JWT_SECRET: <base64-encoded-jwt-secret>
  JWT_REFRESH_SECRET: <base64-encoded-refresh-secret>
  SMTP_PASSWORD: <base64-encoded-smtp-password>
  AWS_S3_KEY: <base64-encoded-aws-key>
  AWS_S3_SECRET: <base64-encoded-aws-secret>
  AWS_S3_BUCKET_NAME: <base64-encoded-bucket-name>
```

### Deployment

**k8s/deployment.yaml:**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-me
  namespace: auth-me
  labels:
    app: auth-me
spec:
  replicas: 3
  selector:
    matchLabels:
      app: auth-me
  template:
    metadata:
      labels:
        app: auth-me
    spec:
      containers:
      - name: auth-me
        image: your-registry/auth-me:latest
        ports:
        - containerPort: 8080
        envFrom:
        - configMapRef:
            name: auth-me-config
        - secretRef:
            name: auth-me-secrets
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
```

### Service and Ingress

**k8s/service.yaml:**

```yaml
apiVersion: v1
kind: Service
metadata:
  name: auth-me-service
  namespace: auth-me
spec:
  selector:
    app: auth-me
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8080
  type: ClusterIP
```

**k8s/ingress.yaml:**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: auth-me-ingress
  namespace: auth-me
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/rate-limit: "100"
    nginx.ingress.kubernetes.io/rate-limit-window: "1m"
spec:
  tls:
  - hosts:
    - api.yourdomain.com
    secretName: auth-me-tls
  rules:
  - host: api.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: auth-me-service
            port:
              number: 80
```

### Deploy to Kubernetes

```bash
# Apply all configurations
kubectl apply -f k8s/

# Check deployment status
kubectl get pods -n auth-me
kubectl get services -n auth-me
kubectl get ingress -n auth-me

# View logs
kubectl logs -f deployment/auth-me -n auth-me

# Run migrations (one-time job)
kubectl run --rm -i auth-me-migrate --image=your-registry/auth-me:latest --restart=Never --namespace=auth-me -- diesel migration run
```

## Cloud Provider Deployments

### AWS ECS with Fargate

**ecs-task-definition.json:**

```json
{
  "family": "auth-me",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::ACCOUNT:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::ACCOUNT:role/ecsTaskRole",
  "containerDefinitions": [
    {
      "name": "auth-me",
      "image": "your-account.dkr.ecr.region.amazonaws.com/auth-me:latest",
      "portMappings": [
        {
          "containerPort": 8080,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {"name": "ENVIRONMENT", "value": "production"},
        {"name": "PORT", "value": "8080"}
      ],
      "secrets": [
        {
          "name": "DATABASE_URL",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:auth-me/database-url"
        },
        {
          "name": "JWT_SECRET",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:auth-me/jwt-secret"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/auth-me",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -f http://localhost:8080/health || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3
      }
    }
  ]
}
```

### Google Cloud Run

**cloudbuild.yaml:**

```yaml
steps:
  - name: 'gcr.io/cloud-builders/docker'
    args: ['build', '-t', 'gcr.io/$PROJECT_ID/auth-me:$COMMIT_SHA', '.']
  - name: 'gcr.io/cloud-builders/docker'
    args: ['push', 'gcr.io/$PROJECT_ID/auth-me:$COMMIT_SHA']
  - name: 'gcr.io/google.com/cloudsdktool/cloud-sdk'
    entrypoint: gcloud
    args:
    - 'run'
    - 'deploy'
    - 'auth-me'
    - '--image'
    - 'gcr.io/$PROJECT_ID/auth-me:$COMMIT_SHA'
    - '--region'
    - 'us-central1'
    - '--platform'
    - 'managed'
    - '--allow-unauthenticated'
```

## Database Setup

### PostgreSQL Configuration

**postgresql.conf optimizations:**

```ini
# Memory settings
shared_buffers = 256MB
effective_cache_size = 1GB
work_mem = 4MB
maintenance_work_mem = 64MB

# Connection settings
max_connections = 100
idle_in_transaction_session_timeout = 600000

# Logging
log_statement = 'mod'
log_min_duration_statement = 1000

# Performance
random_page_cost = 1.1
effective_io_concurrency = 200
```

### Database Backup

**backup-script.sh:**

```bash
#!/bin/bash
set -e

# Configuration
DB_NAME="auth_me_prod"
DB_USER="postgres"
DB_HOST="localhost"
BACKUP_DIR="/backups"
DATE=$(date +"%Y%m%d_%H%M%S")

# Create backup
pg_dump -h $DB_HOST -U $DB_USER -d $DB_NAME \
  --verbose --clean --no-owner --no-privileges \
  --format=custom > "$BACKUP_DIR/auth_me_backup_$DATE.dump"

# Compress old backups
find $BACKUP_DIR -name "*.dump" -mtime +7 -exec gzip {} \;

# Remove old compressed backups (older than 30 days)
find $BACKUP_DIR -name "*.dump.gz" -mtime +30 -delete

echo "Backup completed: auth_me_backup_$DATE.dump"
```

### Database Restore

```bash
#!/bin/bash
# Restore from backup
BACKUP_FILE="auth_me_backup_20240115_120000.dump"

# Drop and recreate database
dropdb auth_me_prod
createdb auth_me_prod

# Restore from backup
pg_restore -h localhost -U postgres -d auth_me_prod \
  --verbose --clean --no-owner --no-privileges \
  $BACKUP_FILE

# Run migrations to ensure schema is up to date
diesel migration run
```

## Monitoring and Observability

### Health Checks

The application provides comprehensive health checks:

```bash
# Basic health check
curl http://localhost:8080/health

# Detailed health with database/redis status
curl http://localhost:8080/health?detailed=true
```

### Metrics Collection

**prometheus.yml:**

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'auth-me'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'
    scrape_interval: 10s
```

### Logging

Configure structured logging:

```bash
# Production logging
RUST_LOG=info,auth_me=debug,diesel=warn

# Development logging
RUST_LOG=debug
```

### Alerting

**Example Prometheus alerts:**

```yaml
groups:
- name: auth-me.rules
  rules:
  - alert: AuthMeDown
    expr: up{job="auth-me"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Auth-Me service is down"

  - alert: HighErrorRate
    expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.1
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "High error rate detected"

  - alert: DatabaseConnectionFailure
    expr: auth_me_database_connection_errors > 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Database connection failures"
```

## Performance Tuning

### Application Tuning

```bash
# Environment variables for performance
DATABASE_POOL_SIZE=15
REDIS_POOL_SIZE=10
JWT_EXPIRES_IN=15  # Short-lived tokens for security
CACHE_TTL=300      # 5 minute cache TTL
RATE_LIMIT_RPM=100 # Adjust based on expected load
```

### Database Optimization

```sql
-- Create indexes for better performance
CREATE INDEX CONCURRENTLY idx_users_email_verified ON users(email, verified);
CREATE INDEX CONCURRENTLY idx_users_role_created_at ON users(role, created_at);
CREATE INDEX CONCURRENTLY idx_pending_users_token_expires ON pending_users(verification_token, token_expires_at);

-- Analyze tables for query optimization
ANALYZE users;
ANALYZE pending_users;
```

### Redis Configuration

```bash
# redis.conf optimizations for auth-me
maxmemory 256mb
maxmemory-policy allkeys-lru
save 900 1
save 300 10
save 60 10000
```

## Security Hardening

### Container Security

**Dockerfile.prod:**

```dockerfile
FROM rust:1.75-slim as builder
# ... build steps ...

FROM gcr.io/distroless/cc-debian12
COPY --from=builder /app/target/release/auth-me /auth-me
COPY --from=builder /app/src/email/templates /templates
USER 1000:1000
EXPOSE 8080
ENTRYPOINT ["/auth-me"]
```

### Network Security

```bash
# Firewall rules (UFW example)
sudo ufw allow 22/tcp   # SSH
sudo ufw allow 80/tcp   # HTTP
sudo ufw allow 443/tcp  # HTTPS
sudo ufw deny 5432/tcp  # Block direct DB access
sudo ufw deny 6379/tcp  # Block direct Redis access
sudo ufw enable
```

### SSL/TLS Configuration

```bash
# Generate SSL certificate with Let's Encrypt
certbot certonly --webroot -w /var/www/html -d yourdomain.com

# Or use DNS challenge
certbot certonly --dns-cloudflare --dns-cloudflare-credentials ~/.secrets/cloudflare.ini -d yourdomain.com
```

## Troubleshooting

### Common Issues

1. **Database Connection Issues**
   ```bash
   # Check database connectivity
   psql $DATABASE_URL -c "SELECT 1;"
   
   # Check connection pool
   kubectl logs deployment/auth-me | grep "pool"
   ```

2. **Redis Connection Issues**
   ```bash
   # Test Redis connectivity
   redis-cli -u $REDIS_URL ping
   
   # Check Redis memory usage
   redis-cli info memory
   ```

3. **Email Delivery Issues**
   ```bash
   # Test SMTP connectivity
   telnet smtp.sendgrid.net 587
   
   # Check email logs
   kubectl logs deployment/auth-me | grep "email"
   ```

4. **High Memory Usage**
   ```bash
   # Monitor memory usage
   kubectl top pods -n auth-me
   
   # Check for memory leaks
   docker stats auth-me-container
   ```

### Debug Mode

```bash
# Enable debug logging
export RUST_LOG=debug,auth_me=trace

# Enable SQL query logging
export RUST_LOG=debug,diesel=debug

# Disable in production!
```

## Maintenance

### Regular Maintenance Tasks

1. **Database Maintenance**
   ```bash
   # Weekly vacuum and analyze
   psql $DATABASE_URL -c "VACUUM ANALYZE;"
   
   # Monthly reindex
   psql $DATABASE_URL -c "REINDEX DATABASE auth_me_prod;"
   ```

2. **Cache Cleanup**
   ```bash
   # Clear expired cache entries
   curl -X POST http://localhost:8080/api/cache/cleanup
   ```

3. **Log Rotation**
   ```bash
   # Configure logrotate
   echo "/var/log/auth-me/*.log {
       daily
       rotate 30
       compress
       delaycompress
       missingok
       notifempty
       create 644 app app
   }" > /etc/logrotate.d/auth-me
   ```

### Updates and Migrations

```bash
# Update application
docker pull your-registry/auth-me:latest
docker-compose up -d app

# Run new migrations
docker-compose exec app diesel migration run

# Rollback if needed
docker-compose exec app diesel migration revert
```
