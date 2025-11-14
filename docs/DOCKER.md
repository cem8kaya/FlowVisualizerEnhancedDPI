# Docker Deployment Guide

## Overview

The nDPI Callflow Visualizer is fully containerized with Docker, providing production-ready deployment with multi-stage builds, security hardening, and comprehensive health checks.

## Quick Start

### Build and Run with Docker Compose

```bash
# Build and start services
docker-compose up -d

# View logs
docker-compose logs -f callflowd

# Stop services
docker-compose down

# Stop and remove volumes (WARNING: deletes data)
docker-compose down -v
```

### Access the Application

- Web UI: http://localhost:8080
- WebSocket: ws://localhost:8081
- API: http://localhost:8080/api/v1/
- Health Check: http://localhost:8080/health
- Metrics: http://localhost:9090/metrics

## Building the Docker Image

### Standard Build

```bash
docker build -t callflowd:latest .
```

### Multi-architecture Build

```bash
docker buildx build --platform linux/amd64,linux/arm64 -t callflowd:latest .
```

### Build Arguments

```bash
docker build \
  --build-arg CMAKE_BUILD_TYPE=Release \
  --build-arg WORKERS=8 \
  -t callflowd:latest .
```

## Running with Docker CLI

### Basic Run

```bash
docker run -d \
  --name callflowd \
  -p 8080:8080 \
  -p 8081:8081 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/output:/app/output \
  -v $(pwd)/db:/app/db \
  callflowd:latest
```

### With Custom Configuration

```bash
docker run -d \
  --name callflowd \
  -p 8080:8080 \
  -p 8081:8081 \
  -v $(pwd)/config.json:/app/config.json:ro \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/db:/app/db \
  -e JWT_SECRET="your-secret-key" \
  -e AUTH_ENABLED=true \
  callflowd:latest
```

### With TLS/HTTPS

```bash
docker run -d \
  --name callflowd \
  -p 8080:8080 \
  -p 8081:8081 \
  -v $(pwd)/certs:/app/certs:ro \
  -e TLS_ENABLED=true \
  -e TLS_CERT_FILE=/app/certs/server.crt \
  -e TLS_KEY_FILE=/app/certs/server.key \
  callflowd:latest
```

## Docker Compose Configurations

### Production with Nginx Reverse Proxy

```bash
# Start with nginx proxy
docker-compose --profile with-proxy up -d

# Generate self-signed certificates for testing
mkdir -p certs
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout certs/server.key \
  -out certs/server.crt \
  -subj "/CN=localhost"
```

### Environment Variables

All configuration options can be overridden via environment variables:

```yaml
environment:
  # Server
  - API_PORT=8080
  - WS_PORT=8081
  - WORKERS=8
  - LOG_LEVEL=INFO

  # Database
  - DATABASE_ENABLED=true
  - DATABASE_PATH=/app/db/callflowd.db

  # Authentication
  - AUTH_ENABLED=true
  - JWT_SECRET=${JWT_SECRET}
  - JWT_EXPIRY_HOURS=24

  # Rate Limiting
  - RATE_LIMIT_ENABLED=true
  - RATE_LIMIT_RPM=60
  - RATE_LIMIT_BURST=10

  # TLS
  - TLS_ENABLED=false
  - TLS_CERT_FILE=/app/certs/server.crt
  - TLS_KEY_FILE=/app/certs/server.key
```

## Volume Mounts

### Data Directories

- `/app/data` - PCAP upload directory (persistent)
- `/app/output` - JSON export directory (persistent)
- `/app/db` - SQLite database directory (persistent)
- `/app/logs` - Application logs (ephemeral or persistent)
- `/app/certs` - TLS certificates (read-only)

### Configuration

- `/app/config.json` - Main configuration file (read-only recommended)

## Health Checks

The container includes built-in health checks:

```bash
# Check container health
docker ps
docker inspect callflowd | grep -A10 Health

# Manual health check
curl -f http://localhost:8080/health
```

Health check configuration in docker-compose.yml:

```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 40s
```

## Resource Limits

### Docker Compose

```yaml
deploy:
  resources:
    limits:
      cpus: '4.0'
      memory: 4G
    reservations:
      cpus: '1.0'
      memory: 512M
```

### Docker CLI

```bash
docker run -d \
  --name callflowd \
  --cpus=4 \
  --memory=4g \
  callflowd:latest
```

## Networking

### Custom Networks

```yaml
networks:
  callflowd-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/16
```

### Port Mapping

- 8080: REST API (HTTP/HTTPS)
- 8081: WebSocket
- 9090: Prometheus metrics (optional)

## Security Best Practices

### 1. Run as Non-Root User

The container runs as user `callflowd` (UID 1000) by default.

### 2. Read-Only Root Filesystem (Optional)

```yaml
security_opt:
  - no-new-privileges:true
read_only: true
tmpfs:
  - /tmp
  - /app/logs
```

### 3. Drop Capabilities

```yaml
cap_drop:
  - ALL
cap_add:
  - NET_BIND_SERVICE  # Only if binding to ports < 1024
```

### 4. Use Secrets for Sensitive Data

```bash
# Create Docker secret
echo "your-jwt-secret" | docker secret create jwt_secret -

# Use in docker-compose.yml
secrets:
  - jwt_secret

environment:
  - JWT_SECRET_FILE=/run/secrets/jwt_secret
```

### 5. Keep Images Updated

```bash
# Pull latest image
docker pull ghcr.io/cem8kaya/flowvisualizer-enhanced-dpi:latest

# Rebuild with latest base image
docker build --no-cache -t callflowd:latest .
```

## Logging

### View Logs

```bash
# Follow logs
docker logs -f callflowd

# Last 100 lines
docker logs --tail 100 callflowd

# Logs since 1 hour ago
docker logs --since 1h callflowd
```

### Log Drivers

Configure in docker-compose.yml:

```yaml
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
```

Or use syslog/journald:

```yaml
logging:
  driver: "syslog"
  options:
    syslog-address: "udp://192.168.0.42:514"
```

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker logs callflowd

# Check container status
docker ps -a

# Inspect container
docker inspect callflowd
```

### Permission Issues

```bash
# Fix volume permissions
sudo chown -R 1000:1000 data/ output/ db/ logs/
```

### Database Locked

```bash
# Stop container
docker-compose down

# Remove lock file
rm db/.lock

# Restart
docker-compose up -d
```

### Out of Disk Space

```bash
# Check disk usage
docker system df

# Clean up
docker system prune -a
docker volume prune
```

### Network Issues

```bash
# Inspect network
docker network inspect callflowd-net

# Restart networking
docker-compose down
docker-compose up -d
```

## Performance Tuning

### Worker Threads

```bash
# Set based on CPU cores
docker run -e WORKERS=$(nproc) callflowd:latest
```

### Memory Limits

```bash
# For large PCAP files
docker run --memory=8g callflowd:latest
```

### Database Performance

```yaml
environment:
  - DATABASE_JOURNAL_MODE=WAL
  - DATABASE_CACHE_SIZE=10000
```

## Maintenance

### Backup Database

```bash
# Backup while running
docker exec callflowd sqlite3 /app/db/callflowd.db ".backup /app/db/backup.db"
docker cp callflowd:/app/db/backup.db ./backup-$(date +%Y%m%d).db
```

### Restore Database

```bash
# Stop container
docker-compose down

# Restore backup
cp backup-20231114.db db/callflowd.db

# Restart
docker-compose up -d
```

### Update Configuration

```bash
# Edit config
vi config.json

# Restart to apply
docker-compose restart callflowd
```

### Clean Old Data

```bash
# Clean uploads older than 7 days
docker exec callflowd find /app/data -type f -mtime +7 -delete
```

## CI/CD Integration

### GitHub Actions

See `.github/workflows/ci.yml` for automated Docker builds.

### Pull Latest Image

```bash
# Login to GitHub Container Registry
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin

# Pull image
docker pull ghcr.io/cem8kaya/flowvisualizer-enhanced-dpi:latest
```

## Additional Resources

- [Kubernetes Deployment](KUBERNETES.md)
- [Security Guide](SECURITY.md)
- [Architecture Documentation](ARCHITECTURE.md)
- [API Documentation](API.md)
