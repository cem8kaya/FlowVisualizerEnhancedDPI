# Multi-stage Dockerfile for nDPI Callflow Visualizer (M5 Production-Ready)

# Build stage
FROM ubuntu:24.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libpcap-dev \
    libsqlite3-dev \
    libssl-dev \
    libndpi-dev \
    libsctp-dev \
    pkg-config \
    wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy source files
COPY CMakeLists.txt ./
COPY src/ ./src/
COPY include/ ./include/
COPY thirdparty/ ./thirdparty/
COPY ui/ ./ui/

# Build
RUN mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTS=OFF \
    -DBUILD_API_SERVER=ON \
    -DCMAKE_CXX_FLAGS="-O3 -march=native -flto" \
    .. && \
    make -j2 VERBOSE=1 && \
    strip src/callflowd

# Runtime stage
FROM ubuntu:24.04

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    libsqlite3-0 \
    libssl3 \
    lksctp-tools \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user and group
RUN groupadd -r -g 1000 callflowd 2>/dev/null || groupmod -n callflowd $(getent group 1000 | cut -d: -f1) && \
    useradd -r -u 1000 -g callflowd -m -d /home/callflowd -s /bin/bash callflowd 2>/dev/null || \
    usermod -l callflowd -d /home/callflowd -m $(getent passwd 1000 | cut -d: -f1)

WORKDIR /app

# Copy binary and static files from builder
COPY --from=builder /build/build/src/callflowd /app/
COPY --from=builder /build/build/src/create_admin /app/
COPY --from=builder /build/ui/static /app/ui/static/

# Copy default configuration
COPY config.example.json /app/config.json
COPY config/ /app/config/

# Create directories with proper permissions
RUN mkdir -p /app/data /app/output /app/db /app/logs /app/certs && \
    chown -R callflowd:callflowd /app && \
    chmod 700 /app/db /app/logs /app/certs && \
    chmod 755 /app/data /app/output

# Switch to non-root user
USER callflowd

# Expose ports
EXPOSE 8080 8081

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Environment variables with secure defaults
ENV API_PORT=8080 \
    WS_PORT=8081 \
    WORKERS=4 \
    LOG_LEVEL=INFO \
    DATABASE_ENABLED=true \
    DATABASE_PATH=/app/db/callflowd.db \
    CONFIG_PATH=/app/config.json \
    PROTOCOLS_CONFIG_PATH=/app/config/protocols.yaml \
    TZ=UTC

# Add labels for metadata
LABEL maintainer="Callflow Visualizer Team" \
    version="1.0.0-m5" \
    description="Production-ready nDPI Callflow Visualizer with authentication, rate limiting, and database persistence" \
    org.opencontainers.image.source="https://github.com/cem8kaya/FlowVisualizerEnhancedDPI"

# Run the application
CMD ["./callflowd", "--api-server", "--config", "/app/config.json"]
