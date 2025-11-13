# Multi-stage Dockerfile for Callflow Visualizer

# Stage 1: Builder
FROM ubuntu:22.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy source code
COPY . .

# Create build directory and build
RUN mkdir -p build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make -j$(nproc)

# Stage 2: Runtime
FROM ubuntu:22.04

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -m -u 1000 callflow

# Copy binary from builder
COPY --from=builder /build/build/src/callflowd /usr/local/bin/

# Create directories
RUN mkdir -p /app/output && chown -R callflow:callflow /app

# Switch to app user
USER callflow
WORKDIR /app

# Default command
ENTRYPOINT ["/usr/local/bin/callflowd"]
CMD ["--help"]
