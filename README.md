# Callflow Visualizer Enhanced DPI

A production-ready, enterprise-grade network packet analysis and visualization platform that ingests PCAP files, performs deep packet inspection using nDPI, parses telecom protocols (SIP, RTP, DIAMETER, GTP, NGAP, S1AP, HTTP/2, 5G SBA), correlates distributed 3GPP sessions, and exposes results through REST/WebSocket APIs to a modern web frontend.

## Project Status

**Current Milestone: M7 (5G SBA Parser, HTTP/2 Reassembly, Enhanced Session Correlation)** ✅

| Milestone | Description | Status |
|-----------|-------------|--------|
| M1 | Core PCAP Processing - SIP/RTP parsing, Session correlation, JSON export | ✅ Complete |
| M2 | REST API & WebSocket - nDPI integration, Job management, Configuration | ✅ Complete |
| M3 | Protocol Parsers - DIAMETER, GTPv2-C, nDPI flow caching with LRU | ✅ Complete |
| M4 | HTTP/2 & Web UI - HPACK support, D3.js visualizations, SQLite3 persistence | ✅ Complete |
| M5 | Production Deployment - Docker, Kubernetes, CI/CD, Security hardening | ✅ Complete |
| M6 | Auth & Monitoring - JWT authentication, RBAC, Analytics, Prometheus metrics | ✅ Complete |
| M7 | 5G SBA Parser - HTTP/2 reassembly, 5G NF detection, Enhanced correlation | ✅ Complete |

**Status**: 🚀 **ENTERPRISE READY**

## Key Features

### Protocol Support
- **Signaling**: SIP (with 3GPP headers), DIAMETER (20+ command codes), S1AP, X2AP, NGAP, NAS
- **Media**: RTP, RTCP with quality metrics (loss, jitter)
- **Tunneling**: GTPv1, GTPv2-C, PFCP
- **Transport**: TCP, UDP, SCTP (with reassembly)
- **5G SBA**: HTTP/2 with full HPACK support, JSON payload parsing, NF detection

### Advanced Capabilities
- Multi-interface session correlation (IMSI, SUPI, TEID, SEID, Call-ID)
- VoLTE call lifecycle tracking (signaling + media + control)
- 5G Registration and PDU Session tracking
- Real-time WebSocket event streaming
- Interactive timeline visualization with D3.js
- JWT authentication and API key support
- Prometheus metrics and analytics

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            Application Layer                                  │
│  ┌──────────────────┐              ┌────────────────────────────────────┐   │
│  │   CLI Interface  │              │   REST API + WebSocket Server      │   │
│  │   (./callflowd)  │              │   (Authentication, Rate Limiting)  │   │
│  └────────┬─────────┘              └──────────────┬─────────────────────┘   │
└───────────┼─────────────────────────────────────────┼────────────────────────┘
            │                                          │
            └─────────────────┬────────────────────────┘
                              │
┌─────────────────────────────▼────────────────────────────────────────────────┐
│                          Processing Pipeline                                   │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                        Packet Processor                                  │ │
│  │  • Link Layer Parser (Ethernet, VLAN, SLL)                              │ │
│  │  • IP Reassembler (Defragmentation)                                     │ │
│  │  • TCP Reassembler (Stream reconstruction)                              │ │
│  │  • SCTP Parser (Chunk reassembly)                                       │ │
│  └───────────────────────────────┬─────────────────────────────────────────┘ │
│                                  │                                            │
│  ┌─────────────────┐    ┌────────▼────────┐    ┌────────────────────────┐   │
│  │  nDPI Engine    │◄───│ Flow Classifier │───►│   Dynamic Port         │   │
│  │  (LRU Cache)    │    │                 │    │   Tracker              │   │
│  └─────────────────┘    └─────────────────┘    └────────────────────────┘   │
│                                  │                                            │
│  ┌───────────────────────────────▼─────────────────────────────────────────┐ │
│  │                      Protocol Parsers (15+)                              │ │
│  │  ┌─────┐ ┌─────┐ ┌─────┐ ┌──────────┐ ┌────────┐ ┌──────┐ ┌────────┐  │ │
│  │  │ SIP │ │ RTP │ │ GTP │ │ DIAMETER │ │ HTTP/2 │ │ NGAP │ │ 5G SBA │  │ │
│  │  └─────┘ └─────┘ └─────┘ └──────────┘ └────────┘ └──────┘ └────────┘  │ │
│  │  ┌─────┐ ┌─────┐ ┌──────┐ ┌─────┐ ┌──────┐ ┌─────┐ ┌──────┐          │ │
│  │  │S1AP │ │X2AP │ │ NAS  │ │PFCP │ │ SCTP │ │ DNS │ │ RTCP │          │ │
│  │  └─────┘ └─────┘ └──────┘ └─────┘ └──────┘ └─────┘ └──────┘          │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
                                   │
┌──────────────────────────────────▼──────────────────────────────────────────┐
│                      Session Correlation Engine                               │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │              EnhancedSessionCorrelator                                │   │
│  │  • IMSI/SUPI correlation (3GPP subscriber identity)                  │   │
│  │  • TEID correlation (GTP tunnel identification)                       │   │
│  │  • SEID correlation (PFCP session identification)                     │   │
│  │  • Call-ID correlation (SIP dialogs)                                  │   │
│  │  • UE IP address correlation                                          │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────────────────┐   │
│  │ VoLTE Master    │ │ LTE Attach      │ │ 5G Registration             │   │
│  │ Session         │ │ Machine         │ │ Machine                     │   │
│  └─────────────────┘ └─────────────────┘ └─────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                   │
┌──────────────────────────────────▼──────────────────────────────────────────┐
│                        Output & Storage Layer                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌────────────────────────────┐  │
│  │  Event Builder  │  │  JSON Exporter  │  │  SQLite3 Database          │  │
│  │  (Timeline)     │  │                 │  │  (WAL mode, Indexed)       │  │
│  └─────────────────┘  └─────────────────┘  └────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                                   │
┌──────────────────────────────────▼──────────────────────────────────────────┐
│                          Web Frontend                                         │
│  ┌─────────────────┐  ┌─────────────────┐  ┌────────────────────────────┐  │
│  │  Dashboard      │  │  Session View   │  │  Timeline Visualization    │  │
│  │  (Upload, Jobs) │  │  (Details)      │  │  (D3.js Ladder Diagrams)   │  │
│  └─────────────────┘  └─────────────────┘  └────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Using Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/cem8kaya/FlowVisualizerEnhancedDPI.git
cd FlowVisualizerEnhancedDPI

# Start services with Docker Compose
docker-compose up -d

# Create admin user (inside container)
docker-compose exec callflowd ./create_admin /data/callflowd.db admin MySecureP@ss123 admin@example.com

# Check health
curl http://localhost:8080/health

# Login and get JWT token
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"MySecureP@ss123"}'

# Access the web UI
open http://localhost:8080
```

### Using Kubernetes

```bash
# Apply Kubernetes configurations
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/pvc.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml

# Check status
kubectl get pods -n callflowd
kubectl get svc -n callflowd
```

### Building from Source

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    git \
    libpcap-dev \
    libsqlite3-dev \
    libssl-dev \
    libyaml-cpp-dev \
    pkg-config

# Clone and build
git clone https://github.com/cem8kaya/FlowVisualizerEnhancedDPI.git
cd FlowVisualizerEnhancedDPI
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)

# Run the application
./src/callflowd --help
```

## Usage

### CLI Mode

```bash
# Process a PCAP file
./callflowd --input capture.pcap --output results.json

# Enable verbose logging
./callflowd --input capture.pcap --verbose

# Use multiple worker threads
./callflowd --input capture.pcap --workers 8
```

### API Server Mode

```bash
# Start API server on default port (8080)
./callflowd --api-server

# Start with custom configuration
./callflowd --api-server --config config.json

# Start on custom port
./callflowd --api-server --api-port 9090
```

### CLI Options

```
Usage: callflowd [OPTIONS]

Options:
  -i, --input FILE        Input PCAP file (required for CLI mode)
  -o, --output FILE       Output JSON file (optional, auto-generated)
  --output-dir DIR        Output directory (default: ./output)
  -w, --workers N         Number of worker threads (default: 4)
  --verbose               Enable verbose output
  --debug                 Enable debug logging
  --trace                 Enable trace logging
  --export-pcap           Export PCAP subsets per session

API Server Options:
  --api-server            Enable REST API server
  --api-port PORT         API server port (default: 8080)
  --api-bind ADDR         API bind address (default: 0.0.0.0)
  -c, --config FILE       Configuration file (JSON format)
```

## API Endpoints

### Core Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/api/v1/upload` | Upload PCAP file (multipart, up to 10GB) |
| GET | `/api/v1/jobs/{id}/status` | Get job processing status |
| GET | `/api/v1/jobs/{id}/sessions` | Get sessions with pagination |
| GET | `/api/v1/sessions/{id}` | Get session details |
| DELETE | `/api/v1/jobs/{id}` | Delete job |

### Authentication Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/register` | User registration |
| POST | `/api/v1/auth/login` | Login with JWT |
| POST | `/api/v1/auth/refresh` | Refresh access token |
| POST | `/api/v1/auth/logout` | Logout (token blacklist) |
| GET | `/api/v1/auth/me` | Current user info |
| POST | `/api/v1/auth/change-password` | Change password |
| POST | `/api/v1/auth/apikeys` | Create API key |
| GET | `/api/v1/auth/apikeys` | List API keys |
| DELETE | `/api/v1/auth/apikeys/:id` | Revoke API key |

### Analytics Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/analytics/summary` | Overall statistics |
| GET | `/api/v1/analytics/protocols` | Protocol distribution |
| GET | `/api/v1/analytics/top-talkers` | Top IP addresses |
| GET | `/api/v1/analytics/performance` | System metrics |
| GET | `/api/v1/analytics/timeseries` | Time series data |
| GET | `/metrics` | Prometheus metrics |

For complete API documentation, see [docs/API.md](docs/API.md).

## Project Structure

```
FlowVisualizerEnhancedDPI/
├── src/                          # C++ source code (15 modules)
│   ├── api_server/              # REST API, WebSocket, Auth, Analytics
│   ├── cli/                     # Command-line interface
│   ├── common/                  # Utilities, logging, configuration
│   ├── config/                  # Runtime configuration management
│   ├── correlation/             # Session correlation logic (10+ correlators)
│   ├── event_extractor/         # Timeline and JSON export
│   ├── flow_manager/            # Network flow tracking
│   ├── ndpi_engine/             # nDPI integration layer
│   ├── pcap_ingest/             # PCAP processing pipeline
│   ├── persistence/             # SQLite3 database operations
│   ├── protocol_parsers/        # Protocol decoders (15+ protocols)
│   ├── session/                 # Session types and correlators
│   └── transport/               # SCTP parser
├── include/                     # Header files (mirrors src structure)
├── ui/static/                   # Web frontend
│   ├── js/                      # Application logic, components
│   ├── css/                     # Styling and design system
│   └── *.html                   # Dashboard, sessions, VoLTE views
├── tests/                       # Test suite
│   ├── unit/                    # Unit tests (GoogleTest)
│   ├── integration/             # Integration tests
│   └── pcap/                    # Test PCAP files
├── k8s/                         # Kubernetes manifests
├── config/                      # Protocol configuration (YAML)
├── database/                    # Database schema files
├── docs/                        # Documentation
├── CMakeLists.txt              # Build configuration
├── Dockerfile                   # Multi-stage Docker build
├── docker-compose.yml          # Container orchestration
└── nginx.conf                   # Reverse proxy configuration
```

## Configuration

### config.json

```json
{
  "server": {
    "bind_address": "0.0.0.0",
    "port": 8080,
    "workers": 4,
    "max_upload_size_mb": 10240
  },
  "processing": {
    "worker_threads": 8,
    "packet_queue_size": 10000,
    "flow_timeout_sec": 300
  },
  "storage": {
    "upload_dir": "/data/uploads",
    "output_dir": "/data/results",
    "retention_hours": 24
  },
  "database": {
    "enabled": true,
    "path": "/data/callflowd.db",
    "retention_days": 7
  },
  "auth": {
    "jwt_secret": "your-secret-key",
    "jwt_expiry_hours": 24,
    "bcrypt_rounds": 12
  },
  "monitoring": {
    "prometheus_enabled": true,
    "prometheus_path": "/metrics"
  }
}
```

See [config.example.json](config.example.json) for a complete example.

## Performance

### Benchmarks (Achieved)
- **Throughput**: ~34,700 packets/second (single CPU, Release build)
- **Memory**: Process 10GB PCAP within 16GB RAM
- **nDPI Caching**: ~25% throughput improvement with LRU flow cache
- **Analytics Caching**: ~95% database load reduction with 60s TTL

### Optimization Techniques
- Minimal copying with move semantics
- Lock-free queues for packet distribution
- Header-only checks before full parsing
- Hash-based flow table with O(1) lookup
- Batch processing for reduced lock contention

## Testing

```bash
# Build with tests enabled
cmake -DBUILD_TESTS=ON ..
make

# Run all tests
ctest --output-on-failure

# Run specific test suite
./tests/unit_tests --gtest_filter=SipParser.*
```

## Security Features

- **JWT Authentication**: HS256 token signing with configurable expiry
- **API Keys**: Scoped keys with SHA256 storage
- **Password Security**: PBKDF2-HMAC-SHA256 with policy enforcement
- **Rate Limiting**: Token bucket algorithm (60 req/min default)
- **Input Validation**: PCAP magic validation, path traversal prevention
- **TLS/HTTPS**: OpenSSL integration with TLS 1.2+
- **Audit Logging**: Security event tracking

## Documentation

| Document | Description |
|----------|-------------|
| [API.md](docs/API.md) | REST API documentation |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System architecture |
| [BUILD.md](docs/BUILD.md) | Build instructions |
| [DOCKER.md](docs/DOCKER.md) | Docker deployment |
| [SECURITY.md](docs/SECURITY.md) | Security features |
| [FEATURES.md](docs/FEATURES.md) | Complete feature list |
| [PROTOCOLS.md](docs/PROTOCOLS.md) | Protocol support details |

## Dependencies

### Required
- **libpcap** (≥1.9.0): Packet capture
- **SQLite3**: Database persistence
- **OpenSSL 3.x**: Cryptography, TLS
- **yaml-cpp**: Protocol configuration

### Bundled (CMake FetchContent)
- **nlohmann/json** (3.11.2): JSON parsing
- **cpp-httplib** (0.15.3): HTTP server
- **jwt-cpp** (0.7.0): JWT authentication
- **fmt** (10.1.1): Logging
- **GoogleTest**: Unit testing

### Optional
- **nDPI**: Enhanced protocol detection

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Follow the code style guidelines (clang-format)
4. Add tests for new features
5. Submit a pull request

## License

See [LICENSE](LICENSE) file for details.

## Acknowledgments

- [nDPI](https://github.com/ntop/nDPI) - Deep Packet Inspection library
- [libpcap](https://www.tcpdump.org/) - Packet capture library
- [nlohmann/json](https://github.com/nlohmann/json) - JSON library for C++
- [cpp-httplib](https://github.com/yhirose/cpp-httplib) - HTTP/HTTPS server
- [jwt-cpp](https://github.com/Thalhammer/jwt-cpp) - JWT library
