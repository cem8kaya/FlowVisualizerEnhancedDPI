# Callflow Visualizer — C++ + nDPI (VoLTE / 3GPP Data / DIAMETER / HTTP/2)

A production-ready Callflow Visualizer that ingests PCAPs, decodes telecom protocols using nDPI in C++, correlates sessions (VoLTE, GTP, DIAMETER, HTTP/2), and exposes structured events via REST/WebSocket to a web frontend.

## Project Status

**Current Milestone: M1 (Prototype)** ✅

- ✅ Basic PCAP upload CLI
- ✅ libpcap ingestion
- ✅ SIP/RTP parsing
- ✅ Session correlation
- ✅ JSON export
- ⏳ nDPI integration (placeholder, full implementation in M2)
- ⏳ REST API (planned for M2)
- ⏳ WebSocket streaming (planned for M2)
- ⏳ DIAMETER & GTP parsing (planned for M3)
- ⏳ HTTP/2 parsing (planned for M4)

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLI Interface                             │
│                      (./callflowd)                               │
└────────────────────────────┬────────────────────────────────────┘
                             │
         ┌───────────────────┴────────────────────┐
         │                                        │
┌────────▼─────────┐                  ┌──────────▼──────────┐
│  PCAP Ingestion  │                  │   API Server        │
│   (libpcap)      │                  │   (REST/WebSocket)  │
└────────┬─────────┘                  └─────────────────────┘
         │                                    (M2)
         │
┌────────▼──────────────────────────────────────────────────┐
│              Packet Queue (Thread-Safe)                    │
└────────┬──────────────────────────────────────────────────┘
         │
         │   ┌───────────────────┐
         ├──▶│  nDPI Engine      │ (Protocol Classification)
         │   └───────────────────┘
         │
┌────────▼──────────────────────────────────────────────────┐
│                   Protocol Parsers                         │
│  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────────┐  ┌────────┐ │
│  │ SIP  │  │ RTP  │  │ GTP  │  │ DIAMETER │  │ HTTP/2 │ │
│  └──────┘  └──────┘  └──────┘  └──────────┘  └────────┘ │
└────────┬──────────────────────────────────────────────────┘
         │
┌────────▼──────────────────────────────────────────────────┐
│               Flow Manager & Session Correlator            │
│  • Track flows by 5-tuple                                  │
│  • Correlate by Call-ID, Session-ID, TEID, Stream-ID      │
│  • Calculate metrics (loss, jitter, setup time)            │
└────────┬──────────────────────────────────────────────────┘
         │
┌────────▼──────────────────────────────────────────────────┐
│              Event Extractor & JSON Exporter               │
│  • Build timeline events                                   │
│  • Export sessions as JSON                                 │
└────────┬──────────────────────────────────────────────────┘
         │
         ▼
    Output JSON
```

## Features

### ✅ Implemented (M1)

- **PCAP Ingestion**: Stream processing of PCAP files using libpcap
- **SIP Parser**: Full SIP message parsing with SDP support
- **RTP Parser**: RTP header parsing with quality metrics (packet loss, jitter)
- **Session Correlation**: Group packets by Call-ID into VoLTE sessions
- **Flow Tracking**: Maintain flow state with 5-tuple identification
- **JSON Export**: Structured JSON output with sessions and events
- **CLI Interface**: Command-line tool for PCAP processing

### ⏳ Planned

- **M2**: REST API, WebSocket streaming, full nDPI integration
- **M3**: DIAMETER & GTP parsing
- **M4**: HTTP/2 parsing, performance optimization
- **M5**: Docker, CI/CD, documentation, security hardening

## Building

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    git \
    libpcap-dev

# Optional: nDPI (will be fully integrated in M2)
# git clone https://github.com/ntop/nDPI.git
# cd nDPI && ./autogen.sh && ./configure && make && sudo make install
```

### Build Steps

```bash
# Clone the repository
git clone <repository-url>
cd FlowVisualizerEnhancedDPI

# Create build directory
mkdir build && cd build

# Configure
cmake ..

# Build
make -j$(nproc)

# The binary will be at: ./src/callflowd
```

### Build Options

```bash
# Debug build with sanitizers
cmake -DCMAKE_BUILD_TYPE=Debug ..

# Release build (optimized)
cmake -DCMAKE_BUILD_TYPE=Release ..

# Disable tests
cmake -DBUILD_TESTS=OFF ..

# Disable API server
cmake -DBUILD_API_SERVER=OFF ..
```

## Usage

### Basic Usage

```bash
# Process a PCAP file
./callflowd --input capture.pcap

# Specify output file
./callflowd --input capture.pcap --output results.json

# Enable verbose logging
./callflowd --input capture.pcap --verbose

# Use multiple worker threads
./callflowd --input capture.pcap --workers 8
```

### CLI Options

```
Usage: callflowd [OPTIONS]

Options:
  -i, --input FILE        Input PCAP file (required)
  -o, --output FILE       Output JSON file (optional, default: auto-generated)
  --output-dir DIR        Output directory (default: ./output)
  -w, --workers N         Number of worker threads (default: 4)
  --verbose               Enable verbose output
  --debug                 Enable debug logging
  --trace                 Enable trace logging
  --export-pcap           Export PCAP subsets per session

API Server Options (M2):
  --api-server            Enable REST API server
  --api-port PORT         API server port (default: 8080)
  --api-bind ADDR         API bind address (default: 0.0.0.0)
```

## Output Format

### Session JSON

```json
{
  "session_id": "uuid",
  "type": "VoLTE",
  "session_key": "call-id-value",
  "start_time": "2025-11-10T12:34:56.789Z",
  "end_time": "2025-11-10T12:35:10.100Z",
  "participants": ["192.0.2.1:5060", "198.51.100.2:5060"],
  "metrics": {
    "packets": 1234,
    "bytes": 987654,
    "rtp_loss": 0.01,
    "rtp_jitter_ms": 2.5,
    "setup_time_ms": 230,
    "duration_ms": 13311
  },
  "events_count": 12,
  "events": [
    {
      "event_id": "uuid",
      "timestamp": "2025-11-10T12:34:58.100Z",
      "direction": "client->server",
      "protocol": "SIP",
      "message_type": "INVITE",
      "short": "SIP INVITE from alice",
      "details": {
        "call_id": "abc123",
        "cseq": 1,
        "from": "sip:alice@example.com",
        "to": "sip:bob@example.com"
      },
      "packet_ref": "packet-uuid"
    }
  ]
}
```

## Project Structure

```
FlowVisualizerEnhancedDPI/
├── CMakeLists.txt              # Main build configuration
├── README.md                   # This file
├── LICENSE                     # Project license
├── .gitignore                  # Git ignore rules
├── .clang-format              # Code formatting rules
│
├── include/                    # Header files
│   ├── common/                # Common types and utilities
│   ├── pcap_ingest/           # PCAP reading
│   ├── ndpi_engine/           # nDPI integration
│   ├── flow_manager/          # Flow tracking and session correlation
│   ├── protocol_parsers/      # Protocol-specific parsers
│   ├── event_extractor/       # Event building and JSON export
│   ├── api_server/            # REST/WebSocket server (M2)
│   └── cli/                   # CLI interface
│
├── src/                        # Implementation files
│   ├── common/
│   ├── pcap_ingest/
│   ├── ndpi_engine/
│   ├── flow_manager/
│   ├── protocol_parsers/
│   ├── event_extractor/
│   ├── api_server/
│   └── cli/
│       └── main.cpp           # Entry point
│
├── tests/                      # Unit and integration tests
│   ├── unit/
│   ├── integration/
│   └── samples/               # Sample PCAP files
│
├── ui/                         # Web frontend (M2)
│   └── static/
│
├── docker/                     # Docker configuration (M5)
├── docs/                       # Additional documentation
└── bench/                      # Benchmark scripts
```

## Testing

### Sample Test PCAPs

Create sample PCAP files for testing:

```bash
# Create output directory
mkdir -p output

# Test with your own PCAP file
./callflowd --input /path/to/sip_call.pcap --output output/result.json
```

### Unit Tests (Coming in M1)

```bash
# Build with tests
cmake -DBUILD_TESTS=ON ..
make

# Run tests
ctest --output-on-failure

# Or run directly
./tests/unit_tests
```

## Performance

### Target Metrics (M1)

- **Throughput**: Process PCAP at ≥ 200 Mbps sustained
- **Memory**: Process 10GB PCAP within 16GB RAM
- **Latency**: < 500ms from packet ingestion to event emission

### Benchmarking

```bash
# Run benchmark
./bench/parse_bench.sh capture.pcap
```

## Development

### Code Style

We use `clang-format` for code formatting:

```bash
# Format all source files
find src include -name '*.cpp' -o -name '*.h' | xargs clang-format -i
```

### Adding a New Protocol Parser

1. Create header in `include/protocol_parsers/myproto_parser.h`
2. Implement in `src/protocol_parsers/myproto_parser.cpp`
3. Register in the main packet processor
4. Add unit tests

## Roadmap

### Milestone 1 (Completed) ✅
- Basic PCAP ingestion and SIP/RTP parsing
- Session correlation
- JSON export
- CLI interface

### Milestone 2 (Next)
- REST API endpoints
- WebSocket streaming
- Full nDPI integration
- Simple web UI

### Milestone 3
- DIAMETER parsing
- GTP-C/GTP-U parsing
- Enhanced session correlation

### Milestone 4
- HTTP/2 parsing
- Performance optimization
- Multi-threading improvements

### Milestone 5
- Docker packaging
- CI/CD pipeline
- Security hardening
- Production deployment guide

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Follow the code style guidelines
4. Add tests for new features
5. Submit a pull request

## License

See [LICENSE](LICENSE) file for details.

## Contact

For questions or issues, please open a GitHub issue.

## Acknowledgments

- [nDPI](https://github.com/ntop/nDPI) - Deep Packet Inspection library
- [libpcap](https://www.tcpdump.org/) - Packet capture library
- [nlohmann/json](https://github.com/nlohmann/json) - JSON library for C++
