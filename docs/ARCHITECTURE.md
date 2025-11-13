# Architecture Documentation

## Overview

Callflow Visualizer is designed as a modular, high-performance system for processing and analyzing telecom protocol traffic from PCAP files. The architecture follows a producer-consumer pattern with clear separation of concerns.

## Design Principles

1. **Modularity**: Each component has a single, well-defined responsibility
2. **Performance**: Designed for streaming processing of large PCAP files
3. **Extensibility**: Easy to add new protocol parsers
4. **Thread Safety**: Components designed for concurrent access
5. **Memory Efficiency**: Streaming processing to avoid loading entire files into memory

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Application Layer                            │
│  ┌──────────────┐              ┌──────────────────────────┐    │
│  │ CLI Interface│              │   REST API (M2)          │    │
│  └──────┬───────┘              └───────────┬──────────────┘    │
└─────────┼──────────────────────────────────┼───────────────────┘
          │                                   │
          └──────────────┬────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────────┐
│                    Control Layer                                 │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │              Main Processor                                 │ │
│  │  • Orchestrates packet flow                                 │ │
│  │  • Manages worker threads                                   │ │
│  │  • Coordinates components                                   │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
          │
┌─────────▼───────────────────────────────────────────────────────┐
│                   Ingestion Layer                                │
│  ┌─────────────────┐        ┌──────────────────────────┐       │
│  │   PCAP Reader   │───────▶│   Packet Queue           │       │
│  │   (libpcap)     │        │   (Thread-Safe)          │       │
│  └─────────────────┘        └──────────┬───────────────┘       │
└────────────────────────────────────────┼─────────────────────────┘
                                          │
┌─────────────────────────────────────────▼───────────────────────┐
│                  Classification Layer                            │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │              nDPI Engine (M2)                               │ │
│  │  • Protocol detection                                       │ │
│  │  • DPI classification                                       │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
          │
┌─────────▼───────────────────────────────────────────────────────┐
│                    Parsing Layer                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │
│  │   SIP    │  │   RTP    │  │   GTP    │  │   DIAMETER   │   │
│  │  Parser  │  │  Parser  │  │  Parser  │  │    Parser    │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────┘   │
│  ┌──────────┐                                                   │
│  │  HTTP/2  │                                                   │
│  │  Parser  │                                                   │
│  └──────────┘                                                   │
└─────────────────────────────────────────────────────────────────┘
          │
┌─────────▼───────────────────────────────────────────────────────┐
│                   Correlation Layer                              │
│  ┌────────────────────┐      ┌─────────────────────────┐       │
│  │   Flow Tracker     │      │  Session Correlator     │       │
│  │  • 5-tuple flows   │      │  • Call-ID grouping     │       │
│  │  • Flow metrics    │      │  • Session timeline     │       │
│  └────────────────────┘      └─────────────────────────┘       │
└─────────────────────────────────────────────────────────────────┘
          │
┌─────────▼───────────────────────────────────────────────────────┐
│                    Export Layer                                  │
│  ┌────────────────────┐      ┌─────────────────────────┐       │
│  │  Event Builder     │      │   JSON Exporter         │       │
│  │  • Timeline events │      │   • Session JSON        │       │
│  │  • Structured data │      │   • File output         │       │
│  └────────────────────┘      └─────────────────────────┘       │
└─────────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. PCAP Ingestion (`pcap_ingest/`)

**Responsibility:** Read PCAP files and extract packets

**Key Classes:**
- `PcapReader`: Wraps libpcap for file reading
- `PacketQueue`: Thread-safe queue for packet distribution

**Design:**
- Streaming processing (no full file load)
- Memory-efficient packet handling
- Statistics tracking (packets processed, bytes, timing)

### 2. Protocol Classification (`ndpi_engine/`)

**Responsibility:** Identify protocol types from packet data

**Key Classes:**
- `NdpiWrapper`: Interface to nDPI library
- `FlowClassifier`: High-level classification logic

**Design:**
- Uses nDPI for DPI-based detection
- Fallback to port-based heuristics
- Maintains flow state for stateful protocols

### 3. Protocol Parsers (`protocol_parsers/`)

**Responsibility:** Parse protocol-specific packet payloads

**Key Classes:**
- `SipParser`: SIP message and SDP parsing
- `RtpParser`: RTP header extraction and quality metrics
- `GtpParser`: GTP-C/GTP-U message parsing (M3)
- `DiameterParser`: DIAMETER AVP parsing (M3)
- `Http2Parser`: HTTP/2 frame parsing (M4)

**Design:**
- Protocol-agnostic base interface
- Header-only detection methods for quick classification
- Detailed parsing only when needed
- Stateless parsing (state managed by correlator)

### 4. Flow Management (`flow_manager/`)

**Responsibility:** Track network flows and correlate into sessions

**Key Classes:**
- `FlowTracker`: Maintains per-flow state and metrics
- `SessionCorrelator`: Groups flows into logical sessions
- `RtpStreamTracker`: RTP-specific quality metrics

**Design:**
- Hash-based flow lookup (5-tuple key)
- Session correlation by Call-ID, Session-ID, TEID, etc.
- Automatic flow timeout and cleanup
- RTP jitter and packet loss calculation

**Session Correlation Keys:**
- **VoLTE**: SIP Call-ID + associated RTP flows
- **GTP**: TEID (Tunnel Endpoint Identifier)
- **DIAMETER**: Session-Id AVP
- **HTTP/2**: Connection 5-tuple + Stream ID
- **Fallback**: 5-tuple for unidentified traffic

### 5. Event Extraction (`event_extractor/`)

**Responsibility:** Convert parsed data into timeline events

**Key Classes:**
- `EventBuilder`: Creates structured events from packets
- `JsonExporter`: Serializes sessions and events to JSON

**Design:**
- Event-driven architecture
- Rich metadata extraction
- Flexible JSON schema
- Incremental export support (for WebSocket in M2)

### 6. API Server (`api_server/`) — M2

**Responsibility:** Provide REST and WebSocket interfaces

**Key Classes:**
- `HttpServer`: HTTP server implementation
- `WebSocketHandler`: Real-time event streaming
- `ApiRoutes`: Route handlers for REST endpoints

**Design:**
- RESTful API for queries
- WebSocket for real-time updates
- Authentication and authorization
- Rate limiting

## Data Flow

### Packet Processing Pipeline

```
PCAP File
   │
   ▼
[PcapReader] ──────────────────┐
   │                           │
   │ read_packet()             │ callback
   │                           │
   ▼                           │
[Packet Parse] ────────────────┘
   │ (Ethernet/IP/UDP/TCP headers)
   │
   ▼
[PacketMetadata]
   │ {timestamp, 5-tuple, payload}
   │
   ▼
[Protocol Detection]
   │ (nDPI or heuristics)
   │
   ├─ SIP? ──▶ [SipParser] ──▶ SipMessage
   ├─ RTP? ──▶ [RtpParser] ──▶ RtpHeader
   ├─ GTP? ──▶ [GtpParser] ──▶ GtpMessage
   └─ ...
   │
   ▼
[SessionCorrelator]
   │ correlate by session_key
   │
   ▼
[Session + Events]
   │
   ▼
[JsonExporter]
   │
   ▼
Output JSON
```

### Threading Model

```
Main Thread
   │
   ├─▶ PcapReader Thread
   │     │ (reads packets from file)
   │     ▼
   │   PacketQueue ◀─────┐
   │                     │
   ├─▶ Worker Thread 1   │
   │     │ (process)     │
   │     └───────────────┘
   │
   ├─▶ Worker Thread 2
   │     │ (process)
   │     └─────▶ SessionCorrelator (thread-safe)
   │
   ├─▶ Worker Thread N
   │     │ (process)
   │     └───────────────▶ FlowTracker (thread-safe)
   │
   └─▶ Export Thread (optional)
         │
         ▼
       JSON files
```

## Memory Management

### Memory Efficiency Strategies

1. **Streaming Processing**: Don't load entire PCAP into memory
2. **Packet Queue Limit**: Bounded queue size (default: 10,000 packets)
3. **Flow Timeout**: Automatically expire old flows
4. **Minimal Packet Storage**: Store only essential metadata
5. **Incremental Export**: Write results as sessions complete

### Memory Footprint Estimates

For a 10GB PCAP with 10M packets:

- **Packet Queue**: ~500MB (10K packets × 50KB average)
- **Flow Table**: ~100MB (100K active flows × 1KB)
- **Session Data**: ~200MB (10K sessions × 20KB)
- **Parser State**: ~50MB
- **Total**: ~1GB active memory

## Performance Characteristics

### Target Performance (M1)

- **Throughput**: 200 Mbps sustained (25 MB/s)
- **Packet Rate**: 50,000 pps for average-sized packets
- **Memory**: ≤ 16GB for 10GB PCAP
- **Latency**: < 500ms per packet (ingestion to export)

### Optimization Techniques

1. **Minimal Copying**: Use references and move semantics
2. **Lock-Free Queues**: For packet distribution
3. **Fast Parsing**: Header-only checks before full parse
4. **Efficient Lookups**: Hash-based flow table
5. **Batch Processing**: Process multiple packets per lock

## Extensibility

### Adding a New Protocol Parser

1. **Create Parser Class**
   ```cpp
   class MyProtoParser {
   public:
       std::optional<MyProtoMessage> parse(const uint8_t* data, size_t len);
       static bool isMyProto(const uint8_t* data, size_t len);
   };
   ```

2. **Register in Processor**
   ```cpp
   if (MyProtoParser::isMyProto(packet.raw_data)) {
       auto msg = parser.parse(packet.raw_data);
       correlator.processPacket(packet, ProtocolType::MYPROTO, msg.toJson());
   }
   ```

3. **Define Session Correlation**
   ```cpp
   // In SessionCorrelator
   if (protocol == ProtocolType::MYPROTO) {
       session_key = parsed_data["my_session_id"];
   }
   ```

### Adding a New Export Format

1. **Implement Exporter Interface**
   ```cpp
   class MyFormatExporter {
   public:
       std::string exportSession(const Session& session);
   };
   ```

2. **Register Format**
   ```cpp
   if (args.output_format == "myformat") {
       MyFormatExporter exporter;
       exporter.exportToFile(filename, sessions);
   }
   ```

## Security Considerations

### Input Validation

- All packet parsing includes bounds checking
- Sanitization of string fields before export
- Validation of PCAP file structure

### Resource Limits

- Maximum packet queue size
- Maximum flow count
- Timeout for inactive flows
- Memory usage monitoring

### Isolation

- No network access during processing
- Sandboxed parsing (crash handling)
- Minimal privileges required

## Testing Strategy

### Unit Tests

- Parser correctness (valid and malformed input)
- Flow correlation logic
- Event building
- JSON export format

### Integration Tests

- End-to-end PCAP processing
- Golden output comparison
- Multi-protocol PCAPs
- Large file handling

### Performance Tests

- Throughput benchmarks
- Memory profiling
- Latency measurement
- Stress tests (concurrent access)

## Future Enhancements

### M2: API and Real-time

- REST API implementation
- WebSocket streaming
- Live capture support (DPDK)

### M3: Additional Protocols

- Full DIAMETER parsing
- GTP-C/GTP-U support
- SCTP awareness

### M4: Advanced Features

- HTTP/2 parsing
- Machine learning for anomaly detection
- Flow export (IPFIX/NetFlow)

### M5: Production Readiness

- Distributed processing
- Database backend
- Kubernetes deployment
- Monitoring and alerting
