# Protocol Support Documentation

This document describes the protocol parsing capabilities of the nDPI Callflow Visualizer, with detailed focus on SCTP as the critical transport layer for 3GPP control plane interfaces.

## Table of Contents

- [SCTP (Stream Control Transmission Protocol)](#sctp-stream-control-transmission-protocol)
- [3GPP Control Plane Protocols](#3gpp-control-plane-protocols)
- [Diameter](#diameter)
- [Other Protocols](#other-protocols)

---

## SCTP (Stream Control Transmission Protocol)

### Overview

SCTP (RFC 4960) is the **mandatory transport layer** for all 3GPP control plane interfaces. Unlike TCP, SCTP provides:

- **Multi-streaming**: Multiple independent streams within a single association to avoid head-of-line blocking
- **Multi-homing**: Support for multiple IP addresses per endpoint for reliability
- **Message-oriented**: Preserves message boundaries
- **Ordered and unordered delivery**: Per-stream ordering with optional unordered delivery
- **Built-in heartbeat**: Native keep-alive mechanism

### 3GPP Usage

SCTP is used for the following 3GPP interfaces:

| Interface | Port  | PPID | Protocol | Description |
|-----------|-------|------|----------|-------------|
| S1-MME    | 36412 | 18   | S1AP     | LTE eNodeB ↔ MME control plane |
| X2-C      | 36422 | 27   | X2AP     | LTE inter-eNodeB handover |
| NG-C      | 38412 | 60   | NGAP     | 5G gNodeB ↔ AMF control plane |
| Diameter  | 3868  | 46   | Diameter | Policy, charging, authentication (optional) |

### Architecture

#### Association State Machine

```
CLOSED → COOKIE-WAIT → COOKIE-ECHOED → ESTABLISHED → SHUTDOWN-*
  ↑                                                         ↓
  └─────────────────────────────────────────────────────────┘
```

**States:**
1. **CLOSED**: No association exists
2. **COOKIE-WAIT**: INIT sent, waiting for INIT-ACK
3. **COOKIE-ECHOED**: COOKIE-ECHO sent, waiting for COOKIE-ACK
4. **ESTABLISHED**: Association active, data transfer possible
5. **SHUTDOWN-PENDING**: Local shutdown initiated, waiting for DATA acknowledgments
6. **SHUTDOWN-SENT**: SHUTDOWN sent, waiting for SHUTDOWN-ACK
7. **SHUTDOWN-RECEIVED**: Remote SHUTDOWN received
8. **SHUTDOWN-ACK-SENT**: SHUTDOWN-ACK sent, waiting for SHUTDOWN-COMPLETE

#### Packet Structure

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Source Port Number     |      Destination Port Number  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Verification Tag                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Checksum (CRC32c)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Chunk #1                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           ...                                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Chunk #N                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

#### DATA Chunk Structure

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Type = 0    | Flags |U|B|E|        Length                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Transmission Sequence Number (TSN)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Stream Identifier        |   Stream Sequence Number (SSN)|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Payload Protocol Identifier (PPID)           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                          User Data                            |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Flags:
  U = Unordered (bypass stream ordering)
  B = Beginning of fragmented message
  E = Ending of fragmented message
```

### Implementation Details

#### Components

1. **SctpParser** (`include/transport/sctp_parser.h`)
   - Parses SCTP common header (12 bytes)
   - Identifies and parses chunk types (DATA, INIT, SACK, etc.)
   - Validates CRC32c checksum
   - Tracks associations per 4-tuple
   - Maintains association state machine

2. **SctpStreamReassembler** (`include/transport/sctp_reassembler.h`)
   - Per-stream sequence tracking
   - Fragment reassembly for large messages
   - Out-of-order packet handling
   - Ordered and unordered delivery support

3. **Association Management**
   - Association identified by 5-tuple hash
   - Stores verification tags (local and peer)
   - Tracks stream counts (inbound/outbound)
   - Maintains statistics (packets, bytes, chunks)

#### Stream Reassembly Algorithm

**Ordered Delivery:**
```
1. Fragment arrives with stream_id=S, SSN=N, TSN=T
2. Add to pending_fragments[S][N]
3. Sort fragments by TSN
4. Check if message complete:
   - Has B (beginning) flag fragment
   - Has E (ending) flag fragment
   - All TSNs are consecutive
5. If complete AND N == next_expected_ssn[S]:
   - Assemble and deliver message
   - Increment next_expected_ssn[S]
   - Check if SSN=N+1 is ready (continue loop)
```

**Unordered Delivery (U flag set):**
```
1. Fragment arrives with U=1
2. If B=1 and E=1: Deliver immediately (single chunk)
3. Else: Buffer by TSN, try to find complete sequence (B...E)
4. Deliver as soon as complete (ignore SSN ordering)
```

#### PPID Routing

The Payload Protocol Identifier (PPID) in DATA chunks determines the upper-layer protocol:

```cpp
switch (ppid) {
    case 18:  // S1AP
        S1apParser.parse(data);
        break;
    case 27:  // X2AP
        X2apParser.parse(data);
        break;
    case 46:  // Diameter
        DiameterParser.parse(data);
        break;
    case 60:  // NGAP
        NgapParser.parse(data);
        break;
}
```

**Supported PPIDs:**
- 18: S1AP (LTE S1 interface)
- 27: X2AP (LTE handover)
- 46: Diameter (policy/charging)
- 60: NGAP (5G NG interface)
- 61: XWAP (LTE-WLAN aggregation)

### Checksum Validation

SCTP uses **CRC32c** (Castagnoli polynomial) instead of TCP's checksum:

```
Polynomial: 0x1EDC6F41
Initial CRC: 0xFFFFFFFF
Final XOR: 0xFFFFFFFF

Algorithm:
1. Set checksum field to 0x00000000
2. Calculate CRC32c over entire packet
3. Compare with checksum in header
```

**Why CRC32c?**
- Stronger error detection than Adler-32 or Fletcher checksum
- Hardware acceleration available (SSE4.2 instruction)
- Critical for telecom reliability

### Multi-Streaming Example

```
Association 1 (eNodeB ↔ MME):
  Stream 0: Control signaling (NGAP procedures)
  Stream 1: NAS transport (UE1)
  Stream 2: NAS transport (UE2)
  Stream 3: NAS transport (UE3)
  ...

Benefit: UE1's retransmission doesn't block UE2/UE3 messages
```

### Performance Characteristics

| Metric                    | Target          | Implementation |
|---------------------------|-----------------|----------------|
| Concurrent associations   | 100+            | ✓ Unlimited (map-based) |
| DATA chunks/second        | 10,000+         | ✓ Lock-free parsing |
| Reassembly latency        | < 1ms           | ✓ O(1) stream lookup |
| Memory per association    | < 10MB          | ✓ Dynamic allocation |
| Checksum validation       | 100% packets    | ✓ CRC32c table lookup |

### Testing

**Unit Tests** (`tests/unit/test_sctp_parser.cpp`):
- SCTP header parsing
- All chunk types (DATA, INIT, SACK, etc.)
- Association establishment sequence
- Single-chunk messages
- Multi-chunk fragmented messages
- Out-of-order delivery
- Multi-stream handling
- Association shutdown
- Checksum validation (valid and invalid)
- PPID detection

**Test Coverage:**
- Header parsing: ✓
- Chunk types: ✓ (14 standard chunks)
- Fragmentation: ✓ (B/E flag combinations)
- Ordering: ✓ (ordered and unordered)
- Multi-stream: ✓ (concurrent streams)
- State machine: ✓ (CLOSED → ESTABLISHED → CLOSED)

### Known Limitations

1. **Multi-homing**: Parsed but not actively used for failover (PCAP doesn't capture IP-level events)
2. **Partial Reliability (PR-SCTP)**: Not implemented (requires FORWARD-TSN chunk handling)
3. **Dynamic Address Reconfiguration (ASCONF)**: Parsed but not acted upon
4. **Stream Reset (RE-CONFIG)**: Chunk parsed but stream state not updated

---

## 3GPP Control Plane Protocols

### S1AP (S1 Application Protocol)

**Purpose**: Control plane signaling between LTE eNodeB and MME

**Transport**: SCTP (port 36412, PPID 18)

**Key Procedures:**
- UE attach/detach
- E-RAB (E-UTRAN Radio Access Bearer) setup/release
- Handover preparation
- Paging
- NAS transport

**Message Types:**
- Initial UE Message
- Downlink/Uplink NAS Transport
- E-RAB Setup Request/Response
- UE Context Release Command
- Handover Request/Response

---

### X2AP (X2 Application Protocol)

**Purpose**: Inter-eNodeB signaling for handover and load management

**Transport**: SCTP (port 36422, PPID 27)

**Key Procedures:**
- Handover preparation
- SN (Sequence Number) status transfer
- Load indication
- Cell activation

---

### NGAP (NG Application Protocol)

**Purpose**: Control plane signaling between 5G gNodeB and AMF (Access and Mobility Management Function)

**Transport**: SCTP (port 38412, PPID 60)

**Key Procedures:**
- UE registration
- PDU session establishment/modification/release
- Handover
- NAS transport (5G NAS messages)

**Improvements over S1AP:**
- Service-based architecture support
- Enhanced QoS handling
- Network slicing support

---

## Diameter

**Purpose**: AAA (Authentication, Authorization, Accounting) for mobile networks

**Transport**: TCP (port 3868) or SCTP (port 3868, PPID 46)

**3GPP Interfaces:**
- **S6a/S6d**: MME ↔ HSS (subscriber data, authentication)
- **Gx**: PCEF ↔ PCRF (policy control)
- **Gy**: PCEF ↔ OCS (online charging)
- **Rx**: P-CSCF ↔ PCRF (IMS policy)
- **Cx/Dx**: I-CSCF/S-CSCF ↔ HSS (IMS subscriber data)
- **Sh**: AS ↔ HSS (service data)

**Implementation**: See `include/protocol_parsers/diameter/`

---

## Other Protocols

### GTP (GPRS Tunneling Protocol)

- **GTP-C** (Control): UDP port 2123
- **GTP-U** (User data): UDP port 2152

### PFCP (Packet Forwarding Control Protocol)

- **Transport**: UDP port 8805
- **Purpose**: Control plane for 5G UPF (User Plane Function)

### SIP (Session Initiation Protocol)

- **Transport**: UDP/TCP ports 5060/5061
- **Purpose**: VoLTE call setup

### RTP (Real-time Transport Protocol)

- **Transport**: UDP ports 10000+ (even ports)
- **Purpose**: VoLTE voice media

### HTTP/2 (5G Service-Based Architecture)

- **Transport**: TCP port 80/8080/custom
- **Purpose**: 5G NF (Network Function) communication

---

## 5G Service Based Architecture (SBA)

### Overview

5G networks use a Service-Based Architecture (SBA) where Network Functions (NFs) communicate via HTTP/2-based Service-Based Interfaces (SBI). The Callflow Visualizer provides comprehensive SBA protocol support.

### Supported Network Functions

| NF | Full Name | Description |
|----|-----------|-------------|
| AMF | Access and Mobility Management Function | UE registration, mobility, access |
| SMF | Session Management Function | PDU session management |
| UDM | Unified Data Management | Subscriber data management |
| AUSF | Authentication Server Function | UE authentication |
| NRF | Network Repository Function | NF discovery and registration |
| PCF | Policy Control Function | Policy decisions |
| NEF | Network Exposure Function | API exposure to external apps |
| UPF | User Plane Function | User traffic routing |

### SBI Service Discovery

The parser identifies NF types from URI paths:

```
/namf-comm/* → AMF Communication Service
/nsmf-pdusession/* → SMF PDU Session Service
/nausf-auth/* → AUSF Authentication Service
/nudm-sdm/* → UDM Subscriber Data Management
/nnrf-disc/* → NRF Discovery Service
/npcf-smpolicy/* → PCF Session Management Policy
```

### Key Information Extraction

The SBA parser extracts critical 5G identifiers:

| Identifier | Description | Example |
|------------|-------------|---------|
| SUPI | Subscription Permanent Identifier | imsi-123456789012345 |
| PEI | Permanent Equipment Identifier | imeisv-1234567890123456 |
| GPSI | Generic Public Subscription Identifier | msisdn-14155551234 |
| DNN | Data Network Name | internet, ims |
| S-NSSAI | Network Slice Selection | {sst: 1, sd: "010203"} |
| 5G-GUTI | Globally Unique Temporary ID | {amf_id, set_id, pointer, tmsi} |

### Procedure Tracking

#### Registration Procedure
```
UE → AMF: Registration Request (NGAP)
AMF → AUSF: Nausf_UEAuthentication_Authenticate
AUSF → UDM: Nudm_UEAuthentication_Get
UDM → AUSF: Authentication Vectors
AUSF → AMF: Authentication Response
AMF → UE: Authentication Request
UE → AMF: Authentication Response
AMF → UDM: Nudm_UECM_Registration
AMF → UE: Registration Accept (NGAP)
```

#### PDU Session Establishment
```
UE → AMF: PDU Session Establishment Request (NAS)
AMF → SMF: Nsmf_PDUSession_CreateSMContext
SMF → UDM: Nudm_SDM_Get (subscription data)
SMF → PCF: Npcf_SMPolicyControl_Create
SMF → UPF: PFCP Session Establishment
SMF → AMF: N1N2MessageTransfer
AMF → UE: PDU Session Establishment Accept (NAS)
```

### HTTP/2 Stream Reassembly

The parser handles HTTP/2 complexities:

1. **Frame Types**: DATA, HEADERS, CONTINUATION
2. **HPACK Decompression**: Static + dynamic table
3. **Stream Multiplexing**: Multiple concurrent requests
4. **Fragmented Messages**: Reassemble across DATA frames
5. **gRPC Support**: Detect and parse gRPC over HTTP/2

### JSON Payload Parsing

SBI messages use JSON bodies. The parser extracts:

```json
{
  "supi": "imsi-123456789012345",
  "pei": "imeisv-1234567890123456",
  "gpsi": "msisdn-14155551234",
  "dnn": "internet",
  "sNssai": {
    "sst": 1,
    "sd": "010203"
  },
  "servingNetwork": {
    "mcc": "310",
    "mnc": "260"
  }
}
```

### Correlation Strategy

The SBA correlator uses multiple keys:

1. **SUPI/PEI**: Primary subscriber/device identity
2. **PDU Session ID**: Within a UE context
3. **HTTP/2 Stream ID**: Request-response correlation
4. **SBI Correlation ID**: Cross-NF transaction tracking
5. **UE Context ID**: AMF-assigned context reference

### Implementation Files

| File | Purpose |
|------|---------|
| `fiveg_sba_parser.h/cpp` | SBA message parsing |
| `http2_parser.h/cpp` | HTTP/2 frame parsing |
| `hpack_decoder.h/cpp` | HPACK header decompression |
| `fiveg_registration_machine.h/cpp` | 5G registration state machine |
| `sba_correlator.h/cpp` | SBA session correlation |

### Testing

Unit tests cover:
- HTTP/2 frame parsing
- HPACK decompression
- SBI path detection
- JSON payload extraction
- Multi-stream correlation
- Registration procedure tracking

### References

- **3GPP TS 29.500**: 5G SBA Technical Realization
- **3GPP TS 29.501**: 5G SBA Principles and Guidelines
- **3GPP TS 29.502**: 5G SMF Services
- **3GPP TS 29.503**: 5G UDM Services
- **3GPP TS 29.509**: 5G AUSF Services
- **3GPP TS 29.518**: 5G AMF Services
- **RFC 7540**: HTTP/2
- **RFC 7541**: HPACK Header Compression

---

## Integration Architecture

```
PCAP File
    ↓
LinkLayerParser (Ethernet/SLL)
    ↓
IpReassembler (IPv4/IPv6 fragments)
    ↓
┌─────────────┬──────────────┬──────────────┐
│   TCP       │   UDP        │   SCTP       │
│ Reassembler │   Direct     │   Parser +   │
│             │              │  Reassembler │
└─────────────┴──────────────┴──────────────┘
    ↓               ↓               ↓
processTransportAndPayload()   SctpMessageCallback
    ↓                               ↓
┌───────────────────────────────────────────┐
│        processSctpMessage()               │
│     (PPID-based routing)                  │
└───────────────────────────────────────────┘
    ↓
┌───────────┬───────────┬───────────┬───────────┐
│   S1AP    │   X2AP    │   NGAP    │ Diameter  │
│  Parser   │  Parser   │  Parser   │  Parser   │
└───────────┴───────────┴───────────┴───────────┘
    ↓
EnhancedSessionCorrelator
    ↓
JSON Output / Database
```

---

## References

- **RFC 4960**: Stream Control Transmission Protocol (SCTP)
- **RFC 6525**: SCTP Stream Reconfiguration
- **RFC 3309**: SCTP Checksum Change (CRC32c)
- **3GPP TS 36.412**: S1 Application Protocol (S1AP)
- **3GPP TS 36.422**: X2 Application Protocol (X2AP)
- **3GPP TS 38.412**: NG Application Protocol (NGAP)
- **3GPP TS 29.060**: GTP
- **3GPP TS 29.244**: PFCP
- **RFC 6733**: Diameter Base Protocol

---

## Contribution Notes

When adding new SCTP-based protocol support:

1. Add PPID constant to `SctpPayloadProtocolId` enum
2. Update `getSctpPpidName()` function
3. Add case in `PacketProcessor::processSctpMessage()`
4. Implement protocol parser following existing patterns
5. Add unit tests for new protocol
6. Update this documentation

**Example:**
```cpp
// 1. In sctp_parser.h
enum class SctpPayloadProtocolId : uint32_t {
    // ...
    NEW_PROTOCOL = 99,
};

// 2. In sctp_parser.cpp
std::string getSctpPpidName(uint32_t ppid) {
    // ...
    case SctpPayloadProtocolId::NEW_PROTOCOL: return "NEW_PROTOCOL";
}

// 3. In packet_processor.cpp
void PacketProcessor::processSctpMessage(...) {
    switch (message.payload_protocol) {
        case 99: {  // NEW_PROTOCOL
            NewProtocolParser parser;
            auto msg = parser.parse(message.data.data(), message.data.size());
            if (msg.has_value()) {
                correlator_.processPacket(metadata, ProtocolType::NEW_PROTO, msg->toJson());
            }
            break;
        }
    }
}
```

---

**Document Version**: 1.0
**Last Updated**: 2025-12-20
**Author**: Claude Code - SCTP Implementation
