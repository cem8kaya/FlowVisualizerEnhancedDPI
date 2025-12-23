# VoLTE Call Correlator

## Overview

The VoLTE Call Correlator provides end-to-end call tracking for Voice over LTE by correlating multiple protocol interactions into a unified call view. This feature enables comprehensive analysis of VoLTE call quality, setup times, and failure diagnostics.

## Architecture

### Components

A complete VoLTE call involves multiple protocol legs:

1. **SIP Signaling** (IMS Layer)
   - INVITE/100 Trying/180 Ringing/200 OK/ACK
   - BYE for call termination
   - Carried over TCP/UDP to P-CSCF

2. **DIAMETER Rx** (P-CSCF ↔ PCRF)
   - AAR (AA-Request) for media authorization
   - AAA (AA-Answer) with policy decision
   - Application Function (AF) to PCRF interface

3. **DIAMETER Gx** (PCRF ↔ PGW)
   - RAR (Re-Auth-Request) for policy installation
   - RAA (Re-Auth-Answer) confirming policy
   - Charging rules for bearer setup

4. **GTP-C** (S5/S8 Interface)
   - Create Bearer Request for dedicated voice bearer
   - Create Bearer Response with QCI=1 (voice)
   - EPS Bearer ID assignment

5. **RTP Media** (User Plane)
   - Voice packets over dedicated bearer
   - Packet loss, jitter, MOS estimation
   - SSRC-based stream tracking

### Data Structures

#### VolteCall

Main structure containing all call legs and computed metrics:

```cpp
struct VolteCall {
    // Identifiers
    std::string call_id;        // SIP Call-ID (primary key)
    std::string icid;           // IMS Charging ID
    std::string imsi;           // Subscriber identifier
    std::string msisdn;         // Phone number
    std::string calling_number; // Calling party
    std::string called_number;  // Called party

    // State
    enum class State {
        INITIATING, TRYING, RINGING, ANSWERED, CONFIRMED,
        MEDIA_ACTIVE, TERMINATING, COMPLETED, FAILED, CANCELLED
    };

    // Protocol legs
    SipLeg sip_leg;
    std::optional<RxLeg> rx_leg;
    std::optional<GxLeg> gx_leg;
    std::optional<BearerLeg> bearer_leg;
    std::optional<RtpLeg> rtp_leg;

    // Computed metrics
    Metrics metrics;
};
```

#### VolteCallCorrelator

Manager class for correlating protocol messages into calls:

```cpp
class VolteCallCorrelator {
public:
    // Process protocol messages
    void processSipMessage(const SessionMessageRef& msg, const SipMessage& sip);
    void processDiameterRx(const SessionMessageRef& msg, const DiameterMessage& dia);
    void processDiameterGx(const SessionMessageRef& msg, const DiameterMessage& dia);
    void processGtpBearer(const SessionMessageRef& msg, const GtpMessage& gtp);
    void processRtpPacket(const SessionMessageRef& msg, const RtpHeader& rtp);

    // Lookup operations
    std::shared_ptr<VolteCall> findByCallId(const std::string& call_id);
    std::shared_ptr<VolteCall> findByIcid(const std::string& icid);
    std::shared_ptr<VolteCall> findByTeid(uint32_t teid);
    std::vector<std::shared_ptr<VolteCall>> findByImsi(const std::string& imsi);

    // Management
    size_t cleanupCompletedCalls(std::chrono::seconds retention);
    Stats getStats() const;
};
```

## Correlation Strategy

### Primary Correlation Flow

1. **SIP INVITE** creates new call
   - Extract Call-ID as primary key
   - Extract ICID from P-Charging-Vector header
   - Extract calling/called numbers from P-Asserted-Identity
   - Store SDP media parameters (codec, RTP ports)

2. **Subscriber Resolution**
   - Lookup IMSI by UE source IP via SubscriberContextManager
   - Register ICID with subscriber context
   - Index call by IMSI for multi-call tracking

3. **DIAMETER Rx Correlation**
   - Match by ICID from P-Charging-Vector
   - Fallback: Match by UE IP + recent call
   - Link AAR/AAA pair to call

4. **DIAMETER Gx Correlation**
   - Match by UE IP (Framed-IP-Address AVP)
   - Find most recent active call for subscriber
   - Link RAR/RAA pair to call

5. **GTP Bearer Correlation**
   - Match by IMSI + QCI=1 (voice bearer)
   - Associate TEID with call for data plane tracking
   - Link Create Bearer Request/Response pair

6. **RTP Stream Correlation**
   - Match by UE IP + RTP port from SDP negotiation
   - Track SSRC for stream identification
   - Update packet/byte counters, jitter, loss

### Correlation Indices

For O(1) lookup performance:
- `call_id → VolteCall`
- `icid → call_id`
- `rx_session_id → call_id`
- `teid → call_id`
- `imsi → [call_id, ...]` (multimap for multiple calls)

## Computed Metrics

### Timing Metrics

- **setup_time**: INVITE → 200 OK (total call setup)
- **post_dial_delay**: INVITE → 180 Ringing (alerting latency)
- **answer_delay**: 180 Ringing → 200 OK (answer latency)
- **bearer_setup_time**: Create Bearer Req → Resp (bearer establishment)
- **rx_authorization_time**: AAR → AAA (policy decision latency)
- **total_call_duration**: INVITE → BYE (entire call duration)
- **media_duration**: First RTP → Last RTP (active media time)

### Quality Metrics

- **avg_mos**: Mean Opinion Score estimate (1-5 scale)
- **packet_loss_rate**: Percentage of lost RTP packets
- **jitter_ms**: Inter-packet delay variation in milliseconds

MOS is estimated from packet loss and jitter using ITU-T E-Model:
- Packet loss < 1%, Jitter < 20ms → MOS ≈ 4.0-4.5 (Good)
- Packet loss 1-3%, Jitter 20-40ms → MOS ≈ 3.5-4.0 (Acceptable)
- Packet loss > 5%, Jitter > 50ms → MOS < 3.0 (Poor)

## Usage Example

```cpp
#include "correlation/volte_call.h"
#include "correlation/subscriber_context.h"

using namespace callflow::correlation;

// Initialize
auto context_mgr = std::make_shared<SubscriberContextManager>();
auto correlator = std::make_unique<VolteCallCorrelator>(context_mgr);

// Process SIP message
SipMessage sip = parseSipPacket(packet_data);
SessionMessageRef msg{/* ... */};
correlator->processSipMessage(msg, sip);

// Find call
auto call = correlator->findByCallId(sip.call_id);
if (call) {
    std::cout << "Call state: " << static_cast<int>(call->state) << "\n";
    std::cout << "Setup time: " << call->metrics.setup_time.count() << " ms\n";
    std::cout << "MOS: " << call->metrics.avg_mos << "\n";
}

// Get aggregate statistics
auto stats = correlator->getStats();
std::cout << "Total calls: " << stats.total_calls << "\n";
std::cout << "Success rate: "
          << (stats.successful_calls * 100.0 / stats.total_calls) << "%\n";
```

## JSON Export

### Call JSON Structure

```json
{
  "call_id": "abc123@10.10.10.10",
  "icid": "icid-12345",
  "imsi": "001010123456789",
  "msisdn": "+1234567890",
  "calling_number": "sip:+1234567890@ims.example.com",
  "called_number": "sip:+9876543210@ims.example.com",
  "state": 8,
  "state_name": "COMPLETED",
  "state_reason": "Call ended normally",

  "sip_leg": {
    "call_id": "abc123@10.10.10.10",
    "from_uri": "sip:alice@example.com",
    "to_uri": "sip:bob@example.com",
    "p_cscf_ip": "192.168.1.100",
    "invite_time": 1703001000,
    "trying_time": 1703001000,
    "ringing_time": 1703001001,
    "answer_time": 1703001002,
    "ack_time": 1703001002,
    "bye_time": 1703001032,
    "audio_codec": "AMR-WB",
    "rtp_port_local": 50000,
    "rtp_port_remote": 60000
  },

  "rx_leg": {
    "session_id": "pcscf.example.com;1234567890",
    "af_app_id": "IMS Services",
    "framed_ip": "10.10.10.10",
    "aar_time": 1703001000,
    "aaa_time": 1703001000,
    "result_code": 2001,
    "media_components": [
      {
        "flow_number": 1,
        "media_type": "audio",
        "max_bandwidth_ul": 128000,
        "max_bandwidth_dl": 128000
      }
    ]
  },

  "gx_leg": {
    "session_id": "pgw.example.com;9876543210",
    "framed_ip": "10.10.10.10",
    "rar_time": 1703001000,
    "raa_time": 1703001000,
    "charging_rules": [
      {
        "rule_name": "voice_qci1",
        "qci": 1,
        "guaranteed_bandwidth_ul": 128000,
        "guaranteed_bandwidth_dl": 128000
      }
    ]
  },

  "bearer_leg": {
    "teid_uplink": 305419896,
    "teid_downlink": 2271560481,
    "eps_bearer_id": 5,
    "qci": 1,
    "gbr_ul": 128000,
    "gbr_dl": 128000,
    "request_time": 1703001000,
    "response_time": 1703001000,
    "cause": 16
  },

  "rtp_leg": {
    "ssrc": 3735928559,
    "local_ip": "10.10.10.10",
    "local_port": 50000,
    "remote_ip": "10.20.30.40",
    "remote_port": 60000,
    "uplink": {
      "packets": 1500,
      "bytes": 240000,
      "packet_loss_rate": 0.5,
      "jitter_ms": 15.2,
      "mos_estimate": 4.2,
      "first_packet": 1703001002,
      "last_packet": 1703001032
    },
    "downlink": {
      "packets": 1480,
      "bytes": 236800,
      "packet_loss_rate": 0.8,
      "jitter_ms": 18.5,
      "mos_estimate": 4.0,
      "first_packet": 1703001002,
      "last_packet": 1703001032
    }
  },

  "metrics": {
    "setup_time_ms": 2000,
    "post_dial_delay_ms": 500,
    "answer_delay_ms": 1500,
    "bearer_setup_time_ms": 100,
    "rx_authorization_time_ms": 50,
    "total_call_duration_ms": 32000,
    "media_duration_ms": 30000,
    "avg_mos": 4.1,
    "packet_loss_rate": 0.65,
    "jitter_ms": 16.85
  }
}
```

### Ladder Diagram JSON

```json
{
  "call_id": "abc123@10.10.10.10",
  "type": "volte_call",
  "participants": [
    {"id": "ue", "name": "UE (+1234567890)"},
    {"id": "pcscf", "name": "P-CSCF"},
    {"id": "pcrf", "name": "PCRF"},
    {"id": "pgw", "name": "PGW"},
    {"id": "sgw", "name": "SGW"},
    {"id": "remote", "name": "Remote Party"}
  ],
  "messages": [
    {
      "timestamp": 1703001000,
      "from": "ue",
      "to": "pcscf",
      "protocol": "SIP",
      "message": "INVITE",
      "details": "Call-ID: abc123@10.10.10.10"
    },
    {
      "timestamp": 1703001000,
      "from": "pcscf",
      "to": "pcrf",
      "protocol": "DIAMETER Rx",
      "message": "AAR",
      "details": "Media authorization request"
    },
    {
      "timestamp": 1703001000,
      "from": "pcrf",
      "to": "pcscf",
      "protocol": "DIAMETER Rx",
      "message": "AAA",
      "details": "Result-Code: 2001"
    }
    // ... more messages in chronological order
  ],
  "metrics": { /* ... */ }
}
```

## Testing

### Unit Tests

#### `test_volte_call.cpp`

Tests for VolteCall data structure:
- State transitions (INITIATING → COMPLETED)
- JSON serialization for all legs
- Metrics calculation
- Ladder diagram generation
- hasMedia(), isComplete(), isFailed() helpers

Coverage: 90%+

#### `test_volte_correlation.cpp`

Tests for correlation logic:
- SIP message processing (INVITE, 100, 180, 200, ACK, BYE)
- DIAMETER Rx processing (AAR, AAA)
- DIAMETER Gx processing (RAR, RAA)
- GTP bearer processing (Create Bearer Req/Resp)
- RTP packet correlation
- Call lookup by various keys
- Statistics and cleanup

Coverage: 85%+

### Integration Tests

#### `test_volte_full_call.cpp`

End-to-end scenarios:
- Complete successful call (all legs)
- Call failure (486 Busy Here)
- Call cancellation (CANCEL)
- Multiple calls per subscriber
- Correlation by ICID
- Correlation by TEID

## Performance Considerations

### Memory Usage

Per active call: ~2-4 KB
- Base structure: ~1 KB
- SIP leg: ~500 bytes
- Optional legs: ~500 bytes each
- RTP statistics: ~200 bytes

For 10,000 concurrent calls: ~20-40 MB

### Lookup Performance

All lookups are O(1) via hash maps:
- findByCallId: O(1)
- findByIcid: O(1)
- findByTeid: O(1)
- findByImsi: O(k) where k = calls per IMSI (typically 1-5)

### Cleanup Strategy

Use periodic cleanup to manage memory:

```cpp
// Every minute, remove calls completed > 1 hour ago
correlator->cleanupCompletedCalls(std::chrono::hours(1));
```

## Debugging

The correlator includes detailed logging via spdlog:

```cpp
spdlog::info("Created new VoLTE call: Call-ID={}, ICID={}, IMSI={}",
             call->call_id, call->icid, call->imsi);

spdlog::debug("Correlated DIAMETER Rx AAR to call {}", call->call_id);

spdlog::warn("SIP message without Call-ID, skipping");
```

Set log level for debugging:
```cpp
spdlog::set_level(spdlog::level::debug);
```

## Integration with Existing System

The VoLTE Call Correlator integrates with:

1. **SubscriberContextManager**: Resolves IMSI from UE IP addresses
2. **SessionMessageRef**: Receives parsed protocol messages
3. **Protocol Parsers**: SipParser, DiameterParser, GtpParser, RtpParser
4. **EnhancedSessionCorrelator**: Can be used alongside for multi-level correlation

## Future Enhancements

Potential improvements:
- [ ] MOS estimation refinement using R-factor calculation
- [ ] Support for VoNR (5G Voice) correlation
- [ ] Call forwarding detection
- [ ] Conference call tracking
- [ ] Detailed SIP dialog state machine
- [ ] RTCP statistics integration
- [ ] Call Detail Record (CDR) generation
- [ ] Real-time alerting for poor call quality

## References

- 3GPP TS 24.229: IMS Call Control Protocol (SIP)
- 3GPP TS 29.213: DIAMETER Rx Interface (P-CSCF - PCRF)
- 3GPP TS 29.212: DIAMETER Gx Interface (PCRF - PCEF)
- 3GPP TS 29.274: GTPv2-C Protocol
- RFC 3261: SIP Protocol
- RFC 3550: RTP Protocol
- ITU-T G.107: E-Model for Quality Estimation
