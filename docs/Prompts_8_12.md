
# MILESTONE 8: PCAP Parsing & Stream Reassembly

---

## PROMPT 8.1: TCP Stream Reassembly Engine

```
# TCP Stream Reassembly Engine Implementation
## nDPI Callflow Visualizer - Robust Protocol Reassembly

**Context:**
I'm enhancing the nDPI Callflow Visualizer. The current TCP handling in `src/pcap_ingest/packet_processor.cpp` has issues:
1. Out-of-order packets are not properly reordered
2. Retransmissions cause duplicate parsing
3. FIN/RST handling doesn't flush partial buffers
4. Large SIP messages spanning multiple segments may be truncated

**Current State:**
- Milestones M1-M7 completed
- Basic TCP session tracking exists for SIP and DIAMETER
- Uses map<FiveTuple, TcpSession> in packet_processor.cpp

**Requirements:**

1. **TCP Connection Tracking**

Create `include/pcap_ingest/tcp_reassembly.h`:

```cpp
#pragma once

#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <optional>
#include <vector>

#include "common/types.h"

namespace callflow {

struct TcpSegment {
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t flags;  // SYN, ACK, FIN, RST, PSH
    std::vector<uint8_t> payload;
    Timestamp timestamp;
    bool retransmission = false;
};

struct TcpStreamState {
    enum class State { CLOSED, SYN_SENT, SYN_RECEIVED, ESTABLISHED, FIN_WAIT, CLOSED_WAIT, TIME_WAIT };
    
    State state = State::CLOSED;
    uint32_t isn_client = 0;
    uint32_t isn_server = 0;
    uint32_t next_seq_client = 0;
    uint32_t next_seq_server = 0;
    
    // Out-of-order segment buffers
    std::map<uint32_t, TcpSegment> ooo_buffer_client;
    std::map<uint32_t, TcpSegment> ooo_buffer_server;
    
    // Reassembled stream buffers
    std::vector<uint8_t> buffer_client;
    std::vector<uint8_t> buffer_server;
    
    // Statistics
    uint64_t bytes_client = 0;
    uint64_t bytes_server = 0;
    uint32_t retransmissions = 0;
    uint32_t out_of_order = 0;
    
    Timestamp first_seen;
    Timestamp last_seen;
};

class TcpReassembler {
public:
    using DataCallback = std::function<void(const FiveTuple&, Direction, 
                                            const uint8_t*, size_t, Timestamp)>;
    using StreamCloseCallback = std::function<void(const FiveTuple&)>;
    
    TcpReassembler(size_t max_streams = 100000, size_t max_buffer_per_stream = 1024 * 1024);
    ~TcpReassembler();
    
    void processPacket(const FiveTuple& ft, const TcpSegment& segment);
    void setDataCallback(DataCallback cb) { data_callback_ = std::move(cb); }
    void setCloseCallback(StreamCloseCallback cb) { close_callback_ = std::move(cb); }
    size_t cleanupStaleStreams(Timestamp now, std::chrono::seconds timeout = std::chrono::seconds(300));
    
    struct Stats {
        uint64_t total_streams;
        uint64_t active_streams;
        uint64_t bytes_reassembled;
        uint64_t retransmissions;
        uint64_t out_of_order_handled;
        uint64_t truncated_streams;
    };
    Stats getStats() const;

private:
    std::map<FiveTuple, TcpStreamState> streams_;
    DataCallback data_callback_;
    StreamCloseCallback close_callback_;
    size_t max_streams_;
    size_t max_buffer_per_stream_;
    Stats stats_;
    
    void handleSyn(TcpStreamState& state, const TcpSegment& seg, bool is_client);
    void handleData(const FiveTuple& ft, TcpStreamState& state, const TcpSegment& seg, bool is_client);
    void handleFin(const FiveTuple& ft, TcpStreamState& state, const TcpSegment& seg, bool is_client);
    void handleRst(const FiveTuple& ft, TcpStreamState& state);
    
    void deliverInOrderData(const FiveTuple& ft, TcpStreamState& state, bool is_client);
    bool isRetransmission(const TcpStreamState& state, const TcpSegment& seg, bool is_client);
    void flushBuffer(const FiveTuple& ft, TcpStreamState& state, bool is_client);
};

}  // namespace callflow
```

2. **Integration Points**
   - Replace `sip_tcp_sessions_` in `packet_processor.cpp` with `TcpReassembler`
   - Replace `diameter_tcp_sessions_` similarly
   - Add message boundary detection callbacks for each protocol

3. **Message Boundary Detection**
   - SIP: Look for `\r\n\r\n` (end of headers), then parse Content-Length
   - DIAMETER: Read 4-byte length field (bytes 1-3)
   - HTTP/2: Connection preface detection, then frame parsing

4. **Edge Cases to Handle**
   - SYN without SYN-ACK (half-open connections)
   - Data before 3-way handshake complete (early data)
   - Sequence number wraparound (> 4GB transferred)
   - Zero-window probes
   - Keep-alive packets

**File Structure:**
```
include/pcap_ingest/
  tcp_reassembly.h
  tcp_state_machine.h
  protocol_framer.h

src/pcap_ingest/
  tcp_reassembly.cpp
  tcp_state_machine.cpp
  sip_framer.cpp
  diameter_framer.cpp
  http2_framer.cpp

tests/unit/
  test_tcp_reassembly.cpp
  test_tcp_ooo.cpp
  test_tcp_retransmission.cpp

tests/pcaps/
  tcp_ooo_sip.pcap
  tcp_retransmit_diameter.pcap
  tcp_large_sip_message.pcap
```

**Testing Requirements:**

1. Unit test: Normal 3-way handshake
2. Unit test: Out-of-order segments (3 packets, arrive as 1,3,2)
3. Unit test: Retransmission detection
4. Unit test: FIN handling flushes buffer
5. Unit test: RST immediate cleanup
6. Unit test: Sequence number wraparound
7. Integration test: Large SIP INVITE (>1500 bytes, fragmented)
8. Integration test: DIAMETER over TCP with multiple messages
9. Performance test: 100k concurrent streams

**Acceptance Criteria:**
- ✅ Out-of-order packets correctly reordered
- ✅ Retransmissions detected and not double-parsed
- ✅ Stream closure flushes partial messages
- ✅ Memory bounded by max_buffer_per_stream
- ✅ Statistics tracking accurate
- ✅ Unit test coverage > 90%

Please implement with robust error handling and comprehensive logging.
```

---

## PROMPT 8.2: SCTP Chunk Reassembly for S1AP/NGAP

```
# SCTP Chunk Reassembly Implementation
## nDPI Callflow Visualizer - S1AP/NGAP Transport Support

**Context:**
I'm enhancing the nDPI Callflow Visualizer. S1AP (4G) and NGAP (5G) control plane protocols run over SCTP (ports 36412, 38412). SCTP provides:
- Multi-stream support (messages on different streams are independent)
- Message boundaries preserved (unlike TCP)
- INIT/INIT_ACK/COOKIE_ECHO/COOKIE_ACK handshake
- DATA chunks with TSN (Transmission Sequence Number)

Current state: No SCTP support exists. All S1AP/NGAP traffic is ignored.

**3GPP Reference:** 
- TS 36.412 (S1AP Transport)
- TS 38.412 (NGAP Transport)
- RFC 4960 (SCTP)

**Requirements:**

1. **SCTP Header and Chunk Parsing**

Create `include/pcap_ingest/sctp_parser.h`:

```cpp
#pragma once

#include <cstdint>
#include <optional>
#include <vector>
#include <variant>

namespace callflow {

// SCTP Common Header (12 bytes)
struct SctpHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t verification_tag;
    uint32_t checksum;
};

// Chunk Types
enum class SctpChunkType : uint8_t {
    DATA = 0,
    INIT = 1,
    INIT_ACK = 2,
    SACK = 3,
    HEARTBEAT = 4,
    HEARTBEAT_ACK = 5,
    ABORT = 6,
    SHUTDOWN = 7,
    SHUTDOWN_ACK = 8,
    ERROR = 9,
    COOKIE_ECHO = 10,
    COOKIE_ACK = 11,
    SHUTDOWN_COMPLETE = 14,
    FORWARD_TSN = 192
};

// DATA Chunk
struct SctpDataChunk {
    uint32_t tsn;
    uint16_t stream_id;
    uint16_t stream_seq;
    uint32_t ppid;  // Payload Protocol Identifier (S1AP=18, NGAP=60)
    std::vector<uint8_t> user_data;
    
    bool is_unordered;   // U flag
    bool is_beginning;   // B flag
    bool is_ending;      // E flag
};

// INIT Chunk
struct SctpInitChunk {
    uint32_t initiate_tag;
    uint32_t a_rwnd;
    uint16_t num_outbound_streams;
    uint16_t num_inbound_streams;
    uint32_t initial_tsn;
};

class SctpParser {
public:
    struct ParsedPacket {
        SctpHeader header;
        std::vector<std::variant<SctpDataChunk, SctpInitChunk, SctpChunkHeader>> chunks;
    };
    
    static std::optional<ParsedPacket> parse(const uint8_t* data, size_t len);
    static bool isSctp(const uint8_t* data, size_t len);
    static bool isS1apPort(uint16_t port) { return port == 36412; }
    static bool isNgapPort(uint16_t port) { return port == 38412; }
    
    static constexpr uint32_t PPID_S1AP = 18;
    static constexpr uint32_t PPID_NGAP = 60;
    static constexpr uint32_t PPID_X2AP = 27;
};

}  // namespace callflow
```

2. **SCTP Association State Machine**

Create `include/pcap_ingest/sctp_association.h`:

```cpp
#pragma once

#include <map>
#include <deque>

namespace callflow {

struct SctpStream {
    uint16_t stream_id;
    uint16_t next_expected_ssn;
    
    struct Fragment {
        uint32_t tsn;
        uint16_t ssn;
        std::vector<uint8_t> data;
        bool is_beginning;
        bool is_ending;
    };
    std::map<uint16_t, std::vector<Fragment>> fragment_buffer;
};

struct SctpAssociation {
    enum class State { CLOSED, COOKIE_WAIT, COOKIE_ECHOED, ESTABLISHED, SHUTDOWN_PENDING };
    
    State state = State::CLOSED;
    uint32_t local_vtag;
    uint32_t peer_vtag;
    uint32_t local_tsn;
    uint32_t peer_tsn;
    
    std::map<uint16_t, SctpStream> streams;
    
    Timestamp first_seen;
    Timestamp last_seen;
    
    uint64_t data_chunks_received = 0;
    uint64_t user_messages_delivered = 0;
    uint64_t fragments_received = 0;
};

class SctpAssociationTracker {
public:
    using MessageCallback = std::function<void(const FiveTuple&, uint16_t stream_id,
                                               uint32_t ppid, const uint8_t*, size_t, Timestamp)>;
    
    void processPacket(const FiveTuple& ft, const SctpParser::ParsedPacket& packet, Timestamp ts);
    void setMessageCallback(MessageCallback cb) { message_callback_ = std::move(cb); }
    size_t cleanupStaleAssociations(Timestamp now, std::chrono::seconds timeout);
    
private:
    std::map<FiveTuple, SctpAssociation> associations_;
    MessageCallback message_callback_;
    
    void handleInit(const FiveTuple& ft, const SctpInitChunk& init, Timestamp ts);
    void handleData(const FiveTuple& ft, SctpAssociation& assoc, const SctpDataChunk& data, Timestamp ts);
    void reassembleFragments(const FiveTuple& ft, SctpAssociation& assoc, SctpStream& stream);
};

}  // namespace callflow
```

3. **Integration with Packet Processor**
   - Detect SCTP by IP protocol number (132)
   - Route DATA chunks with PPID=18 to S1AP parser
   - Route DATA chunks with PPID=60 to NGAP parser

**File Structure:**
```
include/pcap_ingest/
  sctp_parser.h
  sctp_association.h

src/pcap_ingest/
  sctp_parser.cpp
  sctp_association.cpp

tests/unit/
  test_sctp_parser.cpp
  test_sctp_association.cpp
  test_sctp_reassembly.cpp

tests/pcaps/
  sctp_s1ap_attach.pcap
  sctp_ngap_registration.pcap
  sctp_fragmented_message.pcap
```

**Testing Requirements:**

1. Unit test: Parse SCTP header and DATA chunk
2. Unit test: Parse INIT/INIT_ACK handshake
3. Unit test: SACK processing
4. Unit test: Multi-stream message ordering
5. Unit test: Fragment reassembly (B=1,E=0 then B=0,E=1)
6. Integration test: S1AP Initial UE Message over SCTP
7. Integration test: NGAP PDU Session Resource Setup
8. Performance test: 10k messages/second on single association

**Acceptance Criteria:**
- ✅ SCTP header and all common chunk types parsed
- ✅ DATA chunk PPID correctly identifies payload protocol
- ✅ Fragmented user messages reassembled correctly
- ✅ Multi-stream handling (different streams independent)
- ✅ Association timeout and cleanup
- ✅ S1AP/NGAP messages delivered to respective parsers
- ✅ Unit test coverage > 90%

Please implement with detailed logging for SCTP state transitions.
```

---

## PROMPT 8.3: PCAPNG Multi-Interface Enhancement

```
# PCAPNG Multi-Interface Correlation
## nDPI Callflow Visualizer - Interface Metadata & Correlation

**Context:**
I'm enhancing the nDPI Callflow Visualizer. Real telecom captures often use PCAPNG with multiple interfaces:
- Interface 0: S1-MME (S1AP over SCTP)
- Interface 1: S1-U (GTP-U)
- Interface 2: SGi (User traffic to PDN)
- Interface 3: Gx (DIAMETER to PCRF)

Current state: `pcap_ingest` ignores interface metadata and treats all packets as coming from a single capture point.

**Requirements:**

1. **PCAPNG Block Parsing**

Create `include/pcap_ingest/pcapng_reader.h`:

```cpp
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace callflow {

struct PcapngInterfaceInfo {
    uint32_t interface_id;
    uint16_t link_type;
    uint32_t snap_len;
    std::string name;
    std::string description;
    std::optional<uint8_t> ts_resolution;
    
    enum class TelecomInterface {
        UNKNOWN, S1_MME, S1_U, S5_S8_C, S5_S8_U,
        S6A, SG_I, GX, RX, GY, X2_C,
        N2, N3, N4, N6, IMS_SIP, RTP_MEDIA
    };
    TelecomInterface telecom_type = TelecomInterface::UNKNOWN;
};

struct PcapngPacketInfo {
    uint32_t interface_id;
    uint64_t timestamp_high;
    uint64_t timestamp_low;
    uint32_t captured_len;
    uint32_t original_len;
    std::vector<uint8_t> packet_data;
    std::optional<uint32_t> flags;
    
    enum class Direction { UNKNOWN, INBOUND, OUTBOUND };
    Direction getDirection() const;
    uint64_t getTimestampNs(uint8_t ts_resolution) const;
};

class PcapngReader {
public:
    bool open(const std::string& filename);
    std::optional<PcapngPacketInfo> readPacket();
    const std::map<uint32_t, PcapngInterfaceInfo>& getInterfaces() const;
    std::optional<PcapngInterfaceInfo> getInterface(uint32_t id) const;
    
    static PcapngInterfaceInfo::TelecomInterface detectTelecomInterface(
        const std::string& name, const std::string& description);

private:
    std::ifstream file_;
    std::map<uint32_t, PcapngInterfaceInfo> interfaces_;
    uint64_t packets_read_ = 0;
    bool is_little_endian_ = true;
    
    bool parseBlock(uint32_t block_type, const std::vector<uint8_t>& block_data);
    bool parseSHB(const std::vector<uint8_t>& data);
    bool parseIDB(const std::vector<uint8_t>& data);
    bool parseEPB(const std::vector<uint8_t>& data, PcapngPacketInfo& packet);
};

}  // namespace callflow
```

2. **Multi-Interface Session Correlation**
   - Track which interface each packet was captured on
   - Correlate packets across interfaces (same IMSI on S1-MME and S1-U)
   - Maintain interface-aware session timelines

3. **Interface Auto-Detection**
   - Detect interface type from name patterns ("S1", "Gx", "N2")
   - Detect from observed traffic (SCTP port 36412 → S1-MME)

**File Structure:**
```
include/pcap_ingest/
  pcapng_reader.h
  interface_detector.h

src/pcap_ingest/
  pcapng_reader.cpp
  interface_detector.cpp

tests/unit/
  test_pcapng_reader.cpp
  test_interface_detection.cpp

tests/pcaps/
  multi_interface_lte.pcapng
  multi_interface_5g.pcapng
```

**Testing Requirements:**

1. Unit test: Parse PCAPNG Section Header Block
2. Unit test: Parse Interface Description Block with options
3. Unit test: Parse Enhanced Packet Block
4. Unit test: Timestamp resolution handling
5. Unit test: Interface auto-detection from name
6. Integration test: Read multi-interface PCAPNG
7. Integration test: Correlate S1-MME and S1-U by IMSI/TEID

**Acceptance Criteria:**
- ✅ Full PCAPNG block parsing (SHB, IDB, EPB, SPB)
- ✅ Interface metadata extraction
- ✅ Correct timestamp handling for different resolutions
- ✅ Auto-detection of telecom interface types
- ✅ Packets tagged with interface ID
- ✅ Backward compatibility with classic PCAP format
- ✅ Unit test coverage > 90%

Please implement with extensive error handling for malformed files.
```

---

# MILESTONE 9: Enhanced Session Correlation Engine

---

## PROMPT 9.1: Subscriber Context Manager

```
# Subscriber Context Manager Implementation
## nDPI Callflow Visualizer - Unified Identity Tracking

**Context:**
I'm enhancing the nDPI Callflow Visualizer. The `EnhancedSessionCorrelator` in `src/session/session_correlator.cpp` has correlation gaps:
1. IMSI learned from GTP is not linked to SIP sessions from same UE
2. When UE IP changes during handover, correlation is lost
3. Multiple SIP Call-IDs for same subscriber not grouped together

**Goal:** Create a central `SubscriberContextManager` that maintains a unified view of all identifiers for each subscriber.

**Requirements:**

1. **Subscriber Context Structure**

Create `include/correlation/subscriber_context.h`:

```cpp
#pragma once

#include <chrono>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

namespace callflow {
namespace correlation {

struct SubscriberContext {
    std::string context_id;
    
    // Primary Identifiers
    std::optional<std::string> imsi;
    std::optional<std::string> supi;
    std::optional<std::string> msisdn;
    std::optional<std::string> imei;
    std::optional<std::string> imeisv;
    
    // Temporary Identifiers
    struct GUTI {
        std::string mcc_mnc;
        uint16_t mme_group_id;
        uint8_t mme_code;
        uint32_t m_tmsi;
        std::string toString() const;
        bool operator==(const GUTI& other) const;
    };
    std::optional<GUTI> current_guti;
    std::vector<GUTI> guti_history;
    
    // Network-Assigned Identifiers
    std::set<std::string> ue_ipv4_addresses;
    std::set<std::string> ue_ipv6_addresses;
    std::string current_ue_ipv4;
    std::string current_ue_ipv6;
    
    // Bearer/Tunnel Identifiers
    struct BearerInfo {
        uint32_t teid;
        uint8_t eps_bearer_id;
        std::string interface;
        std::string pgw_ip;
        uint8_t qci;
        std::chrono::system_clock::time_point created;
        std::optional<std::chrono::system_clock::time_point> deleted;
        bool is_active() const { return !deleted.has_value(); }
    };
    std::vector<BearerInfo> bearers;
    
    std::set<uint64_t> seids;  // PFCP
    
    // Control Plane Context IDs
    std::optional<uint32_t> mme_ue_s1ap_id;
    std::optional<uint32_t> enb_ue_s1ap_id;
    std::optional<uint64_t> amf_ue_ngap_id;
    std::optional<uint64_t> ran_ue_ngap_id;
    
    // IMS/VoLTE Identifiers
    std::set<std::string> sip_uris;
    std::string current_sip_uri;
    std::set<std::string> sip_call_ids;
    std::set<std::string> icids;
    
    // Session References
    std::set<std::string> session_ids;
    
    // Lifecycle
    std::chrono::system_clock::time_point first_seen;
    std::chrono::system_clock::time_point last_updated;
    
    bool hasIdentifier(const std::string& id) const;
    std::string getPrimaryIdentifier() const;
    nlohmann::json toJson() const;
};

class SubscriberContextManager {
public:
    SubscriberContextManager(size_t max_contexts = 1000000);
    ~SubscriberContextManager();
    
    // Lookup Methods
    std::shared_ptr<SubscriberContext> findByImsi(const std::string& imsi);
    std::shared_ptr<SubscriberContext> findBySupi(const std::string& supi);
    std::shared_ptr<SubscriberContext> findByMsisdn(const std::string& msisdn);
    std::shared_ptr<SubscriberContext> findByGuti(const SubscriberContext::GUTI& guti);
    std::shared_ptr<SubscriberContext> findByUeIp(const std::string& ip);
    std::shared_ptr<SubscriberContext> findByTeid(uint32_t teid);
    std::shared_ptr<SubscriberContext> findBySeid(uint64_t seid);
    std::shared_ptr<SubscriberContext> findBySipUri(const std::string& uri);
    std::shared_ptr<SubscriberContext> findBySipCallId(const std::string& call_id);
    std::shared_ptr<SubscriberContext> findByMmeUeId(uint32_t mme_ue_s1ap_id);
    std::shared_ptr<SubscriberContext> findByAmfUeId(uint64_t amf_ue_ngap_id);
    
    // Registration Methods
    std::shared_ptr<SubscriberContext> getOrCreate(const std::string& imsi);
    std::shared_ptr<SubscriberContext> getOrCreateBySupi(const std::string& supi);
    
    // Update Methods
    void updateImsi(const std::string& context_id, const std::string& imsi);
    void updateGuti(const std::string& context_id, const SubscriberContext::GUTI& guti);
    void updateUeIp(const std::string& context_id, const std::string& ipv4, const std::string& ipv6 = "");
    void addBearer(const std::string& context_id, const SubscriberContext::BearerInfo& bearer);
    void removeBearer(const std::string& context_id, uint32_t teid);
    void updateSipUri(const std::string& context_id, const std::string& uri);
    void addSipCallId(const std::string& context_id, const std::string& call_id);
    void addSessionId(const std::string& context_id, const std::string& session_id);
    
    // Merge
    void mergeContexts(const std::string& context_id_keep, const std::string& context_id_merge);
    
    // Cleanup
    size_t cleanupStaleContexts(std::chrono::system_clock::time_point cutoff);
    
    // Statistics
    struct Stats {
        size_t total_contexts;
        size_t with_imsi;
        size_t with_msisdn;
        size_t with_ue_ip;
        size_t with_active_bearers;
        size_t with_sip_sessions;
        size_t lookups_total;
        size_t lookups_hit;
    };
    Stats getStats() const;

private:
    mutable std::shared_mutex mutex_;
    
    std::unordered_map<std::string, std::shared_ptr<SubscriberContext>> contexts_;
    
    // Lookup indices
    std::unordered_map<std::string, std::string> imsi_index_;
    std::unordered_map<std::string, std::string> supi_index_;
    std::unordered_map<std::string, std::string> msisdn_index_;
    std::unordered_map<std::string, std::string> guti_index_;
    std::unordered_map<std::string, std::string> ue_ip_index_;
    std::unordered_map<uint32_t, std::string> teid_index_;
    std::unordered_map<uint64_t, std::string> seid_index_;
    std::unordered_map<std::string, std::string> sip_uri_index_;
    std::unordered_map<std::string, std::string> sip_call_id_index_;
    std::unordered_map<uint32_t, std::string> mme_ue_id_index_;
    std::unordered_map<uint64_t, std::string> amf_ue_id_index_;
    
    size_t max_contexts_;
    mutable Stats stats_;
    
    std::string generateContextId();
};

}  // namespace correlation
}  // namespace callflow
```

2. **Integration with Packet Processing**
   - After parsing GTP Create Session Response: Update context with IMSI, TEID, UE IP
   - After parsing NAS Attach Accept: Update context with GUTI
   - After parsing SIP REGISTER: Link SIP URI to context (lookup by UE IP)
   - After parsing SIP INVITE: Add Call-ID to context

3. **Context Merge Logic**
   - When we learn IMSI from GTP and later see same UE IP in SIP, merge contexts
   - When GUTI maps to existing IMSI, update instead of create new

**File Structure:**
```
include/correlation/
  subscriber_context.h
  subscriber_context_manager.h

src/correlation/
  subscriber_context.cpp
  subscriber_context_manager.cpp

tests/unit/
  test_subscriber_context.cpp
  test_context_lookup.cpp
  test_context_merge.cpp

tests/integration/
  test_lte_attach_correlation.cpp
  test_volte_correlation.cpp
```

**Testing Requirements:**

1. Unit test: Create context with IMSI
2. Unit test: Lookup by each identifier type
3. Unit test: Add/remove bearer
4. Unit test: GUTI update and history
5. Unit test: Context merge
6. Integration test: Full LTE attach (IMSI → GUTI → UE IP → TEID)
7. Integration test: IMS registration (UE IP → SIP URI)
8. Integration test: VoLTE call (SIP URI → Call-ID → RTP)
9. Performance test: 100,000 contexts with 10M lookups

**Acceptance Criteria:**
- ✅ All identifier types indexed for fast lookup (<100ns)
- ✅ Context merge preserves all identifiers
- ✅ Bearer lifecycle tracked correctly
- ✅ Thread-safe for concurrent access
- ✅ Memory efficient (<2KB per context)
- ✅ Stale context cleanup works
- ✅ Unit test coverage > 95%

Please implement with comprehensive logging for debugging correlation issues.
```

---

# MILESTONE 10: VoLTE End-to-End Call Correlation

---

## PROMPT 10.1: VoLTE Call Correlator

```
# VoLTE End-to-End Call Correlator
## nDPI Callflow Visualizer - Complete VoLTE Session Tracking

**Context:**
I'm enhancing the nDPI Callflow Visualizer. A VoLTE call involves:
1. SIP INVITE/200 OK/ACK signaling (via P-CSCF)
2. DIAMETER Rx AAR/AAA (P-CSCF → PCRF for QoS)
3. DIAMETER Gx RAR/RAA (PCRF → PGW for bearer)
4. GTP Create Bearer Request/Response (dedicated QCI-1 bearer)
5. RTP media streams (audio over dedicated bearer)

Current state: These are tracked as separate sessions. Need unified "VoLTE Call" entity.

**Requirements:**

1. **VoLTE Call Structure**

Create `include/correlation/volte_call.h`:

```cpp
#pragma once

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "correlation/subscriber_context.h"
#include "session/session_types.h"

namespace callflow {
namespace correlation {

struct VolteCall {
    std::string call_id;
    std::string icid;
    
    std::string imsi;
    std::string msisdn;
    std::string calling_number;
    std::string called_number;
    
    enum class State {
        INITIATING, TRYING, RINGING, ANSWERED, CONFIRMED,
        MEDIA_ACTIVE, TERMINATING, COMPLETED, FAILED, CANCELLED
    };
    State state = State::INITIATING;
    std::string state_reason;
    
    // SIP Leg
    struct SipLeg {
        std::string session_id;
        std::string call_id;
        std::string from_uri;
        std::string to_uri;
        std::string p_cscf_ip;
        
        std::chrono::system_clock::time_point invite_time;
        std::optional<std::chrono::system_clock::time_point> trying_time;
        std::optional<std::chrono::system_clock::time_point> ringing_time;
        std::optional<std::chrono::system_clock::time_point> answer_time;
        std::optional<std::chrono::system_clock::time_point> ack_time;
        std::optional<std::chrono::system_clock::time_point> bye_time;
        
        std::string audio_codec;
        uint16_t rtp_port_local;
        uint16_t rtp_port_remote;
    };
    SipLeg sip_leg;
    
    // DIAMETER Rx Leg
    struct RxLeg {
        std::string session_id;
        std::string af_app_id;
        std::string framed_ip;
        
        std::chrono::system_clock::time_point aar_time;
        std::optional<std::chrono::system_clock::time_point> aaa_time;
        
        uint32_t result_code;
        
        struct MediaComponent {
            uint32_t flow_number;
            std::string media_type;
            uint32_t max_bandwidth_ul;
            uint32_t max_bandwidth_dl;
        };
        std::vector<MediaComponent> media_components;
    };
    std::optional<RxLeg> rx_leg;
    
    // DIAMETER Gx Leg
    struct GxLeg {
        std::string session_id;
        std::string framed_ip;
        
        std::chrono::system_clock::time_point rar_time;
        std::optional<std::chrono::system_clock::time_point> raa_time;
        
        struct ChargingRule {
            std::string rule_name;
            uint8_t qci;
            uint32_t guaranteed_bandwidth_ul;
            uint32_t guaranteed_bandwidth_dl;
        };
        std::vector<ChargingRule> charging_rules;
    };
    std::optional<GxLeg> gx_leg;
    
    // GTP Bearer Leg
    struct BearerLeg {
        std::string session_id;
        uint32_t teid_uplink;
        uint32_t teid_downlink;
        uint8_t eps_bearer_id;
        uint8_t qci;
        uint32_t gbr_ul;
        uint32_t gbr_dl;
        
        std::chrono::system_clock::time_point request_time;
        std::optional<std::chrono::system_clock::time_point> response_time;
        
        uint32_t cause;
    };
    std::optional<BearerLeg> bearer_leg;
    
    // RTP Media Leg
    struct RtpLeg {
        uint32_t ssrc;
        std::string local_ip;
        uint16_t local_port;
        std::string remote_ip;
        uint16_t remote_port;
        
        struct Direction {
            uint64_t packets;
            uint64_t bytes;
            double packet_loss_rate;
            double jitter_ms;
            double mos_estimate;
            std::chrono::system_clock::time_point first_packet;
            std::chrono::system_clock::time_point last_packet;
        };
        Direction uplink;
        Direction downlink;
    };
    std::optional<RtpLeg> rtp_leg;
    
    // Computed Metrics
    struct Metrics {
        std::chrono::milliseconds setup_time;
        std::chrono::milliseconds post_dial_delay;
        std::chrono::milliseconds answer_delay;
        std::chrono::milliseconds bearer_setup_time;
        std::chrono::milliseconds rx_authorization_time;
        std::chrono::milliseconds total_call_duration;
        std::chrono::milliseconds media_duration;
        double avg_mos;
        double packet_loss_rate;
        double jitter_ms;
        
        nlohmann::json toJson() const;
    };
    Metrics metrics;
    
    std::chrono::system_clock::time_point start_time;
    std::chrono::system_clock::time_point end_time;
    
    bool isComplete() const;
    bool isFailed() const;
    bool hasMedia() const;
    nlohmann::json toJson() const;
    nlohmann::json toLadderDiagramJson() const;
};

class VolteCallCorrelator {
public:
    VolteCallCorrelator(std::shared_ptr<SubscriberContextManager> context_mgr);
    
    void processSipMessage(const SessionMessageRef& msg, const SipMessage& sip);
    void processDiameterRx(const SessionMessageRef& msg, const DiameterMessage& dia);
    void processDiameterGx(const SessionMessageRef& msg, const DiameterMessage& dia);
    void processGtpBearer(const SessionMessageRef& msg, const GtpMessage& gtp);
    void processRtpPacket(const SessionMessageRef& msg, const RtpPacket& rtp);
    
    std::shared_ptr<VolteCall> findByCallId(const std::string& call_id);
    std::shared_ptr<VolteCall> findByIcid(const std::string& icid);
    std::shared_ptr<VolteCall> findByRxSessionId(const std::string& session_id);
    std::shared_ptr<VolteCall> findByTeid(uint32_t teid);
    std::vector<std::shared_ptr<VolteCall>> findByImsi(const std::string& imsi);
    
    std::vector<std::shared_ptr<VolteCall>> getAllCalls() const;
    std::vector<std::shared_ptr<VolteCall>> getActiveCalls() const;
    
    size_t cleanupCompletedCalls(std::chrono::seconds retention);
    
    struct Stats {
        uint64_t total_calls;
        uint64_t successful_calls;
        uint64_t failed_calls;
        uint64_t active_calls;
        double avg_setup_time_ms;
        double avg_mos;
    };
    Stats getStats() const;

private:
    std::shared_ptr<SubscriberContextManager> context_mgr_;
    std::unordered_map<std::string, std::shared_ptr<VolteCall>> calls_by_call_id_;
    std::unordered_map<std::string, std::string> icid_to_call_id_;
    std::unordered_map<std::string, std::string> rx_session_to_call_id_;
    std::unordered_map<uint32_t, std::string> teid_to_call_id_;
    
    void correlateRxToCall(std::shared_ptr<VolteCall> call, const std::string& framed_ip);
    void correlateBearerToCall(std::shared_ptr<VolteCall> call, const std::string& ue_ip);
    void correlateRtpToCall(std::shared_ptr<VolteCall> call, const std::string& ue_ip, uint16_t port);
    void updateCallState(std::shared_ptr<VolteCall> call, VolteCall::State new_state, const std::string& reason = "");
    void calculateMetrics(std::shared_ptr<VolteCall> call);
};

}  // namespace correlation
}  // namespace callflow
```

2. **Correlation Logic**
   - SIP INVITE with P-Charging-Vector → Extract ICID
   - Lookup subscriber by UE source IP → Get IMSI
   - DIAMETER Rx AAR with matching ICID → Link to call
   - DIAMETER Gx RAR with same Framed-IP → Link to call
   - GTP Create Bearer for same IMSI with QCI=1 → Link to call
   - RTP packets to SDP-negotiated ports → Link to call

**File Structure:**
```
include/correlation/
  volte_call.h
  volte_call_correlator.h

src/correlation/
  volte_call.cpp
  volte_call_correlator.cpp

tests/unit/
  test_volte_call.cpp
  test_volte_correlation.cpp

tests/integration/
  test_volte_full_call.cpp

tests/pcaps/
  volte_call_complete.pcap
  volte_call_failed.pcap
```

**Testing Requirements:**

1. Unit test: Create call from INVITE
2. Unit test: State transitions
3. Unit test: Rx correlation by ICID
4. Unit test: Bearer correlation by IMSI
5. Unit test: RTP correlation by port
6. Unit test: Metrics calculation
7. Integration test: Complete VoLTE call flow
8. Integration test: Call failure (reject)
9. Integration test: Call cancel

**Acceptance Criteria:**
- ✅ All VoLTE call legs correlated
- ✅ Correct state tracking
- ✅ Accurate timing metrics
- ✅ MOS estimation from RTP stats
- ✅ Ladder diagram JSON generation
- ✅ Unit test coverage > 90%

Please implement with detailed logging for correlation debugging.
```


MILESTONE 11: DIAMETER Policy Interfaces (Gx/Rx/Gy)
Duration: 1.5 weeks
Priority: High
Dependencies: M3 (DIAMETER base parser)
Objectives

Implement DIAMETER Gx parser (Policy Control)
Implement DIAMETER Rx parser (IMS QoS)
Implement DIAMETER Gy parser (Online Charging)
Support charging rule and media component parsing


PROMPT 11.1: DIAMETER Gx Interface Parser
markdown# DIAMETER Gx Interface Parser
## nDPI Callflow Visualizer - Policy and Charging Control

**Context:**
I'm enhancing the nDPI Callflow Visualizer. Gx is the interface between PCRF and PCEF (PGW) for policy and charging control. It's critical for VoLTE (installing QCI-1 bearers) and data sessions (enforcing fair usage policies).

**3GPP Reference:** TS 29.212 (Policy and Charging Control over Gx)

**Requirements:**

1. **Gx Message Types**
```cpp
// include/protocol_parsers/diameter/diameter_gx.h
#pragma once

#include "protocol_parsers/diameter_parser.h"

namespace callflow {
namespace diameter {

// Gx Application ID
static constexpr uint32_t GX_APPLICATION_ID = 16777238;

// Gx Command Codes
enum class GxCommandCode : uint32_t {
    CC_REQUEST = 272,   // CCR
    CC_ANSWER = 272,    // CCA
    RE_AUTH_REQUEST = 258,  // RAR
    RE_AUTH_ANSWER = 258    // RAA
};

// CC-Request-Type values
enum class CcRequestType : uint32_t {
    INITIAL_REQUEST = 1,
    UPDATE_REQUEST = 2,
    TERMINATION_REQUEST = 3,
    EVENT_REQUEST = 4
};

// Gx AVP Codes (3GPP)
enum class GxAVPCode : uint32_t {
    // Session (base)
    CC_REQUEST_TYPE = 416,
    CC_REQUEST_NUMBER = 415,
    
    // Subscription
    SUBSCRIPTION_ID = 443,
    SUBSCRIPTION_ID_DATA = 444,
    SUBSCRIPTION_ID_TYPE = 450,
    
    // Bearer
    BEARER_IDENTIFIER = 1020,
    BEARER_OPERATION = 1021,
    
    // QoS
    QOS_INFORMATION = 1016,
    QOS_CLASS_IDENTIFIER = 1028,
    MAX_REQUESTED_BANDWIDTH_UL = 516,
    MAX_REQUESTED_BANDWIDTH_DL = 515,
    GUARANTEED_BITRATE_UL = 1026,
    GUARANTEED_BITRATE_DL = 1025,
    ALLOCATION_RETENTION_PRIORITY = 1034,
    PRIORITY_LEVEL = 1046,
    PRE_EMPTION_CAPABILITY = 1047,
    PRE_EMPTION_VULNERABILITY = 1048,
    
    // Charging
    CHARGING_RULE_INSTALL = 1001,
    CHARGING_RULE_REMOVE = 1002,
    CHARGING_RULE_DEFINITION = 1003,
    CHARGING_RULE_BASE_NAME = 1004,
    CHARGING_RULE_NAME = 1005,
    FLOW_INFORMATION = 1058,
    FLOW_DESCRIPTION = 507,
    
    // User info
    FRAMED_IP_ADDRESS = 8,
    FRAMED_IPV6_PREFIX = 97,
    CALLED_STATION_ID = 30,  // APN
    
    // Events
    EVENT_TRIGGER = 1006,
    
    // Results
    RULE_FAILURE_CODE = 1031,
    CHARGING_RULE_REPORT = 1018
};

// Event Trigger values
enum class EventTrigger : uint32_t {
    SGSN_CHANGE = 0,
    QOS_CHANGE = 1,
    RAT_CHANGE = 2,
    TFT_CHANGE = 3,
    PLMN_CHANGE = 4,
    LOSS_OF_BEARER = 5,
    RECOVERY_OF_BEARER = 6,
    IP_CAN_CHANGE = 7,
    QOS_CHANGE_EXCEEDING_AUTHORIZATION = 11,
    RAI_CHANGE = 12,
    USER_LOCATION_CHANGE = 13,
    NO_EVENT_TRIGGERS = 14,
    OUT_OF_CREDIT = 15,
    REALLOCATION_OF_CREDIT = 16,
    REVALIDATION_TIMEOUT = 17,
    UE_IP_ADDRESS_ALLOCATE = 18,
    UE_IP_ADDRESS_RELEASE = 19,
    DEFAULT_EPS_BEARER_QOS_CHANGE = 20,
    AN_GW_CHANGE = 21,
    SUCCESSFUL_RESOURCE_ALLOCATION = 22,
    RESOURCE_MODIFICATION_REQUEST = 23,
    PGW_TRACE_CONTROL = 24,
    UE_TIME_ZONE_CHANGE = 25,
    TAI_CHANGE = 26,
    ECGI_CHANGE = 27,
    CHARGING_CORRELATION_EXCHANGE = 28,
    APN_AMBR_MODIFICATION_FAILURE = 29,
    USER_CSG_INFORMATION_CHANGE = 30,
    USAGE_REPORT = 33,
    DEFAULT_EPS_BEARER_QOS_MODIFICATION_FAILURE = 34,
    APPLICATION_START = 39,
    APPLICATION_STOP = 40
};

// Charging Rule structures
struct FlowDescription {
    std::string description;    // IPFilterRule format
    enum Direction { IN, OUT, BIDIRECTIONAL } direction;
};

struct ChargingRule {
    std::string rule_name;
    std::optional rule_base_name;
    std::vector flows;
    
    // QoS
    std::optional qci;
    std::optional max_bandwidth_ul;
    std::optional max_bandwidth_dl;
    std::optional guaranteed_bandwidth_ul;
    std::optional guaranteed_bandwidth_dl;
    
    // ARP
    std::optional priority_level;
    std::optional pre_emption_capability;
    std::optional pre_emption_vulnerability;
    
    // Rating
    std::optional rating_group;
    std::optional service_identifier;
    
    // Precedence
    std::optional precedence;
    
    nlohmann::json toJson() const;
};

struct QoSInformation {
    std::optional qci;
    std::optional max_bandwidth_ul;
    std::optional max_bandwidth_dl;
    std::optional guaranteed_bandwidth_ul;
    std::optional guaranteed_bandwidth_dl;
    
    // ARP
    std::optional priority_level;
    std::optional pre_emption_capability;
    std::optional pre_emption_vulnerability;
    
    nlohmann::json toJson() const;
};

// Gx CCR Message
struct GxCCR {
    CcRequestType request_type;
    uint32_t request_number;
    std::string session_id;
    
    // Subscription ID (IMSI/MSISDN)
    std::optional imsi;
    std::optional msisdn;
    
    // Network info
    std::optional framed_ip_address;
    std::optional framed_ipv6_prefix;
    std::optional called_station_id;  // APN
    
    // Bearer
    std::optional bearer_identifier;
    
    // Default QoS
    std::optional default_qos;
    
    // Event triggers
    std::vector event_triggers;
    
    nlohmann::json toJson() const;
};

// Gx CCA Message
struct GxCCA {
    uint32_t result_code;
    std::optional experimental_result_code;
    std::string session_id;
    CcRequestType request_type;
    uint32_t request_number;
    
    // Rules to install
    std::vector rules_to_install;
    
    // Rules to remove
    std::vector rules_to_remove;
    
    // Default QoS
    std::optional default_qos;
    
    // Events to report
    std::vector event_triggers;
    
    nlohmann::json toJson() const;
};

// Gx RAR Message (PCRF → PCEF)
struct GxRAR {
    std::string session_id;
    
    // Rules to install
    std::vector rules_to_install;
    
    // Rules to remove
    std::vector rules_to_remove;
    
    // QoS update
    std::optional default_qos;
    
    // Event triggers to add/remove
    std::vector event_triggers_to_add;
    std::vector event_triggers_to_remove;
    
    nlohmann::json toJson() const;
};

// Gx RAA Message
struct GxRAA {
    std::string session_id;
    uint32_t result_code;
    std::optional experimental_result_code;
    
    // Rule reports (success/failure)
    struct RuleReport {
        std::string rule_name;
        uint32_t rule_failure_code;
    };
    std::vector rule_reports;
    
    nlohmann::json toJson() const;
};

class DiameterGxParser {
public:
    static GxCCR parseCCR(const DiameterMessage& msg);
    static GxCCA parseCCA(const DiameterMessage& msg);
    static GxRAR parseRAR(const DiameterMessage& msg);
    static GxRAA parseRAA(const DiameterMessage& msg);
    
    static bool isGx(const DiameterMessage& msg) {
        return msg.header.application_id == GX_APPLICATION_ID;
    }
    
    static ChargingRule parseChargingRuleDefinition(const DiameterAVP& avp);
    static QoSInformation parseQoSInformation(const DiameterAVP& avp);

private:
    static std::string parseSubscriptionId(const std::vector& avps, uint32_t type);
    static std::vector parseEventTriggers(const std::vector& avps);
};

}  // namespace diameter
}  // namespace callflow
```

**File Structure:**
include/protocol_parsers/diameter/
diameter_gx.h
gx_types.h
src/protocol_parsers/diameter/
diameter_gx_parser.cpp
gx_charging_rule_parser.cpp
tests/unit/
test_diameter_gx.cpp
test_gx_charging_rules.cpp
tests/pcaps/
gx_ccr_initial.pcap
gx_rar_volte_bearer.pcap

**Testing Requirements:**

1. Unit test: Parse CCR-Initial
2. Unit test: Parse CCA with charging rules
3. Unit test: Parse RAR for VoLTE bearer
4. Unit test: Parse Charging-Rule-Definition
5. Unit test: Parse QoS-Information
6. Unit test: Extract IMSI from Subscription-Id
7. Integration test: Gx session for data
8. Integration test: Gx RAR for VoLTE

**Acceptance Criteria:**
- ✅ Parse all Gx message types (CCR/CCA/RAR/RAA)
- ✅ Extract charging rules with QoS
- ✅ Parse event triggers
- ✅ Extract subscription identifiers
- ✅ Support grouped AVPs (Charging-Rule-Definition)
- ✅ Unit test coverage > 90%

Please implement with comprehensive error handling for malformed AVPs.



PROMPT 11.1: DIAMETER Gx Interface Parser
markdown# DIAMETER Gx Interface Parser
## nDPI Callflow Visualizer - Policy and Charging Control

**Context:**
I'm enhancing the nDPI Callflow Visualizer. Gx is the interface between PCRF (Policy and Charging Rules Function) and PCEF (Policy and Charging Enforcement Function, typically the PGW/SMF). It's critical for:
- VoLTE: Installing QCI-1 dedicated bearers for voice
- Data sessions: Enforcing fair usage policies
- QoS management: Applying bandwidth limits and ARP

**3GPP Reference:** TS 29.212 (Policy and Charging Control over Gx)

**Requirements:**

1. **Gx Message Types and Application ID**
```cpp
// include/protocol_parsers/diameter/diameter_gx.h
#pragma once

#include "protocol_parsers/diameter_parser.h"

namespace callflow {
namespace diameter {

// Gx Application ID
static constexpr uint32_t GX_APPLICATION_ID = 16777238;

// Gx Command Codes
enum class GxCommandCode : uint32_t {
    CC_REQUEST = 272,   // CCR - Credit Control Request
    CC_ANSWER = 272,    // CCA - Credit Control Answer
    RE_AUTH_REQUEST = 258,  // RAR - Re-Auth Request
    RE_AUTH_ANSWER = 258    // RAA - Re-Auth Answer
};

// CC-Request-Type values (AVP 416)
enum class CcRequestType : uint32_t {
    INITIAL_REQUEST = 1,
    UPDATE_REQUEST = 2,
    TERMINATION_REQUEST = 3,
    EVENT_REQUEST = 4
};

// Gx AVP Codes (3GPP Vendor ID = 10415)
enum class GxAVPCode : uint32_t {
    // Session control (base DIAMETER)
    CC_REQUEST_TYPE = 416,
    CC_REQUEST_NUMBER = 415,
    
    // Subscription identification
    SUBSCRIPTION_ID = 443,
    SUBSCRIPTION_ID_DATA = 444,
    SUBSCRIPTION_ID_TYPE = 450,
    
    // Bearer management (3GPP)
    BEARER_IDENTIFIER = 1020,
    BEARER_OPERATION = 1021,
    DEFAULT_EPS_BEARER_QOS = 1049,
    
    // QoS-Information grouped AVP (3GPP)
    QOS_INFORMATION = 1016,
    QOS_CLASS_IDENTIFIER = 1028,
    MAX_REQUESTED_BANDWIDTH_UL = 516,
    MAX_REQUESTED_BANDWIDTH_DL = 515,
    GUARANTEED_BITRATE_UL = 1026,
    GUARANTEED_BITRATE_DL = 1025,
    
    // Allocation and Retention Priority (ARP)
    ALLOCATION_RETENTION_PRIORITY = 1034,
    PRIORITY_LEVEL = 1046,
    PRE_EMPTION_CAPABILITY = 1047,
    PRE_EMPTION_VULNERABILITY = 1048,
    
    // Charging Rules
    CHARGING_RULE_INSTALL = 1001,
    CHARGING_RULE_REMOVE = 1002,
    CHARGING_RULE_DEFINITION = 1003,
    CHARGING_RULE_BASE_NAME = 1004,
    CHARGING_RULE_NAME = 1005,
    
    // Flow information
    FLOW_INFORMATION = 1058,
    FLOW_DESCRIPTION = 507,
    FLOW_DIRECTION = 1080,
    
    // User identity and network info
    FRAMED_IP_ADDRESS = 8,
    FRAMED_IPV6_PREFIX = 97,
    CALLED_STATION_ID = 30,  // APN
    
    // Triggers and events
    EVENT_TRIGGER = 1006,
    
    // Results and reporting
    RULE_FAILURE_CODE = 1031,
    CHARGING_RULE_REPORT = 1018,
    PCC_RULE_STATUS = 1019,
    
    // Rating
    RATING_GROUP = 432,
    SERVICE_IDENTIFIER = 439,
    PRECEDENCE = 1010,
    
    // Usage monitoring
    USAGE_MONITORING_INFORMATION = 1067,
    MONITORING_KEY = 1066,
    GRANTED_SERVICE_UNIT = 431,
    USED_SERVICE_UNIT = 446
};

// Event Trigger values (TS 29.212 Section 5.3.7)
enum class EventTrigger : uint32_t {
    SGSN_CHANGE = 0,
    QOS_CHANGE = 1,
    RAT_CHANGE = 2,
    TFT_CHANGE = 3,
    PLMN_CHANGE = 4,
    LOSS_OF_BEARER = 5,
    RECOVERY_OF_BEARER = 6,
    IP_CAN_CHANGE = 7,
    QOS_CHANGE_EXCEEDING_AUTHORIZATION = 11,
    RAI_CHANGE = 12,
    USER_LOCATION_CHANGE = 13,
    NO_EVENT_TRIGGERS = 14,
    OUT_OF_CREDIT = 15,
    REALLOCATION_OF_CREDIT = 16,
    REVALIDATION_TIMEOUT = 17,
    UE_IP_ADDRESS_ALLOCATE = 18,
    UE_IP_ADDRESS_RELEASE = 19,
    DEFAULT_EPS_BEARER_QOS_CHANGE = 20,
    AN_GW_CHANGE = 21,
    SUCCESSFUL_RESOURCE_ALLOCATION = 22,
    RESOURCE_MODIFICATION_REQUEST = 23,
    PGW_TRACE_CONTROL = 24,
    UE_TIME_ZONE_CHANGE = 25,
    TAI_CHANGE = 26,
    ECGI_CHANGE = 27,
    CHARGING_CORRELATION_EXCHANGE = 28,
    APN_AMBR_MODIFICATION_FAILURE = 29,
    USER_CSG_INFORMATION_CHANGE = 30,
    USAGE_REPORT = 33,
    DEFAULT_EPS_BEARER_QOS_MODIFICATION_FAILURE = 34,
    USER_CSG_HYBRID_SUBSCRIBED_INFORMATION_CHANGE = 35,
    USER_CSG_HYBRID_UNSUBSCRIBED_INFORMATION_CHANGE = 36,
    ROUTING_RULE_CHANGE = 37,
    APPLICATION_START = 39,
    APPLICATION_STOP = 40,
    CS_TO_PS_HANDOVER = 42,
    UE_LOCAL_IP_ADDRESS_CHANGE = 43,
    HENB_LOCAL_IP_ADDRESS_CHANGE = 44,
    ACCESS_NETWORK_INFO_REPORT = 45,
    CREDIT_MANAGEMENT_SESSION_FAILURE = 46,
    DEFAULT_QOS_CHANGE = 47,
    CHANGE_OF_UE_PRESENCE_IN_PRESENCE_REPORTING_AREA_REPORT = 48
};

// Flow Description structure
struct FlowDescription {
    std::string description;    // IPFilterRule format (RFC 3588)
    enum class Direction { 
        UNSPECIFIED = 0,
        DOWNLINK = 1,  // IN - to UE
        UPLINK = 2,    // OUT - from UE
        BIDIRECTIONAL = 3 
    } direction = Direction::UNSPECIFIED;
    
    nlohmann::json toJson() const;
};

// Charging Rule Definition
struct ChargingRule {
    std::string rule_name;
    std::optional rule_base_name;
    std::vector flows;
    
    // QoS parameters
    std::optional qci;
    std::optional max_bandwidth_ul;      // bits/sec
    std::optional max_bandwidth_dl;      // bits/sec
    std::optional guaranteed_bandwidth_ul; // bits/sec
    std::optional guaranteed_bandwidth_dl; // bits/sec
    
    // Allocation Retention Priority
    std::optional priority_level;         // 1-15 (1=highest)
    std::optional pre_emption_capability;    // can preempt others
    std::optional pre_emption_vulnerability; // can be preempted
    
    // Rating and charging
    std::optional rating_group;
    std::optional service_identifier;
    
    // Rule precedence
    std::optional precedence;
    
    // Metering method
    enum class MeteringMethod {
        DURATION = 0,
        VOLUME = 1,
        DURATION_VOLUME = 2
    };
    std::optional metering_method;
    
    // Online/offline charging
    std::optional online;
    std::optional offline;
    
    nlohmann::json toJson() const;
};

// QoS Information grouped AVP
struct QoSInformation {
    std::optional qci;
    std::optional max_bandwidth_ul;
    std::optional max_bandwidth_dl;
    std::optional guaranteed_bandwidth_ul;
    std::optional guaranteed_bandwidth_dl;
    std::optional apn_aggregate_max_bandwidth_ul;
    std::optional apn_aggregate_max_bandwidth_dl;
    
    // ARP
    std::optional priority_level;
    std::optional pre_emption_capability;
    std::optional pre_emption_vulnerability;
    
    nlohmann::json toJson() const;
};

// Gx CCR Message (PCEF → PCRF)
struct GxCCR {
    CcRequestType request_type;
    uint32_t request_number;
    std::string session_id;
    std::string origin_host;
    std::string origin_realm;
    std::string destination_realm;
    
    // Subscription ID (IMSI/MSISDN)
    std::optional imsi;
    std::optional msisdn;
    
    // Network information
    std::optional framed_ip_address;
    std::optional framed_ipv6_prefix;
    std::optional called_station_id;  // APN
    std::optional access_network_charging_identifier;
    
    // 3GPP user location
    std::optional tgpp_user_location_info;  // hex encoded
    std::optional rai;
    std::optional rat_type;
    
    // Bearer
    std::optional bearer_identifier;
    std::optional bearer_operation;  // 0=establish, 1=modify, 2=release
    
    // Default QoS
    std::optional default_qos;
    
    // Event triggers that occurred
    std::vector event_triggers;
    
    // Usage reports
    std::vector<std::pair> usage_reports; // monitoring_key → bytes
    
    nlohmann::json toJson() const;
};

// Gx CCA Message (PCRF → PCEF)
struct GxCCA {
    uint32_t result_code;
    std::optional experimental_result_code;
    std::string session_id;
    CcRequestType request_type;
    uint32_t request_number;
    std::string origin_host;
    std::string origin_realm;
    
    // Rules to install
    std::vector rules_to_install;
    
    // Rule names to remove
    std::vector rules_to_remove;
    
    // Default QoS for the session
    std::optional default_qos;
    
    // Event triggers to subscribe to
    std::vector event_triggers;
    
    // Revalidation time (seconds)
    std::optional revalidation_time;
    
    nlohmann::json toJson() const;
};

// Gx RAR Message (PCRF → PCEF) - Push from PCRF
struct GxRAR {
    std::string session_id;
    std::string origin_host;
    std::string origin_realm;
    std::string destination_host;
    std::string destination_realm;
    uint32_t auth_application_id = GX_APPLICATION_ID;
    
    // Re-Auth-Request-Type
    enum class ReAuthRequestType : uint32_t {
        AUTHORIZE_ONLY = 0,
        AUTHORIZE_AUTHENTICATE = 1
    };
    ReAuthRequestType re_auth_request_type = ReAuthRequestType::AUTHORIZE_ONLY;
    
    // Rules to install
    std::vector rules_to_install;
    
    // Rules to remove
    std::vector rules_to_remove;
    
    // QoS update
    std::optional default_qos;
    
    // Event trigger changes
    std::vector event_triggers_to_add;
    std::vector event_triggers_to_remove;
    
    // Session release cause
    std::optional session_release_cause;
    
    nlohmann::json toJson() const;
};

// Gx RAA Message (PCEF → PCRF)
struct GxRAA {
    std::string session_id;
    uint32_t result_code;
    std::optional experimental_result_code;
    std::string origin_host;
    std::string origin_realm;
    
    // Rule installation/removal reports
    struct RuleReport {
        std::string rule_name;
        enum class Status { ACTIVE = 0, INACTIVE = 1, REMOVED = 2 } status;
        std::optional rule_failure_code;
    };
    std::vector rule_reports;
    
    nlohmann::json toJson() const;
};

// Main Gx Parser Class
class DiameterGxParser {
public:
    static GxCCR parseCCR(const DiameterMessage& msg);
    static GxCCA parseCCA(const DiameterMessage& msg);
    static GxRAR parseRAR(const DiameterMessage& msg);
    static GxRAA parseRAA(const DiameterMessage& msg);
    
    static bool isGx(const DiameterMessage& msg) {
        return msg.header.application_id == GX_APPLICATION_ID;
    }
    
    static bool isCCR(const DiameterMessage& msg) {
        return msg.header.command_code == 272 && msg.header.flags.request;
    }
    
    static bool isCCA(const DiameterMessage& msg) {
        return msg.header.command_code == 272 && !msg.header.flags.request;
    }
    
    static bool isRAR(const DiameterMessage& msg) {
        return msg.header.command_code == 258 && msg.header.flags.request;
    }
    
    static bool isRAA(const DiameterMessage& msg) {
        return msg.header.command_code == 258 && !msg.header.flags.request;
    }
    
    static ChargingRule parseChargingRuleDefinition(const DiameterAVP& avp);
    static QoSInformation parseQoSInformation(const DiameterAVP& avp);
    static FlowDescription parseFlowDescription(const std::string& filter_rule);

private:
    static std::string parseSubscriptionId(const std::vector& avps, uint32_t type);
    static std::vector parseEventTriggers(const std::vector& avps);
    static std::string ipv4ToString(uint32_t ip);
};

}  // namespace diameter
}  // namespace callflow
```

**File Structure:**
include/protocol_parsers/diameter/
diameter_gx.h
gx_types.h
src/protocol_parsers/diameter/
diameter_gx_parser.cpp
gx_charging_rule_parser.cpp
tests/unit/
test_diameter_gx.cpp
test_gx_charging_rules.cpp
tests/pcaps/
gx_ccr_initial.pcap
gx_cca_with_rules.pcap
gx_rar_volte_bearer.pcap

**Testing Requirements:**

1. Unit test: Parse CCR-Initial with IMSI/APN
2. Unit test: Parse CCA with charging rules
3. Unit test: Parse RAR for VoLTE bearer installation
4. Unit test: Parse RAA with rule reports
5. Unit test: Parse Charging-Rule-Definition grouped AVP
6. Unit test: Parse QoS-Information grouped AVP
7. Unit test: Extract IMSI from Subscription-Id
8. Unit test: Parse Flow-Description IPFilterRule
9. Integration test: Gx session for data (CCR-I/CCA-I/CCR-T/CCA-T)
10. Integration test: Gx RAR/RAA for VoLTE dedicated bearer

**Acceptance Criteria:**
- ✅ Parse all Gx message types (CCR/CCA/RAR/RAA)
- ✅ Extract charging rules with full QoS parameters
- ✅ Parse all event trigger types
- ✅ Extract subscription identifiers (IMSI/MSISDN)
- ✅ Support grouped AVPs (Charging-Rule-Definition, QoS-Information)
- ✅ Handle missing optional AVPs gracefully
- ✅ Unit test coverage > 90%

Please implement with comprehensive error handling for malformed AVPs and detailed logging.

PROMPT 11.2: DIAMETER Rx Interface Parser
markdown# DIAMETER Rx Interface Parser
## nDPI Callflow Visualizer - IMS QoS Authorization

**Context:**
I'm enhancing the nDPI Callflow Visualizer. Rx is the interface between the Application Function (AF, typically P-CSCF for VoLTE) and the PCRF. It's used for:
- VoLTE call setup: Requesting QoS for voice media (QCI-1)
- IMS emergency calls: Priority handling
- Video calling: Requesting GBR bearers for video
- SDP-to-QoS mapping: Translating SDP media descriptions to bearer requirements

**3GPP Reference:** TS 29.214 (Policy and Charging Control over Rx reference point)

**Requirements:**

1. **Rx Message Types and Application ID**
```cpp
// include/protocol_parsers/diameter/diameter_rx.h
#pragma once

#include "protocol_parsers/diameter_parser.h"

namespace callflow {
namespace diameter {

// Rx Application ID (3GPP)
static constexpr uint32_t RX_APPLICATION_ID = 16777236;

// Rx Command Codes
enum class RxCommandCode : uint32_t {
    AA_REQUEST = 265,   // AAR - AA Request (AF → PCRF)
    AA_ANSWER = 265,    // AAA - AA Answer (PCRF → AF)
    RE_AUTH_REQUEST = 258,  // RAR - Re-Auth Request (PCRF → AF)
    RE_AUTH_ANSWER = 258,   // RAA - Re-Auth Answer (AF → PCRF)
    SESSION_TERMINATION_REQUEST = 275,  // STR
    SESSION_TERMINATION_ANSWER = 275,   // STA
    ABORT_SESSION_REQUEST = 274,  // ASR (PCRF → AF)
    ABORT_SESSION_ANSWER = 274    // ASA (AF → PCRF)
};

// Rx-Request-Type values (AVP 1027)
enum class RxRequestType : uint32_t {
    INITIAL_REQUEST = 0,
    UPDATE_REQUEST = 1
};

// Rx AVP Codes (3GPP Vendor ID = 10415)
enum class RxAVPCode : uint32_t {
    // Media component description
    MEDIA_COMPONENT_DESCRIPTION = 517,
    MEDIA_COMPONENT_NUMBER = 518,
    MEDIA_TYPE = 520,
    MAX_REQUESTED_BANDWIDTH_UL = 516,
    MAX_REQUESTED_BANDWIDTH_DL = 515,
    MIN_REQUESTED_BANDWIDTH_UL = 534,
    MIN_REQUESTED_BANDWIDTH_DL = 533,
    FLOW_STATUS = 511,
    RESERVATION_PRIORITY = 458,
    
    // Media sub-component
    MEDIA_SUB_COMPONENT = 519,
    FLOW_NUMBER = 509,
    FLOW_DESCRIPTION = 507,
    FLOW_USAGE = 512,
    
    // RTP/RTCP
    RR_BANDWIDTH = 521,
    RS_BANDWIDTH = 522,
    
    // Codec data
    CODEC_DATA = 524,
    
    // Session linking
    AF_APPLICATION_IDENTIFIER = 504,
    AF_CHARGING_IDENTIFIER = 505,  // ICID
    
    // Specific actions
    SPECIFIC_ACTION = 513,
    
    // Service info
    SERVICE_INFO_STATUS = 527,
    SIP_FORKING_INDICATION = 523,
    
    // Rx-Request-Type
    RX_REQUEST_TYPE = 1027,
    
    // Sponsoring
    SPONSOR_IDENTITY = 531,
    APPLICATION_SERVICE_PROVIDER_IDENTITY = 532,
    
    // Emergency
    MPS_IDENTIFIER = 528,
    PRIORITY_SHARING_INDICATOR = 550,
    
    // Access network info
    IP_DOMAIN_ID = 537,
    ACCESS_NETWORK_CHARGING_IDENTIFIER_VALUE = 503,
    
    // Results
    ACCEPTABLE_SERVICE_INFO = 526
};

// Media Type values (AVP 520)
enum class MediaType : uint32_t {
    AUDIO = 0,
    VIDEO = 1,
    DATA = 2,
    APPLICATION = 3,
    CONTROL = 4,
    TEXT = 5,
    MESSAGE = 6,
    OTHER = 0xFFFFFFFF
};

// Flow Status values (AVP 511)
enum class FlowStatus : uint32_t {
    ENABLED_UPLINK = 0,
    ENABLED_DOWNLINK = 1,
    ENABLED = 2,
    DISABLED = 3,
    REMOVED = 4
};

// Specific Action values (AVP 513)
enum class SpecificAction : uint32_t {
    CHARGING_CORRELATION_EXCHANGE = 1,
    INDICATION_OF_LOSS_OF_BEARER = 2,
    INDICATION_OF_RECOVERY_OF_BEARER = 3,
    INDICATION_OF_RELEASE_OF_BEARER = 4,
    IP_CAN_CHANGE = 6,
    INDICATION_OF_OUT_OF_CREDIT = 7,
    INDICATION_OF_SUCCESSFUL_RESOURCES_ALLOCATION = 8,
    INDICATION_OF_FAILED_RESOURCES_ALLOCATION = 9,
    INDICATION_OF_LIMITED_PCC_DEPLOYMENT = 10,
    ACCESS_NETWORK_INFO_REPORT = 12,
    INDICATION_OF_RECOVERY_FROM_LIMITED_PCC_DEPLOYMENT = 13
};

// Flow Usage values (AVP 512)
enum class FlowUsage : uint32_t {
    NO_INFORMATION = 0,
    RTCP = 1,
    AF_SIGNALLING = 2
};

// Media Sub-Component structure
struct MediaSubComponent {
    uint32_t flow_number;
    std::vector flow_descriptions;
    std::optional flow_usage;
    std::optional flow_status;
    std::optional max_requested_bandwidth_ul;
    std::optional max_requested_bandwidth_dl;
    
    nlohmann::json toJson() const;
};

// Media Component Description
struct MediaComponentDescription {
    uint32_t media_component_number;
    std::optional media_type;
    std::optional max_requested_bandwidth_ul;
    std::optional max_requested_bandwidth_dl;
    std::optional min_requested_bandwidth_ul;
    std::optional min_requested_bandwidth_dl;
    std::optional flow_status;
    std::optional reservation_priority;  // 0=DEFAULT, 1-15 for emergency
    std::optional rr_bandwidth;  // RTCP RR bandwidth
    std::optional rs_bandwidth;  // RTCP RS bandwidth
    
    // Codec information (from SDP)
    std::vector codec_data;
    
    // Sub-components (individual flows)
    std::vector sub_components;
    
    // For AF-generated rules
    std::optional af_application_identifier;
    
    nlohmann::json toJson() const;
};

// Rx AAR Message (AF → PCRF)
struct RxAAR {
    std::string session_id;
    std::string origin_host;
    std::string origin_realm;
    std::string destination_realm;
    uint32_t auth_application_id = RX_APPLICATION_ID;
    
    // Request type
    RxRequestType request_type = RxRequestType::INITIAL_REQUEST;
    
    // Subscription
    std::optional subscription_id;  // SIP URI or TEL URI
    std::optional framed_ip_address;
    std::optional framed_ipv6_prefix;
    
    // IMS Charging Identifier - links to SIP P-Charging-Vector
    std::optional af_charging_identifier;  // ICID
    
    // AF application
    std::optional af_application_identifier;
    
    // Media components (from SDP)
    std::vector media_components;
    
    // Specific actions to subscribe to
    std::vector specific_actions;
    
    // Service URN (for emergency calls)
    std::optional service_urn;
    
    // Sponsoring (for zero-rating)
    std::optional sponsor_identity;
    
    // SIP forking (for parallel forking scenarios)
    std::optional sip_forking_indication;
    
    nlohmann::json toJson() const;
};

// Rx AAA Message (PCRF → AF)
struct RxAAA {
    std::string session_id;
    uint32_t result_code;
    std::optional experimental_result_code;
    std::string origin_host;
    std::string origin_realm;
    uint32_t auth_application_id = RX_APPLICATION_ID;
    
    // Granted media components (may differ from requested)
    std::vector acceptable_service_info;
    
    // Access network charging identifier (for correlation with Gx)
    std::optional access_network_charging_identifier;
    
    // IP-CAN type
    std::optional ip_can_type;
    std::optional rat_type;
    
    nlohmann::json toJson() const;
};

// Rx RAR Message (PCRF → AF) - Notify AF of bearer changes
struct RxRAR {
    std::string session_id;
    std::string origin_host;
    std::string origin_realm;
    std::string destination_host;
    std::string destination_realm;
    uint32_t auth_application_id = RX_APPLICATION_ID;
    
    // Actions that triggered this RAR
    std::vector specific_actions;
    
    // Abort cause (if session should be terminated)
    std::optional abort_cause;
    
    // Access network info
    std::optional ip_can_type;
    std::optional rat_type;
    std::optional tgpp_user_location_info;
    
    nlohmann::json toJson() const;
};

// Rx RAA Message (AF → PCRF)
struct RxRAA {
    std::string session_id;
    uint32_t result_code;
    std::optional experimental_result_code;
    std::string origin_host;
    std::string origin_realm;
    
    // Updated media components (if AF modified the session)
    std::vector media_components;
    
    nlohmann::json toJson() const;
};

// Rx STR Message (AF → PCRF) - Session Termination
struct RxSTR {
    std::string session_id;
    std::string origin_host;
    std::string origin_realm;
    std::string destination_realm;
    uint32_t auth_application_id = RX_APPLICATION_ID;
    
    // Termination cause
    uint32_t termination_cause;
    
    nlohmann::json toJson() const;
};

// Rx STA Message (PCRF → AF)
struct RxSTA {
    std::string session_id;
    uint32_t result_code;
    std::optional experimental_result_code;
    std::string origin_host;
    std::string origin_realm;
    
    nlohmann::json toJson() const;
};

// Rx ASR Message (PCRF → AF) - Abort Session
struct RxASR {
    std::string session_id;
    std::string origin_host;
    std::string origin_realm;
    std::string destination_host;
    std::string destination_realm;
    uint32_t auth_application_id = RX_APPLICATION_ID;
    
    // Abort cause
    uint32_t abort_cause;
    
    nlohmann::json toJson() const;
};

// Rx ASA Message (AF → PCRF)
struct RxASA {
    std::string session_id;
    uint32_t result_code;
    std::string origin_host;
    std::string origin_realm;
    
    nlohmann::json toJson() const;
};

// Main Rx Parser Class
class DiameterRxParser {
public:
    static RxAAR parseAAR(const DiameterMessage& msg);
    static RxAAA parseAAA(const DiameterMessage& msg);
    static RxRAR parseRAR(const DiameterMessage& msg);
    static RxRAA parseRAA(const DiameterMessage& msg);
    static RxSTR parseSTR(const DiameterMessage& msg);
    static RxSTA parseSTA(const DiameterMessage& msg);
    static RxASR parseASR(const DiameterMessage& msg);
    static RxASA parseASA(const DiameterMessage& msg);
    
    static bool isRx(const DiameterMessage& msg) {
        return msg.header.application_id == RX_APPLICATION_ID;
    }
    
    static bool isAAR(const DiameterMessage& msg) {
        return msg.header.command_code == 265 && msg.header.flags.request;
    }
    
    static bool isAAA(const DiameterMessage& msg) {
        return msg.header.command_code == 265 && !msg.header.flags.request;
    }
    
    static bool isRAR(const DiameterMessage& msg) {
        return msg.header.command_code == 258 && msg.header.flags.request;
    }
    
    static bool isRAA(const DiameterMessage& msg) {
        return msg.header.command_code == 258 && !msg.header.flags.request;
    }
    
    static bool isSTR(const DiameterMessage& msg) {
        return msg.header.command_code == 275 && msg.header.flags.request;
    }
    
    static bool isSTA(const DiameterMessage& msg) {
        return msg.header.command_code == 275 && !msg.header.flags.request;
    }
    
    static MediaComponentDescription parseMediaComponentDescription(const DiameterAVP& avp);
    static MediaSubComponent parseMediaSubComponent(const DiameterAVP& avp);
    
    // Helper to extract ICID for VoLTE correlation
    static std::optional extractIcid(const RxAAR& aar);

private:
    static std::vector parseSpecificActions(const std::vector& avps);
    static std::string parseCodecData(const DiameterAVP& avp);
};

}  // namespace diameter
}  // namespace callflow
```

**VoLTE Call Flow Integration:**
UE          P-CSCF        S-CSCF        PCRF         PGW
|            |             |            |            |
|--INVITE--->|             |            |            |
|            |--INVITE---->|            |            |
|            |             |            |            |
|            |--------AAR (ICID, QCI-1, bandwidth)-->|
|            |             |            |--CCR-U (RAR trigger)-->
|            |             |            |<--CCA-U (install rule)--
|            |<-------AAA (success)--------------------|
|            |             |            |            |
|<--100 Trying|            |            |            |
|            |             |            |--RAR (rule)-->
|            |             |            |<--RAA-------|
|            |             |            |            |
|<--180 Ring-|             |            |            |
|            |             |            |            |
|<--200 OK---|             |            |            |
|---ACK----->|             |            |            |

**File Structure:**
include/protocol_parsers/diameter/
diameter_rx.h
rx_types.h
src/protocol_parsers/diameter/
diameter_rx_parser.cpp
rx_media_component_parser.cpp
tests/unit/
test_diameter_rx.cpp
test_rx_media_components.cpp
tests/pcaps/
rx_aar_volte_audio.pcap
rx_aaa_success.pcap
rx_aar_video_call.pcap
rx_rar_bearer_loss.pcap

**Testing Requirements:**

1. Unit test: Parse AAR for VoLTE audio call
2. Unit test: Parse AAR for video call with multiple media components
3. Unit test: Parse AAA success response
4. Unit test: Parse AAA with experimental result code
5. Unit test: Parse RAR for bearer loss notification
6. Unit test: Parse RAA response
7. Unit test: Parse STR/STA for session termination
8. Unit test: Extract Media-Component-Description
9. Unit test: Extract ICID from AF-Charging-Identifier
10. Integration test: Full Rx session for VoLTE (AAR/AAA/STR/STA)
11. Integration test: Bearer loss notification (RAR/RAA)

**Acceptance Criteria:**
- ✅ Parse all Rx message types (AAR/AAA/RAR/RAA/STR/STA/ASR/ASA)
- ✅ Extract media component descriptions with all sub-components
- ✅ Parse codec data for media type identification
- ✅ Extract ICID for VoLTE call correlation
- ✅ Support specific action subscriptions
- ✅ Handle emergency call priority
- ✅ Unit test coverage > 90%

Please implement with support for correlating Rx sessions to SIP calls via ICID.

PROMPT 11.3: DIAMETER Gy Interface Parser
markdown# DIAMETER Gy Interface Parser
## nDPI Callflow Visualizer - Online Charging System

**Context:**
I'm enhancing the nDPI Callflow Visualizer. Gy is the interface between the Charging Trigger Function (CTF, typically the PGW/GGSN) and the Online Charging System (OCS). It's used for:
- Prepaid charging: Credit control for data and voice
- Real-time balance management: Quota grants and usage reporting
- Service-based charging: Different rates per service (streaming, browsing, etc.)
- Roaming charging: Home-routed vs. visited PLMN charging

**3GPP Reference:** TS 32.299 (Diameter charging applications)

**Requirements:**

1. **Gy Message Types and Application ID**
```cpp
// include/protocol_parsers/diameter/diameter_gy.h
#pragma once

#include "protocol_parsers/diameter_parser.h"

namespace callflow {
namespace diameter {

// Gy Application ID (3GPP Charging)
static constexpr uint32_t GY_APPLICATION_ID = 4;  // Diameter Credit Control

// Gy Command Codes (same as Ro for online charging)
enum class GyCommandCode : uint32_t {
    CC_REQUEST = 272,   // CCR
    CC_ANSWER = 272     // CCA
};

// CC-Request-Type values
enum class GyCcRequestType : uint32_t {
    INITIAL_REQUEST = 1,
    UPDATE_REQUEST = 2,
    TERMINATION_REQUEST = 3,
    EVENT_REQUEST = 4
};

// Gy AVP Codes (mix of RFC 4006 and 3GPP TS 32.299)
enum class GyAVPCode : uint32_t {
    // Credit Control (RFC 4006)
    CC_REQUEST_TYPE = 416,
    CC_REQUEST_NUMBER = 415,
    CC_SESSION_FAILOVER = 418,
    
    // Requested/Granted/Used Service Unit
    REQUESTED_SERVICE_UNIT = 437,
    GRANTED_SERVICE_UNIT = 431,
    USED_SERVICE_UNIT = 446,
    CC_TIME = 420,
    CC_MONEY = 413,
    CC_TOTAL_OCTETS = 421,
    CC_INPUT_OCTETS = 412,
    CC_OUTPUT_OCTETS = 414,
    CC_SERVICE_SPECIFIC_UNITS = 417,
    
    // Multiple Services
    MULTIPLE_SERVICES_INDICATOR = 455,
    MULTIPLE_SERVICES_CREDIT_CONTROL = 456,
    
    // Rating
    RATING_GROUP = 432,
    SERVICE_IDENTIFIER = 439,
    
    // Subscription
    SUBSCRIPTION_ID = 443,
    SUBSCRIPTION_ID_TYPE = 450,
    SUBSCRIPTION_ID_DATA = 444,
    
    // Results
    RESULT_CODE = 268,
    FINAL_UNIT_INDICATION = 430,
    FINAL_UNIT_ACTION = 449,
    
    // Validity
    VALIDITY_TIME = 448,
    
    // Quota
    QUOTA_HOLDING_TIME = 871,
    QUOTA_CONSUMPTION_TIME = 881,
    
    // 3GPP Charging (Vendor ID 10415)
    TGPP_CHARGING_ID = 2,
    TGPP_PDP_TYPE = 3,
    TGPP_GPRS_NEGOTIATED_QOS_PROFILE = 5,
    TGPP_IMSI = 1,
    TGPP_GGSN_MCC_MNC = 9,
    TGPP_NSAPI = 10,
    TGPP_SGSN_MCC_MNC = 18,
    TGPP_MS_TIMEZONE = 23,
    TGPP_USER_LOCATION_INFO = 22,
    TGPP_RAT_TYPE = 21,
    
    // Service Information
    SERVICE_INFORMATION = 873,
    PS_INFORMATION = 874,
    IMS_INFORMATION = 876,
    
    // PS Information contents
    TGPP_CHARGING_CHARACTERISTICS = 13,
    CALLED_STATION_ID = 30,  // APN
    TGPP_SELECTION_MODE = 12,
    START_TIME = 2041,
    STOP_TIME = 2042,
    
    // Low balance
    LOW_BALANCE_INDICATION = 2020,
    REMAINING_BALANCE = 2021,
    
    // Service context
    SERVICE_CONTEXT_ID = 461,
    
    // Trigger
    TRIGGER_TYPE = 870,
    TRIGGER = 1264,
    
    // QoS
    QOS_INFORMATION = 1016,
    APN_AGGREGATE_MAX_BITRATE_UL = 1041,
    APN_AGGREGATE_MAX_BITRATE_DL = 1040
};

// Subscription-Id-Type values
enum class SubscriptionIdType : uint32_t {
    END_USER_E164 = 0,
    END_USER_IMSI = 1,
    END_USER_SIP_URI = 2,
    END_USER_NAI = 3,
    END_USER_PRIVATE = 4
};

// Final-Unit-Action values
enum class FinalUnitAction : uint32_t {
    TERMINATE = 0,
    REDIRECT = 1,
    RESTRICT_ACCESS = 2
};

// Trigger-Type values
enum class TriggerType : uint32_t {
    CHANGE_IN_SGSN_IP_ADDRESS = 1,
    CHANGE_IN_QOS = 2,
    CHANGE_IN_LOCATION = 3,
    CHANGE_IN_RAT = 4,
    CHANGE_IN_UE_TIMEZONE = 5,
    CHANGEINQOS_TRAFFIC_CLASS = 10,
    CHANGEINQOS_RELIABILITY_CLASS = 11,
    CHANGEINQOS_DELAY_CLASS = 12,
    CHANGEINQOS_PEAK_THROUGHPUT = 13,
    CHANGEINQOS_PRECEDENCE_CLASS = 14,
    CHANGEINQOS_MEAN_THROUGHPUT = 15,
    CHANGEINQOS_MAXIMUM_BIT_RATE_FOR_UPLINK = 16,
    CHANGEINQOS_MAXIMUM_BIT_RATE_FOR_DOWNLINK = 17,
    CHANGEINQOS_RESIDUAL_BER = 18,
    CHANGEINQOS_SDU_ERROR_RATIO = 19,
    CHANGEINQOS_TRANSFER_DELAY = 20,
    CHANGEINQOS_TRAFFIC_HANDLING_PRIORITY = 21,
    CHANGEINQOS_GUARANTEED_BIT_RATE_FOR_UPLINK = 22,
    CHANGEINQOS_GUARANTEED_BIT_RATE_FOR_DOWNLINK = 23
};

// Service Unit (granted/used)
struct ServiceUnit {
    std::optional time_seconds;          // CC-Time
    std::optional total_octets;          // CC-Total-Octets
    std::optional input_octets;          // CC-Input-Octets (uplink)
    std::optional output_octets;         // CC-Output-Octets (downlink)
    std::optional service_specific_units;
    
    nlohmann::json toJson() const;
};

// Multiple Services Credit Control
struct MultipleServicesCreditControl {
    std::optional rating_group;
    std::optional service_identifier;
    
    std::optional requested_service_unit;
    std::optional granted_service_unit;
    std::optional used_service_unit;
    
    // Result for this rating group
    std::optional result_code;
    
    // Quota management
    std::optional validity_time;
    std::optional quota_holding_time;
    
    // Final unit handling
    std::optional final_unit_action;
    
    // Triggers for next update
    std::vector trigger_types;
    
    nlohmann::json toJson() const;
};

// PS-Information (for data sessions)
struct PSInformation {
    std::optional tgpp_charging_id;
    std::optional called_station_id;  // APN
    std::optional tgpp_pdp_type;
    std::optional sgsn_address;
    std::optional ggsn_address;
    std::optional tgpp_imsi_mcc_mnc;
    std::optional tgpp_ggsn_mcc_mnc;
    std::optional tgpp_sgsn_mcc_mnc;
    std::optional tgpp_user_location_info;  // hex
    std::optional tgpp_rat_type;
    std::optional tgpp_ms_timezone;
    
    // Timestamps
    std::optional start_time;
    std::optional stop_time;
    
    // QoS
    std::optional apn_aggregate_max_bitrate_ul;
    std::optional apn_aggregate_max_bitrate_dl;
    
    nlohmann::json toJson() const;
};

// IMS-Information (for VoLTE sessions)
struct IMSInformation {
    std::optional node_functionality;
    std::optional role_of_node;
    std::optional calling_party_address;
    std::optional called_party_address;
    std::optional icid;
    std::optional ioi;  // Inter-Operator Identifier
    
    // SIP methods for event-based charging
    std::optional sip_request_method;
    std::optional sip_response_timestamp;
    
    nlohmann::json toJson() const;
};

// Service Information
struct ServiceInformation {
    std::optional ps_information;
    std::optional ims_information;
    
    nlohmann::json toJson() const;
};

// Gy CCR Message (CTF → OCS)
struct GyCCR {
    GyCcRequestType request_type;
    uint32_t request_number;
    std::string session_id;
    std::string origin_host;
    std::string origin_realm;
    std::string destination_realm;
    uint32_t auth_application_id = GY_APPLICATION_ID;
    
    // Service context
    std::string service_context_id;
    
    // Subscription
    std::optional imsi;
    std::optional msisdn;
    
    // Multiple Services
    bool multiple_services_indicator = true;
    std::vector multiple_services_cc;
    
    // Service information
    std::optional service_information;
    
    // Event timestamp
    std::optional event_timestamp;
    
    // User equipment info
    std::optional user_equipment_info;  // IMEISV
    
    nlohmann::json toJson() const;
};

// Gy CCA Message (OCS → CTF)
struct GyCCA {
    uint32_t result_code;
    std::optional experimental_result_code;
    std::string session_id;
    GyCcRequestType request_type;
    uint32_t request_number;
    std::string origin_host;
    std::string origin_realm;
    uint32_t auth_application_id = GY_APPLICATION_ID;
    
    // Credit control answers for each rating group
    std::vector multiple_services_cc;
    
    // Session failover
    std::optional cc_session_failover;
    
    // Low balance warning
    std::optional low_balance_indication;
    std::optional remaining_balance;
    std::optional currency_code;
    
    // Validity
    std::optional validity_time;
    
    nlohmann::json toJson() const;
};

// Main Gy Parser Class
class DiameterGyParser {
public:
    static GyCCR parseCCR(const DiameterMessage& msg);
    static GyCCA parseCCA(const DiameterMessage& msg);
    
    static bool isGy(const DiameterMessage& msg) {
        // Gy uses application ID 4 (Credit Control)
        // Distinguish from other CC apps by service-context-id or AVPs
        return msg.header.application_id == GY_APPLICATION_ID;
    }
    
    static bool isCCR(const DiameterMessage& msg) {
        return msg.header.command_code == 272 && msg.header.flags.request;
    }
    
    static bool isCCA(const DiameterMessage& msg) {
        return msg.header.command_code == 272 && !msg.header.flags.request;
    }
    
    static ServiceUnit parseServiceUnit(const DiameterAVP& avp);
    static MultipleServicesCreditControl parseMSCC(const DiameterAVP& avp);
    static ServiceInformation parseServiceInformation(const DiameterAVP& avp);
    static PSInformation parsePSInformation(const DiameterAVP& avp);
    static IMSInformation parseIMSInformation(const DiameterAVP& avp);

private:
    static std::string parseSubscriptionId(const std::vector& avps, SubscriptionIdType type);
    static std::vector parseTriggers(const std::vector& avps);
};

}  // namespace diameter
}  // namespace callflow
```

**Data Session Charging Flow:**
UE          PGW/GGSN(CTF)        OCS
|              |                 |
|--Attach----->|                 |
|              |                 |
|              |---CCR-I (rating_group, RSU)-->|
|              |<--CCA-I (GSU: 100MB, validity: 1h)--|
|              |                 |
|<--IP assigned|                 |
|              |                 |
|--Data------->|                 |
|<--Data-------|                 |
|              |                 |
|              |---CCR-U (USU: 50MB, RSU)-->|
|              |<--CCA-U (GSU: 100MB)--|
|              |                 |
|--Detach----->|                 |
|              |---CCR-T (USU: 30MB)-->|
|              |<--CCA-T (final)--|

**File Structure:**
include/protocol_parsers/diameter/
diameter_gy.h
gy_types.h
src/protocol_parsers/diameter/
diameter_gy_parser.cpp
gy_service_unit_parser.cpp
gy_service_info_parser.cpp
tests/unit/
test_diameter_gy.cpp
test_gy_service_units.cpp
test_gy_mscc.cpp
tests/pcaps/
gy_ccr_initial_data.pcap
gy_cca_with_quota.pcap
gy_ccr_update_usage.pcap
gy_cca_low_balance.pcap
gy_ccr_termination.pcap

**Testing Requirements:**

1. Unit test: Parse CCR-Initial for data session
2. Unit test: Parse CCA with granted quota
3. Unit test: Parse CCR-Update with usage report
4. Unit test: Parse CCA-Update with renewed quota
5. Unit test: Parse CCR-Termination
6. Unit test: Parse CCA-Termination (final)
7. Unit test: Parse Multiple-Services-Credit-Control
8. Unit test: Extract Granted-Service-Unit
9. Unit test: Extract Used-Service-Unit
10. Unit test: Parse PS-Information
11. Unit test: Parse IMS-Information for VoLTE
12. Unit test: Low balance indication
13. Unit test: Final unit action handling
14. Integration test: Full data session (CCR-I/CCA-I/CCR-U/CCA-U/CCR-T/CCA-T)
15. Integration test: Quota exhaustion scenario

**Acceptance Criteria:**
- ✅ Parse all Gy message types (CCR/CCA with all request types)
- ✅ Extract granted/used service units (time, octets)
- ✅ Support multiple rating groups per session
- ✅ Extract PS-Information for data sessions
- ✅ Extract IMS-Information for VoLTE sessions
- ✅ Handle low balance and final unit actions
- ✅ Parse triggers for reporting
- ✅ Unit test coverage > 90%

Please implement with comprehensive usage tracking for correlation with session duration.

Summary: DIAMETER Policy Interface Integration
Cross-Interface Correlation
The three DIAMETER policy interfaces work together in VoLTE and data sessions:
                    ┌─────────────────────────────────────────┐
                    │                 PCRF                     │
                    │  (Policy and Charging Rules Function)   │
                    └─────────────────────────────────────────┘
                       ▲         │          │
                    Rx │         │ Gx       │ Gx
                 (QoS) │         │(Policy)  │(Policy)
                       │         ▼          ▼
┌────────────┐    ┌────────┐  ┌──────┐    ┌──────┐    ┌────────┐
│   P-CSCF   │◀──▶│   AF   │  │ PCEF │◀──▶│ PGW  │◀──▶│  OCS   │
│ (IMS Proxy)│    └────────┘  └──────┘    └──────┘    │ (Gy)   │
└────────────┘                              │         └────────┘
      ▲                                     │
      │ SIP                                 │ GTP
      ▼                                     ▼
┌────────────┐                        ┌────────────┐
│     UE     │◀──────────────────────▶│   eNodeB   │
└────────────┘                        └────────────┘
VoLTE Call Correlation Keys
InterfaceKey for CorrelationSIP ↔ RxICID (P-Charging-Vector → AF-Charging-Identifier)Rx ↔ GxFramed-IP-AddressGx ↔ GTPIMSI + Bearer IDGy ↔ GTP3GPP-Charging-Id
Implementation Order

Gx first - Foundation for policy control
Rx second - Depends on Gx understanding for RAR/RAA
Gy third - Builds on both for charging correlation

Integration Points in VolteCallCorrelator
cpp// In volte_call_correlator.cpp

void VolteCallCorrelator::processDiameterMessage(
    const SessionMessageRef& msg,
    const DiameterMessage& dia) {
    
    if (DiameterGxParser::isGx(dia)) {
        processGxMessage(msg, dia);
    } else if (DiameterRxParser::isRx(dia)) {
        processRxMessage(msg, dia);
    } else if (DiameterGyParser::isGy(dia)) {
        processGyMessage(msg, dia);
    }
}

void VolteCallCorrelator::processRxMessage(
    const SessionMessageRef& msg,
    const DiameterMessage& dia) {
    
    if (DiameterRxParser::isAAR(dia)) {
        auto aar = DiameterRxParser::parseAAR(dia);
        
        // Extract ICID for correlation with SIP
        if (auto icid = DiameterRxParser::extractIcid(aar)) {
            // Find VoLTE call by ICID
            if (auto call = findByIcid(*icid)) {
                // Link Rx session to call
                call->rx_leg.session_id = aar.session_id;
                call->rx_leg.aar_time = msg.timestamp;
                
                // Extract requested QoS
                for (const auto& mc : aar.media_components) {
                    if (mc.media_type == MediaType::AUDIO) {
                        call->rx_leg.requested_bandwidth_ul = mc.max_requested_bandwidth_ul;
                        call->rx_leg.requested_bandwidth_dl = mc.max_requested_bandwidth_dl;
                    }
                }
            }
        }
    }
}


---

# MILESTONE 12: Professional UI/UX Redesign

---

## PROMPT 12.1: UI Framework & Design System

```
# UI Framework & Design System
## nDPI Callflow Visualizer - Professional Telecom UI

**Context:**
I'm redesigning the nDPI Callflow Visualizer UI. Current state uses basic Bootstrap 5 with minimal customization. Need a professional, telecom-focused design suitable for NOC environments and engineering analysis.

**Design Requirements:**

1. **Visual Design Language**
   - Color Palette:
     - Primary: Deep blue (#1a365d)
     - Secondary: Cyan (#00bcd4)
     - Success: Green (#48bb78)
     - Warning: Amber (#ed8936)
     - Error: Red (#f56565)
   - Dark Mode Primary: Near-black (#0d1117)
   - Typography: Inter for UI, JetBrains Mono for code

2. **Create Design System CSS**

Create `ui/static/css/design-system.css`:

```css
:root {
  /* Colors */
  --color-primary: #1a365d;
  --color-primary-light: #2c5282;
  --color-secondary: #00bcd4;
  --color-success: #48bb78;
  --color-warning: #ed8936;
  --color-error: #f56565;
  
  /* Neutrals */
  --color-gray-900: #1a202c;
  --color-gray-800: #2d3748;
  --color-gray-700: #4a5568;
  --color-gray-600: #718096;
  --color-gray-500: #a0aec0;
  --color-gray-400: #cbd5e0;
  --color-gray-300: #e2e8f0;
  --color-gray-200: #edf2f7;
  --color-gray-100: #f7fafc;
  
  /* Spacing */
  --space-1: 4px;
  --space-2: 8px;
  --space-3: 12px;
  --space-4: 16px;
  --space-6: 24px;
  --space-8: 32px;
  
  /* Border radius */
  --radius-sm: 4px;
  --radius-md: 8px;
  --radius-lg: 12px;
  
  /* Typography */
  --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  --font-mono: 'JetBrains Mono', 'Fira Code', monospace;
  
  /* Protocol Colors */
  --protocol-sip: #3b82f6;
  --protocol-rtp: #10b981;
  --protocol-gtp: #f59e0b;
  --protocol-diameter: #8b5cf6;
  --protocol-http2: #ec4899;
  --protocol-s1ap: #06b6d4;
  --protocol-ngap: #14b8a6;
}

/* Dark theme */
[data-theme="dark"] {
  --bg-primary: #0d1117;
  --bg-secondary: #161b22;
  --bg-tertiary: #21262d;
  --text-primary: #f0f6fc;
  --text-secondary: #8b949e;
  --border-color: #30363d;
}

/* Light theme */
[data-theme="light"] {
  --bg-primary: #ffffff;
  --bg-secondary: #f6f8fa;
  --bg-tertiary: #f0f0f0;
  --text-primary: #1a202c;
  --text-secondary: #4a5568;
  --border-color: #e2e8f0;
}
```

3. **Layout Structure**

Create the main application layout with sidebar navigation, top navbar with search, and main content area.

4. **Key Pages to Implement**
   - Dashboard: Summary metrics, recent jobs
   - Jobs List: Sortable/filterable table
   - Session List: Protocol-filtered session table
   - Session Detail: Tabbed view (Timeline, Ladder, Events, Metrics)
   - VoLTE Calls: Dedicated call list with quality indicators
   - Upload: Drag-and-drop with progress

5. **Reusable Components**
   - `SessionCard`: Compact session summary
   - `ProtocolBadge`: Colored protocol indicator
   - `MetricCard`: KPI display with trend
   - `StatusBadge`: Job/session status
   - `DataTable`: Sortable, filterable table
   - `Pagination`: Page navigation
   - `Modal`: Generic modal dialog
   - `Toast`: Notification system

**File Structure:**
```
ui/static/
  css/
    design-system.css
    layout.css
    components.css
    pages/
      dashboard.css
      sessions.css
      volte.css
  js/
    components/
      session-card.js
      protocol-badge.js
      data-table.js
      modal.js
    pages/
      dashboard.js
      sessions.js
      volte.js
    app.js
    theme.js
  img/
    logo.svg
```

**Implementation Requirements:**

1. Implement design system CSS variables
2. Create base layout with sidebar and navbar
3. Implement dark/light theme toggle with localStorage
4. Create component library
5. Implement responsive breakpoints
6. Add keyboard navigation support
7. Ensure WCAG 2.1 AA accessibility

**Acceptance Criteria:**
- ✅ Professional, modern UI
- ✅ Consistent design system
- ✅ Smooth theme switching
- ✅ Responsive down to 768px
- ✅ Accessible
- ✅ Performance (<2s initial load)

Please implement with modular CSS and JavaScript.
```

---

# MILESTONE 13: Ladder Diagram & MSC Visualization

---

## PROMPT 13.1: Ladder Diagram Renderer

```
# Ladder Diagram Renderer
## nDPI Callflow Visualizer - MSC-Style Visualization

**Context:**
I'm enhancing the nDPI Callflow Visualizer. Ladder diagrams (Message Sequence Charts) are the standard way to visualize telecom call flows. Need a proper D3.js-based MSC renderer.

**Requirements:**

1. **Diagram Structure**

```
┌──────┐          ┌──────┐          ┌──────┐          ┌──────┐
│  UE  │          │P-CSCF│          │S-CSCF│          │  HSS │
└──┬───┘          └──┬───┘          └──┬───┘          └──┬───┘
   │                 │                 │                 │
   │─────INVITE─────▶│                 │                 │
   │                 │─────INVITE─────▶│                 │
   │                 │                 │──────UAR───────▶│
   │                 │                 │◀─────UAA────────│
```

2. **Data Model**

```javascript
const ladderData = {
  participants: [
    { id: 'ue', label: 'UE', ip: '10.0.0.1', type: 'endpoint' },
    { id: 'pcscf', label: 'P-CSCF', ip: '10.0.1.1', type: 'proxy' },
    { id: 'scscf', label: 'S-CSCF', ip: '10.0.1.2', type: 'proxy' },
    { id: 'hss', label: 'HSS', ip: '10.0.2.1', type: 'server' }
  ],
  messages: [
    {
      id: 'msg1',
      timestamp: '2024-01-15T10:30:00.123Z',
      from: 'ue',
      to: 'pcscf',
      protocol: 'SIP',
      type: 'INVITE',
      label: 'INVITE',
      details: { call_id: 'abc123' },
      duration_ms: 5
    }
  ],
  notes: [...],
  groups: [...]
};
```

3. **D3.js Renderer Implementation**

Create `ui/static/js/components/ladder-diagram.js`:

Implement a LadderDiagram class with:
- render(data) - Main render function
- renderParticipants() - Header boxes with labels
- renderLifelines() - Vertical dashed lines
- renderMessages() - Arrows with labels and protocol badges
- renderTimeline() - Left-side timestamps
- selectMessage(msg) - Highlight and emit event
- zoomIn(), zoomOut(), resetZoom() - Zoom controls
- exportSVG(), exportPNG() - Export functions

4. **CSS Styling**

Create `ui/static/css/ladder-diagram.css` with:
- Participant box styling
- Lifeline styling
- Message arrow and label styling
- Protocol badge colors
- Hover and selection states
- Dark mode adjustments

**Features:**
- Zoom and pan with D3.js
- Click on message to select and show details
- Tooltip on hover
- Export to SVG and PNG
- Protocol color coding
- Dark mode support

**Testing Requirements:**

1. Render diagram with 4 participants, 20 messages
2. Verify zoom/pan functionality
3. Test message selection
4. Export to SVG
5. Export to PNG
6. Responsive resize handling
7. Dark mode rendering

**Acceptance Criteria:**
- ✅ Correct MSC-style visualization
- ✅ Smooth zoom/pan
- ✅ Message selection and detail display
- ✅ SVG export maintains quality
- ✅ PNG export at 2x resolution
- ✅ Works in dark and light mode
- ✅ Performance: 100 messages renders in <500ms

Please implement with D3.js v7.
```

---



## Dependency Order

1. **M8** (TCP/SCTP) - Foundation, do first
2. **M9** (Correlation) - Depends on M8
3. **M10** (VoLTE) - Depends on M9
4. **M11** (DIAMETER Gx/Rx/Gy) - Can parallel with M10
5. **M12** (UI) - Can start after M10
6. **M13** (Ladder Diagram) - Depends on M12
7. **M14** (Search) - Depends on M9, M12
8. **M15** (Export) - Final polish