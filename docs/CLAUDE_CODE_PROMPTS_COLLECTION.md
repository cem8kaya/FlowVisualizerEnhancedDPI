# nDPI Callflow Visualizer - Claude Code Prompts Collection
## Ready-to-Use Prompts for Each Milestone

---

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

# Additional Notes

## How to Use These Prompts

1. **Start a Claude Code session**
2. **Copy the relevant prompt** (including the triple backticks)
3. **Add project context:**
   ```
   Repository: https://github.com/your-username/nDPI-Callflow-Visualizer
   Branch: main
   Milestones completed: M1-M7
   ```
4. **Paste the prompt and begin implementation**

## Dependency Order

1. **M8** (TCP/SCTP) - Foundation, do first
2. **M9** (Correlation) - Depends on M8
3. **M10** (VoLTE) - Depends on M9
4. **M11** (DIAMETER Gx/Rx/Gy) - Can parallel with M10
5. **M12** (UI) - Can start after M10
6. **M13** (Ladder Diagram) - Depends on M12
7. **M14** (Search) - Depends on M9, M12
8. **M15** (Export) - Final polish
