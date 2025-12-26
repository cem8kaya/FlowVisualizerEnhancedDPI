# SIP Parsing and Display Issues - Analysis and Fixes

## Issue Summary

Based on the screenshots and Docker logs provided, the following issues were identified in SIP parsing, correlation, and UI display:

### 1. **Timestamp Display Issue** (showing 1/20/1970, 7:56:26 PM)
**Symptom**: SIP-only sessions display with timestamps near Unix epoch (Jan 20, 1970)

**Root Cause**:
- `SipSession::getStartTime()` and `getEndTime()` return `double` values in **seconds** since epoch
- In `src/correlation/sip_session_manager.cpp:118-119`, these are exported directly
- In `src/event_extractor/json_exporter.cpp:421-422`, they're treated as **milliseconds**
- When timestamp is 0.0 or near-zero (uninitialized), it displays as 1970-01-20

**Files Affected**:
- `src/correlation/sip_session_manager.cpp`
- `src/event_extractor/json_exporter.cpp`

---

### 2. **Participants Showing "undefined:undefined"**
**Symptom**: Session Information shows `SERVER undefined:undefined` instead of IP:port

**Root Cause**:
- In `json_exporter.cpp:463-470`, participants are extracted from `caller_ip` and `callee_ip`
- These fields are empty because `SipSession::extractCallParties()` doesn't populate IP addresses properly
- The actual source/destination IPs from SIP messages aren't being used

**Files Affected**:
- `src/event_extractor/json_exporter.cpp`

---

### 3. **Direction Showing "? -> ?"**
**Symptom**: Event timeline shows "? -> ?" for direction instead of actual IPs

**Root Cause**:
- When converting SIP messages to events (lines 432-452), network information (src_ip, dst_ip, src_port, dst_port) isn't being extracted
- Events lack the `details` object with connection information

**Files Affected**:
- `src/event_extractor/json_exporter.cpp`

---

### 4. **Session Status Showing "UNKNOWN"**
**Symptom**: Session badge shows "UNKNOWN" instead of proper session type

**Root Cause**:
- SIP sessions aren't calling `finalize()` before export
- Without finalization, session type detection doesn't run
- Call party extraction and media info extraction also don't run

**Files Affected**:
- `src/correlation/sip_session_manager.cpp`

---

### 5. **Missing SIP Message Details**
**Symptom**: Events don't show detailed connection information

**Root Cause**:
- Events converted from SIP messages lack network details
- No `details` object in event JSON

**Files Affected**:
- `src/event_extractor/json_exporter.cpp`

---

## Applied Fixes

### Fix 1: Timestamp Conversion (src/correlation/sip_session_manager.cpp)

**Location**: Line 118-119

**Before**:
```cpp
session_json["start_time"] = sip_session->getStartTime();
session_json["end_time"] = sip_session->getEndTime();
```

**After**:
```cpp
// Convert timestamps from seconds to milliseconds
session_json["start_time"] = static_cast<uint64_t>(sip_session->getStartTime() * 1000);
session_json["end_time"] = static_cast<uint64_t>(sip_session->getEndTime() * 1000);
```

**Rationale**: UI expects milliseconds, but SipSession stores seconds. Conversion ensures correct display.

---

### Fix 2: Session Finalization (src/correlation/sip_session_manager.cpp)

**Location**: Line 109 (added)

**Added**:
```cpp
// Finalize session to extract call parties and session type
sip_session->finalize();
```

**Rationale**: Finalization triggers:
- `detectSessionType()` - determines if it's CALL, REGISTRATION, etc.
- `extractCallParties()` - extracts caller/callee MSISDNs
- `extractMediaInfo()` - extracts media details from SDP
- `extractUeIpAddresses()` - extracts UE IP addresses

---

### Fix 3: Event Network Information & Participants (src/event_extractor/json_exporter.cpp)

**Location**: Lines 432-493

**Changes**:
1. Extract network information from each SIP message:
```cpp
std::string src_ip = msg.value("source_ip", "");
std::string dst_ip = msg.value("dest_ip", "");
uint16_t src_port = msg.value("source_port", 0);
uint16_t dst_port = msg.value("dest_port", 0);
```

2. Add network fields to events:
```cpp
event["src_ip"] = src_ip;
event["dst_ip"] = dst_ip;
event["src_port"] = src_port;
event["dst_port"] = dst_port;
```

3. Build participants from actual message data:
```cpp
std::set<std::string> participants_set;
// ... in loop:
if (!src_ip.empty()) {
    participants_set.insert(src_ip + ":" + std::to_string(src_port));
}
if (!dst_ip.empty()) {
    participants_set.insert(dst_ip + ":" + std::to_string(dst_port));
}
```

4. Add `details` object to events:
```cpp
event["details"] = {
    {"src_ip", src_ip},
    {"dst_ip", dst_ip},
    {"src_port", src_port},
    {"dst_port", dst_port},
    {"payload_len", 0}
};
```

5. Fix timestamp conversion in events:
```cpp
double timestamp = msg.value("timestamp", 0.0);
event["timestamp"] = static_cast<uint64_t>(timestamp * 1000);
```

---

## Expected Results After Fixes

1. **Timestamps**: Will show correct datetime instead of 1970-01-20
2. **Participants**: Will show actual IP:port pairs like `2a01:59f:801f:f625::2:39592`
3. **Direction**: Will show `IP1:port1 -> IP2:port2` instead of `? -> ?`
4. **Session Status**: Will show proper session type badge (e.g., "CALL", "REGISTRATION")
5. **Event Details**: Timeline events will have complete network information

---

## Testing Recommendations

1. **Upload the same PCAP file** that showed the issues
2. **Verify sessions table**:
   - Check that timestamps show realistic dates (2024/2025)
   - Check that IMSI/MSISDN columns populate correctly
   - Check that duration shows non-zero values

3. **Verify session detail view**:
   - Check that participants show IP:port format
   - Check that direction shows proper arrow between IPs
   - Check that session status badge is not "UNKNOWN"

4. **Verify timeline events**:
   - Check that timestamps are correct
   - Check that each event shows source/destination details
   - Check that event details panel shows network info

---

## Code Changes Summary

### Files Modified:
1. `src/correlation/sip_session_manager.cpp` - 2 changes
   - Added `finalize()` call before export
   - Fixed timestamp conversion to milliseconds

2. `src/event_extractor/json_exporter.cpp` - 1 major refactor
   - Fixed event timestamp conversion
   - Added network information extraction
   - Built participants from actual SIP messages
   - Added `details` object to events
   - Improved fallback to caller_ip/callee_ip if messages unavailable

---

## Additional Notes

### Correlation vs Standalone SIP
- **Correlated sessions**: SIP sessions linked to GTP/DIAMETER via IMSI/MSISDN
- **Standalone SIP**: SIP-only sessions without correlation keys
  - Logged as: `"Created standalone SIP session: <Call-ID>"`
  - Still need proper display even without correlation

### Timestamp Architecture
- **Internal storage**: `double` (seconds since epoch)
- **Network wire**: Packet capture timestamps
- **JSON export**: `uint64_t` (milliseconds since epoch)
- **UI display**: JavaScript Date object (milliseconds)

### SIP Message Structure
From nDPI parser → `correlation::SipMessage` class:
- Contains: source_ip, dest_ip, source_port, dest_port, timestamp
- Stored in SipSession as vector of messages
- Exported to JSON with full network details

---

## Related Files (Reference)

- `include/correlation/sip/sip_session.h` - SipSession class definition
- `include/correlation/sip/sip_message.h` - SipMessage class definition
- `src/correlation/sip/sip_session.cpp` - Session management logic
- `src/correlation/sip/sip_message.cpp` - Message toJson() method
- `src/session/session_correlator.cpp` - Main correlation logic
- `src/pcap_ingest/packet_processor.cpp` - Packet parsing and SIP detection

---

## Docker Logs Analysis

The logs show successful SIP parsing:
```
[INFO ] [packet_processor.cpp:917] Registered non-standard SIP port: 45535
[INFO ] [sip_session_manager.cpp:31] Created standalone SIP session: U7kXoCYyb00zbioSqMNw8A..@2a01:59f:801f:f625::2
```

This indicates:
- SIP is being detected on non-standard ports ✓
- Sessions are being created ✓
- Call-IDs are being extracted ✓
- **Issue was in export/display layer, not parsing**

---

## Conclusion

All identified issues stem from the **export and JSON formatting layer**, not the core SIP parsing logic. The fixes ensure:
1. Proper time conversion (seconds → milliseconds)
2. Session finalization before export
3. Complete network information in events
4. Participants built from actual message data
5. Details object for UI consumption

The parsing and correlation engine is working correctly; these fixes ensure the data is properly formatted for UI display.
