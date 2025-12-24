#pragma once

#include "correlation/volte/volte_types.h"
#include "correlation/sip/sip_correlator.h"
#include "correlation/diameter/diameter_correlator.h"
#include "correlation/gtpv2/gtpv2_correlator.h"
#include "correlation/nas/nas_correlator.h"
#include "correlation/rtp/rtp_correlator.h"
#include "correlation/identity/subscriber_context_manager.h"
#include <memory>
#include <vector>
#include <unordered_map>
#include <mutex>

namespace callflow {
namespace correlation {

/**
 * @brief VoLTE inter-protocol correlator
 *
 * Links protocol-specific sessions into complete VoLTE call flows.
 *
 * Implements a multi-phase correlation algorithm:
 * - Phase 1: Link subscriber identities (IMSI ↔ MSISDN ↔ IMEI)
 * - Phase 2: Detect SIP voice/video calls
 * - Phase 3: Correlate other protocols within call time window
 * - Phase 4: Link residual sessions (no SIP parent)
 * - Phase 5: Resolve network elements (UEa, UEb, UEc)
 * - Phase 6: Calculate statistics
 *
 * Key matching logic:
 * - MSISDN matching with format normalization
 * - UE IP address matching
 * - Time-windowed correlation
 * - GTP TEID linking
 */
class VolteCorrelator {
public:
    VolteCorrelator();
    ~VolteCorrelator() = default;

    /**
     * @brief Set protocol correlators
     *
     * These correlators must be set before calling correlate().
     * The VolteCorrelator does not take ownership of these pointers.
     */
    void setSipCorrelator(SipCorrelator* correlator);
    void setDiameterCorrelator(DiameterCorrelator* correlator);
    void setGtpv2Correlator(Gtpv2Correlator* correlator);
    void setNasCorrelator(NasCorrelator* correlator);
    void setRtpCorrelator(RtpCorrelator* correlator);
    void setSubscriberContextManager(SubscriberContextManager* manager);

    /**
     * @brief Run correlation algorithm
     *
     * Executes all 6 phases of the VoLTE correlation algorithm.
     * Must be called after all protocol correlators have finished processing.
     */
    void correlate();

    // ========================================================================
    // Call Flow Access
    // ========================================================================

    /**
     * @brief Get all call flows
     */
    std::vector<VolteCallFlow*> getCallFlows();

    /**
     * @brief Get call flows by type
     */
    std::vector<VolteCallFlow*> getCallFlowsByType(VolteFlowType type);

    /**
     * @brief Get voice calls only (MO/MT, includes forwarded calls)
     */
    std::vector<VolteCallFlow*> getVoiceCalls();

    /**
     * @brief Get video calls only
     */
    std::vector<VolteCallFlow*> getVideoCalls();

    // ========================================================================
    // Call Flow Lookup
    // ========================================================================

    /**
     * @brief Find call flow by ID
     */
    VolteCallFlow* findByFlowId(const std::string& flow_id);

    /**
     * @brief Find call flows by MSISDN (caller or callee)
     */
    std::vector<VolteCallFlow*> findByMsisdn(const std::string& msisdn);

    /**
     * @brief Find call flows by IMSI (caller or callee)
     */
    std::vector<VolteCallFlow*> findByImsi(const std::string& imsi);

    /**
     * @brief Find call flow containing frame
     */
    VolteCallFlow* findByFrame(uint32_t frame_number);

    // ========================================================================
    // Statistics
    // ========================================================================

    struct Stats {
        size_t total_call_flows = 0;
        size_t voice_calls = 0;
        size_t video_calls = 0;
        size_t sms_sessions = 0;
        size_t registrations = 0;
        size_t data_sessions = 0;
        size_t uncorrelated_sip_sessions = 0;
        size_t uncorrelated_diameter_sessions = 0;
        size_t uncorrelated_gtp_sessions = 0;
        size_t uncorrelated_nas_sessions = 0;
        size_t uncorrelated_rtp_streams = 0;
    };

    /**
     * @brief Get correlation statistics
     */
    Stats getStats() const;

    /**
     * @brief Clear all call flows and reset state
     */
    void clear();

private:
    mutable std::mutex mutex_;

    // Protocol correlator references (not owned)
    SipCorrelator* sip_correlator_ = nullptr;
    DiameterCorrelator* diameter_correlator_ = nullptr;
    Gtpv2Correlator* gtpv2_correlator_ = nullptr;
    NasCorrelator* nas_correlator_ = nullptr;
    RtpCorrelator* rtp_correlator_ = nullptr;
    SubscriberContextManager* subscriber_manager_ = nullptr;

    // Call flows storage
    std::vector<std::unique_ptr<VolteCallFlow>> call_flows_;

    // Index for fast lookup
    std::unordered_map<std::string, VolteCallFlow*> flow_id_index_;
    std::unordered_multimap<std::string, VolteCallFlow*> msisdn_index_;
    std::unordered_multimap<std::string, VolteCallFlow*> imsi_index_;
    std::unordered_map<uint32_t, VolteCallFlow*> frame_index_;

    // Statistics
    Stats stats_;

    // Correlation state tracking
    std::unordered_set<std::string> correlated_sip_sessions_;
    std::unordered_set<std::string> correlated_diameter_sessions_;
    std::unordered_set<std::string> correlated_gtp_sessions_;
    std::unordered_set<std::string> correlated_nas_sessions_;
    std::unordered_set<uint32_t> correlated_rtp_ssrcs_;

    // ========================================================================
    // Correlation Phases
    // ========================================================================

    /**
     * @brief Phase 1: Link subscriber identities across protocols
     *
     * Uses SubscriberContextManager to propagate IMSI, MSISDN, IMEI
     * across all protocol sessions.
     */
    void phase1_LinkSubscriberIdentities();

    /**
     * @brief Phase 2: Detect SIP calls and create initial flows
     *
     * Analyzes SIP sessions to identify voice/video calls.
     * Creates initial VolteCallFlow objects with caller/callee info.
     */
    void phase2_DetectSipCalls();

    /**
     * @brief Phase 3: Correlate other protocols within call time window
     *
     * For each SIP-based call flow, finds matching:
     * - Diameter Gx/Rx sessions (by UE IP + time window)
     * - GTPv2 IMS bearers (by MSISDN + time window)
     * - NAS ESM sessions (by IMSI + time window)
     * - RTP streams (by UE media IP + time window)
     */
    void phase3_CorrelateWithinCallWindow();

    /**
     * @brief Phase 4: Link residual sessions without SIP parent
     *
     * Creates flows for:
     * - Diameter/GTP sessions without matching SIP (failed calls, data-only)
     * - SMS sessions
     * - IMS registrations
     */
    void phase4_LinkResidualSessions();

    /**
     * @brief Phase 5: Resolve network elements (UEa, UEb, UEc, IMS nodes)
     *
     * Determines:
     * - Which party is caller (UEa) vs callee (UEb)
     * - Forward target (UEc) for call forwarding
     * - Network path (P-CSCF, S-CSCF, I-CSCF, etc.)
     */
    void phase5_ResolveNetworkElements();

    /**
     * @brief Phase 6: Calculate statistics for each flow
     *
     * Computes:
     * - Call setup time (INVITE -> 200 OK)
     * - Ring time (INVITE -> 180 Ringing)
     * - Call duration (200 OK -> BYE)
     * - RTP quality metrics (jitter, loss, MOS)
     */
    void phase6_CalculateStatistics();

    // ========================================================================
    // Phase 3 Helpers
    // ========================================================================

    void correlateDiameterGx(VolteCallFlow& flow);
    void correlateDiameterRx(VolteCallFlow& flow);
    void correlateDiameterCxSh(VolteCallFlow& flow);
    void correlateGtpv2ImsBearer(VolteCallFlow& flow);
    void correlateNasEsm(VolteCallFlow& flow);
    void correlateRtp(VolteCallFlow& flow);

    // ========================================================================
    // Matching Helpers
    // ========================================================================

    /**
     * @brief Check if two MSISDNs match (with normalization)
     */
    bool matchesMsisdn(const std::string& m1, const std::string& m2);

    /**
     * @brief Check if UE IP addresses match (IPv4 exact, IPv6 prefix)
     */
    bool matchesUeIp(const std::string& ip1, const std::string& ip2);

    /**
     * @brief Check if timestamp is within time window (with tolerance)
     */
    bool isWithinTimeWindow(double ts, double start, double end,
                            double tolerance_ms = 1000.0);

    // ========================================================================
    // Indexing Helpers
    // ========================================================================

    void updateIndices(VolteCallFlow* flow);
    void addToMsisdnIndex(const std::string& msisdn, VolteCallFlow* flow);
    void addToImsiIndex(const std::string& imsi, VolteCallFlow* flow);
    void addToFrameIndex(const std::vector<uint32_t>& frames, VolteCallFlow* flow);

    // ========================================================================
    // Flow ID Generation
    // ========================================================================

    /**
     * @brief Generate unique flow ID from SIP Call-ID
     */
    std::string generateFlowId(const std::string& sip_call_id, double timestamp);

    /**
     * @brief Generate flow ID for non-SIP flows
     */
    std::string generateFlowIdForResidual(const std::string& protocol,
                                           const std::string& session_id,
                                           double timestamp);
};

} // namespace correlation
} // namespace callflow
