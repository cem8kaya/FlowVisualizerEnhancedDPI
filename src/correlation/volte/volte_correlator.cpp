#include "correlation/volte/volte_correlator.h"

#include <algorithm>
#include <iomanip>
#include <sstream>

#include "correlation/diameter/diameter_session.h"
#include "correlation/gtpv2/gtpv2_session.h"
#include "correlation/identity/msisdn_normalizer.h"
#include "correlation/nas/nas_session.h"
#include "correlation/rtp/rtp_stream.h"
#include "correlation/sip/sip_types.h"

namespace callflow {
namespace correlation {

VolteCorrelator::VolteCorrelator() {}

// ============================================================================
// Correlator Setup
// ============================================================================

void VolteCorrelator::setSipCorrelator(SipCorrelator* correlator) {
    sip_correlator_ = correlator;
}

void VolteCorrelator::setDiameterCorrelator(DiameterCorrelator* correlator) {
    diameter_correlator_ = correlator;
}

void VolteCorrelator::setGtpv2Correlator(Gtpv2Correlator* correlator) {
    gtpv2_correlator_ = correlator;
}

void VolteCorrelator::setNasCorrelator(NasCorrelator* correlator) {
    nas_correlator_ = correlator;
}

void VolteCorrelator::setRtpCorrelator(RtpCorrelator* correlator) {
    rtp_correlator_ = correlator;
}

void VolteCorrelator::setSubscriberContextManager(SubscriberContextManager* manager) {
    subscriber_manager_ = manager;
}

// ============================================================================
// Main Correlation Algorithm
// ============================================================================

void VolteCorrelator::correlate() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!sip_correlator_) {
        // At minimum, we need SIP correlator
        return;
    }

    // Clear previous state
    call_flows_.clear();
    flow_id_index_.clear();
    msisdn_index_.clear();
    imsi_index_.clear();
    frame_index_.clear();
    correlated_sip_sessions_.clear();
    correlated_diameter_sessions_.clear();
    correlated_gtp_sessions_.clear();
    correlated_nas_sessions_.clear();
    correlated_rtp_ssrcs_.clear();
    stats_ = Stats{};

    // Phase 1: Link subscriber identities across protocols
    phase1_LinkSubscriberIdentities();

    // Phase 2: Detect SIP voice/video calls and create initial flows
    phase2_DetectSipCalls();

    // Phase 3: Correlate other protocols within each call's time window
    phase3_CorrelateWithinCallWindow();

    // Phase 4: Link residual Diameter/GTP sessions without SIP parent
    phase4_LinkResidualSessions();

    // Phase 5: Resolve network elements (UEa, UEb, UEc, IMS nodes)
    phase5_ResolveNetworkElements();

    // Phase 6: Calculate statistics for each flow
    phase6_CalculateStatistics();

    // Update overall statistics
    stats_.total_call_flows = call_flows_.size();
}

// ============================================================================
// Phase 1: Link Subscriber Identities
// ============================================================================

void VolteCorrelator::phase1_LinkSubscriberIdentities() {
    if (!subscriber_manager_) {
        return;
    }

    // Subscriber identity linking is handled by SubscriberContextManager
    // which is updated by each protocol correlator during their processing.
    // Here we just trigger the propagation algorithm.
    subscriber_manager_->propagateIdentities();
}

// ============================================================================
// Phase 2: Detect SIP Calls
// ============================================================================

void VolteCorrelator::phase2_DetectSipCalls() {
    auto sip_sessions = sip_correlator_->getCallSessions();

    for (auto* sip_session : sip_sessions) {
        auto flow = std::make_unique<VolteCallFlow>();

        // Generate flow ID from SIP Call-ID
        flow->flow_id = generateFlowId(sip_session->getCallId(), sip_session->getStartTime());

        // Determine flow type
        bool has_video = sip_session->hasVideo();
        bool has_forward = sip_session->getForwardTargetMsisdn().has_value();

        if (has_forward) {
            flow->type = VolteFlowType::VOICE_CALL_FORWARDING;
        } else if (has_video) {
            // Will determine MO/MT in phase 5
            flow->type = VolteFlowType::MO_VIDEO_CALL;
        } else {
            // Will determine MO/MT in phase 5
            flow->type = VolteFlowType::MO_VOICE_CALL;
        }

        // Set call parties
        flow->caller.msisdn = sip_session->getCallerMsisdn();
        flow->caller.ip_v4 = sip_session->getCallerIp();
        flow->caller.role = "UEa";

        flow->callee.msisdn = sip_session->getCalleeMsisdn();
        flow->callee.ip_v4 = sip_session->getCalleeIp();
        flow->callee.role = "UEb";

        // Check for call forwarding
        if (auto fwd = sip_session->getForwardTargetMsisdn()) {
            flow->forward_target = VolteParty("UEc");
            flow->forward_target->msisdn = *fwd;
        }

        // Set time window
        flow->start_time = sip_session->getStartTime();
        flow->end_time = sip_session->getEndTime();
        flow->start_frame = sip_session->getStartFrame();
        flow->end_frame = sip_session->getEndFrame();

        // Add SIP session reference
        flow->sip_sessions.push_back(sip_session->getIntraCorrelator());
        correlated_sip_sessions_.insert(sip_session->getIntraCorrelator());

        // Collect frame numbers from SIP messages
        for (const auto& msg : sip_session->getMessages()) {
            flow->frame_numbers.push_back(msg.getFrameNumber());
        }
        flow->stats.sip_messages = sip_session->getMessageCount();

        // Resolve IMSI from subscriber context
        if (subscriber_manager_) {
            auto ctx = subscriber_manager_->findByMsisdn(flow->caller.msisdn);
            if (ctx && ctx->imsi) {
                flow->caller.imsi = ctx->imsi->digits;
            }

            ctx = subscriber_manager_->findByMsisdn(flow->callee.msisdn);
            if (ctx && ctx->imsi) {
                flow->callee.imsi = ctx->imsi->digits;
            }

            if (flow->forward_target) {
                ctx = subscriber_manager_->findByMsisdn(flow->forward_target->msisdn);
                if (ctx && ctx->imsi) {
                    flow->forward_target->imsi = ctx->imsi->digits;
                }
            }
        }

        // Update indices
        auto* flow_ptr = flow.get();
        updateIndices(flow_ptr);

        // Store flow
        call_flows_.push_back(std::move(flow));

        // Update statistics
        if (has_video) {
            stats_.voice_calls++;
        } else {
            stats_.video_calls++;
        }
    }
}

// ============================================================================
// Phase 3: Correlate Within Call Window
// ============================================================================

void VolteCorrelator::phase3_CorrelateWithinCallWindow() {
    for (auto& flow : call_flows_) {
        correlateDiameterGx(*flow);
        correlateDiameterRx(*flow);
        correlateDiameterCxSh(*flow);
        correlateGtpv2ImsBearer(*flow);
        correlateNasEsm(*flow);
        correlateRtp(*flow);
    }
}

void VolteCorrelator::correlateDiameterGx(VolteCallFlow& flow) {
    if (!diameter_correlator_)
        return;

    auto gx_sessions = diameter_correlator_->getGxSessions();

    for (auto* gx : gx_sessions) {
        // Check if already correlated
        if (correlated_diameter_sessions_.count(gx->getSessionId())) {
            continue;
        }

        // Check time window (with tolerance for session setup before call)
        if (!isWithinTimeWindow(gx->getStartTime(), flow.start_time, flow.end_time, 5000.0)) {
            continue;
        }

        // Match by UE IP address
        auto framed_ip = gx->getFramedIpAddress();
        if (!framed_ip)
            continue;

        if (matchesUeIp(*framed_ip, flow.caller.ip_v4) ||
            matchesUeIp(*framed_ip, flow.callee.ip_v4)) {
            flow.diameter_sessions.push_back(gx->getSessionId());
            flow.stats.diameter_messages += gx->getMessageCount();
            correlated_diameter_sessions_.insert(gx->getSessionId());

            // Collect frame numbers
            for (const auto& msg : gx->getMessages()) {
                flow.frame_numbers.push_back(msg.getFrameNumber());
            }
        }
    }
}

void VolteCorrelator::correlateDiameterRx(VolteCallFlow& flow) {
    if (!diameter_correlator_)
        return;

    auto rx_sessions = diameter_correlator_->getRxSessions();

    for (auto* rx : rx_sessions) {
        // Check if already correlated
        if (correlated_diameter_sessions_.count(rx->getSessionId())) {
            continue;
        }

        // Check time window
        if (!isWithinTimeWindow(rx->getStartTime(), flow.start_time, flow.end_time, 2000.0)) {
            continue;
        }

        // Match by UE IP address
        auto framed_ip = rx->getFramedIpAddress();
        if (!framed_ip)
            continue;

        if (matchesUeIp(*framed_ip, flow.caller.ip_v4) ||
            matchesUeIp(*framed_ip, flow.callee.ip_v4)) {
            flow.diameter_sessions.push_back(rx->getSessionId());
            flow.stats.diameter_messages += rx->getMessageCount();
            correlated_diameter_sessions_.insert(rx->getSessionId());

            // Collect frame numbers
            for (const auto& msg : rx->getMessages()) {
                flow.frame_numbers.push_back(msg.getFrameNumber());
            }
        }
    }
}

void VolteCorrelator::correlateDiameterCxSh(VolteCallFlow& flow) {
    if (!diameter_correlator_)
        return;

    // Correlate Cx sessions (IMS registration)
    auto cx_sessions = diameter_correlator_->getCxSessions();
    for (auto* cx : cx_sessions) {
        if (correlated_diameter_sessions_.count(cx->getSessionId())) {
            continue;
        }

        // Cx sessions happen before the call (IMS registration)
        // Look for sessions within extended time window
        if (!isWithinTimeWindow(cx->getStartTime(), flow.start_time, flow.end_time, 30000.0)) {
            continue;
        }

        // Match by MSISDN or public identity
        auto msisdn = cx->getMsisdn();
        if (msisdn && (matchesMsisdn(*msisdn, flow.caller.msisdn) ||
                       matchesMsisdn(*msisdn, flow.callee.msisdn))) {
            flow.diameter_sessions.push_back(cx->getSessionId());
            flow.stats.diameter_messages += cx->getMessageCount();
            correlated_diameter_sessions_.insert(cx->getSessionId());

            for (const auto& msg : cx->getMessages()) {
                flow.frame_numbers.push_back(msg.getFrameNumber());
            }
        }
    }

    // Correlate Sh sessions (IMS user data)
    auto sh_sessions = diameter_correlator_->getShSessions();
    for (auto* sh : sh_sessions) {
        if (correlated_diameter_sessions_.count(sh->getSessionId())) {
            continue;
        }

        if (!isWithinTimeWindow(sh->getStartTime(), flow.start_time, flow.end_time, 30000.0)) {
            continue;
        }

        auto msisdn = sh->getMsisdn();
        if (msisdn && (matchesMsisdn(*msisdn, flow.caller.msisdn) ||
                       matchesMsisdn(*msisdn, flow.callee.msisdn))) {
            flow.diameter_sessions.push_back(sh->getSessionId());
            flow.stats.diameter_messages += sh->getMessageCount();
            correlated_diameter_sessions_.insert(sh->getSessionId());

            for (const auto& msg : sh->getMessages()) {
                flow.frame_numbers.push_back(msg.getFrameNumber());
            }
        }
    }
}

void VolteCorrelator::correlateGtpv2ImsBearer(VolteCallFlow& flow) {
    if (!gtpv2_correlator_)
        return;

    auto ims_sessions = gtpv2_correlator_->getSessionsWithDedicatedBearers();

    for (auto* gtp : ims_sessions) {
        // Check if already correlated
        auto intra_id = gtp->getIntraCorrelator();
        if (correlated_gtp_sessions_.count(intra_id)) {
            continue;
        }

        // Check time window (GTP session setup happens around call time)
        if (!isWithinTimeWindow(gtp->getStartTime(), flow.start_time, flow.end_time, 3000.0)) {
            continue;
        }

        // Match by MSISDN
        auto msisdn = gtp->getMsisdn();
        if (msisdn && (matchesMsisdn(*msisdn, flow.caller.msisdn) ||
                       matchesMsisdn(*msisdn, flow.callee.msisdn))) {
            flow.gtpv2_sessions.push_back(intra_id);
            flow.stats.gtp_messages += gtp->getMessageCount();
            correlated_gtp_sessions_.insert(intra_id);

            // Collect frame numbers
            for (const auto& msg : gtp->getMessages()) {
                flow.frame_numbers.push_back(msg.getFrameNumber());
            }

            // Copy IMSI if not already set
            auto gtp_imsi = gtp->getImsi();
            if (gtp_imsi) {
                if (!flow.caller.imsi && matchesMsisdn(*msisdn, flow.caller.msisdn)) {
                    flow.caller.imsi = *gtp_imsi;
                }
                if (!flow.callee.imsi && matchesMsisdn(*msisdn, flow.callee.msisdn)) {
                    flow.callee.imsi = *gtp_imsi;
                }
            }
        }
    }
}

void VolteCorrelator::correlateNasEsm(VolteCallFlow& flow) {
    if (!nas_correlator_)
        return;

    auto esm_sessions = nas_correlator_->getImsEsmSessions();

    for (auto* nas : esm_sessions) {
        // Check if already correlated
        auto intra_id = nas->getIntraCorrelator();
        if (correlated_nas_sessions_.count(intra_id)) {
            continue;
        }

        // Check time window (NAS ESM for IMS bearer setup)
        if (!isWithinTimeWindow(nas->getStartTime(), flow.start_time, flow.end_time, 3000.0)) {
            continue;
        }

        // Match by IMSI
        auto imsi = nas->getImsi();
        if (imsi) {
            bool matched = false;

            if (flow.caller.imsi && *imsi == *flow.caller.imsi) {
                matched = true;
            }
            if (flow.callee.imsi && *imsi == *flow.callee.imsi) {
                matched = true;
            }

            if (matched) {
                flow.nas_sessions.push_back(intra_id);
                flow.stats.nas_messages += nas->getMessageCount();
                correlated_nas_sessions_.insert(intra_id);

                // Collect frame numbers
                for (const auto& msg : nas->getMessages()) {
                    flow.frame_numbers.push_back(msg.getFrameNum());
                }
            }
        }
    }
}

void VolteCorrelator::correlateRtp(VolteCallFlow& flow) {
    if (!rtp_correlator_)
        return;

    // Get RTP streams within time window
    auto streams = rtp_correlator_->findByTimeWindow(flow.start_time, flow.end_time);

    for (auto* stream : streams) {
        // Check if already correlated
        if (correlated_rtp_ssrcs_.count(stream->getSsrc())) {
            continue;
        }

        // Match by UE IP address
        bool matched = false;

        if (!flow.caller.ip_v4.empty() && (matchesUeIp(stream->getSrcIp(), flow.caller.ip_v4) ||
                                           matchesUeIp(stream->getDstIp(), flow.caller.ip_v4))) {
            matched = true;
        }

        if (!flow.callee.ip_v4.empty() && (matchesUeIp(stream->getSrcIp(), flow.callee.ip_v4) ||
                                           matchesUeIp(stream->getDstIp(), flow.callee.ip_v4))) {
            matched = true;
        }

        if (matched) {
            flow.rtp_ssrcs.push_back(stream->getSsrc());
            flow.stats.rtp_packets += stream->getPacketCount();
            correlated_rtp_ssrcs_.insert(stream->getSsrc());

            // Calculate and aggregate RTP quality metrics
            auto metrics = stream->calculateMetrics();

            if (metrics.jitter_ms > 0.0) {
                if (!flow.stats.rtp_jitter_ms) {
                    flow.stats.rtp_jitter_ms = metrics.jitter_ms;
                } else {
                    // Average jitter across streams
                    *flow.stats.rtp_jitter_ms =
                        (*flow.stats.rtp_jitter_ms + metrics.jitter_ms) / 2.0;
                }
            }

            if (metrics.packet_loss_rate > 0.0) {
                double loss_percent = metrics.packet_loss_rate * 100.0;
                if (!flow.stats.rtp_packet_loss) {
                    flow.stats.rtp_packet_loss = loss_percent;
                } else {
                    // Max packet loss across streams
                    *flow.stats.rtp_packet_loss =
                        std::max(*flow.stats.rtp_packet_loss, loss_percent);
                }
            }

            if (metrics.estimated_mos && *metrics.estimated_mos > 0.0) {
                if (!flow.stats.estimated_mos) {
                    flow.stats.estimated_mos = *metrics.estimated_mos;
                } else {
                    // Min MOS across streams (worst quality)
                    *flow.stats.estimated_mos =
                        std::min(*flow.stats.estimated_mos, *metrics.estimated_mos);
                }
            }
        }
    }
}

// ============================================================================
// Phase 4: Link Residual Sessions
// ============================================================================

void VolteCorrelator::phase4_LinkResidualSessions() {
    // Create flows for uncorrelated SIP sessions (SMS, registrations, etc.)
    auto all_sip_sessions = sip_correlator_->getSessions();
    for (auto* sip : all_sip_sessions) {
        if (correlated_sip_sessions_.count(sip->getIntraCorrelator())) {
            continue;
        }

        auto flow = std::make_unique<VolteCallFlow>();
        flow->flow_id = generateFlowIdForResidual("SIP", sip->getCallId(), sip->getStartTime());

        // Determine type
        auto sip_type = sip->getType();
        if (sip_type == SipSessionType::REGISTRATION) {
            flow->type = VolteFlowType::IMS_REGISTRATION;
            stats_.registrations++;
        } else if (sip_type == SipSessionType::SMS_MESSAGE) {
            flow->type = VolteFlowType::MO_SMS;
            stats_.sms_sessions++;
        } else {
            flow->type = VolteFlowType::UNKNOWN;
        }

        flow->start_time = sip->getStartTime();
        flow->end_time = sip->getEndTime();
        flow->start_frame = sip->getStartFrame();
        flow->end_frame = sip->getEndFrame();
        flow->sip_sessions.push_back(sip->getIntraCorrelator());
        flow->stats.sip_messages = sip->getMessageCount();

        for (const auto& msg : sip->getMessages()) {
            flow->frame_numbers.push_back(msg.getFrameNumber());
        }

        auto* flow_ptr = flow.get();
        updateIndices(flow_ptr);
        call_flows_.push_back(std::move(flow));

        correlated_sip_sessions_.insert(sip->getIntraCorrelator());
    }

    // Count uncorrelated sessions for statistics
    if (sip_correlator_) {
        stats_.uncorrelated_sip_sessions =
            sip_correlator_->getSessions().size() - correlated_sip_sessions_.size();
    }
    if (diameter_correlator_) {
        stats_.uncorrelated_diameter_sessions =
            diameter_correlator_->getSessions().size() - correlated_diameter_sessions_.size();
    }
    if (gtpv2_correlator_) {
        stats_.uncorrelated_gtp_sessions =
            gtpv2_correlator_->getSessions().size() - correlated_gtp_sessions_.size();
    }
    if (nas_correlator_) {
        stats_.uncorrelated_nas_sessions =
            nas_correlator_->getSessions().size() - correlated_nas_sessions_.size();
    }
    if (rtp_correlator_) {
        stats_.uncorrelated_rtp_streams =
            rtp_correlator_->getStreams().size() - correlated_rtp_ssrcs_.size();
    }
}

// ============================================================================
// Phase 5: Resolve Network Elements
// ============================================================================

void VolteCorrelator::phase5_ResolveNetworkElements() {
    // Determine MO vs MT based on which party initiated the SIP session
    for (auto& flow : call_flows_) {
        if (flow->type == VolteFlowType::MO_VOICE_CALL ||
            flow->type == VolteFlowType::MO_VIDEO_CALL) {
            // Check SIP messages to determine direction
            if (!flow->sip_sessions.empty()) {
                auto* sip = sip_correlator_->findByCallId(
                    flow->sip_sessions[0].substr(0, flow->sip_sessions[0].find('_')));

                if (sip && sip->getMessages().size() > 0) {
                    // First INVITE determines direction
                    // (This is simplified - production code would check Via headers)
                    // For now, assume MO is default
                }
            }
        }

        // Extract network path from SIP Via/Route headers
        // (Simplified - production would parse headers)
        flow->network_path.push_back("P-CSCF");
        flow->network_path.push_back("S-CSCF");
    }
}

// ============================================================================
// Phase 6: Calculate Statistics
// ============================================================================

void VolteCorrelator::phase6_CalculateStatistics() {
    for (auto& flow : call_flows_) {
        if (flow->sip_sessions.empty()) {
            continue;
        }

        // Get SIP session
        auto* sip = sip_correlator_->findByCallId(
            flow->sip_sessions[0].substr(0, flow->sip_sessions[0].find('_')));

        if (!sip)
            continue;

        const auto& messages = sip->getMessages();
        if (messages.empty())
            continue;

        // Find key timestamps
        double invite_time = 0.0;
        double ringing_time = 0.0;
        double ok_time = 0.0;
        double bye_time = 0.0;

        for (const auto& msg : messages) {
            if (msg.getMethod() == "INVITE" && msg.isRequest() && invite_time == 0.0) {
                invite_time = msg.getTimestamp();
            } else if (msg.getStatusCode() == 180 && ringing_time == 0.0) {
                ringing_time = msg.getTimestamp();
            } else if (msg.getStatusCode() == 200 && ok_time == 0.0) {
                ok_time = msg.getTimestamp();
            } else if (msg.getMethod() == "BYE" && msg.isRequest() && bye_time == 0.0) {
                bye_time = msg.getTimestamp();
            }
        }

        // Calculate setup time (INVITE -> 200 OK)
        if (invite_time > 0.0 && ok_time > 0.0) {
            flow->stats.setup_time_ms = (ok_time - invite_time) * 1000.0;
        }

        // Calculate ring time (INVITE -> 180 Ringing)
        if (invite_time > 0.0 && ringing_time > 0.0) {
            flow->stats.ring_time_ms = (ringing_time - invite_time) * 1000.0;
        }

        // Calculate call duration (200 OK -> BYE)
        if (ok_time > 0.0 && bye_time > 0.0) {
            flow->stats.call_duration_ms = (bye_time - ok_time) * 1000.0;
        }
    }

    // Sort frame numbers for each flow
    for (auto& flow : call_flows_) {
        std::sort(flow->frame_numbers.begin(), flow->frame_numbers.end());
    }
}

// ============================================================================
// Call Flow Access
// ============================================================================

std::vector<VolteCallFlow*> VolteCorrelator::getCallFlows() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<VolteCallFlow*> result;
    result.reserve(call_flows_.size());
    for (auto& flow : call_flows_) {
        result.push_back(flow.get());
    }
    return result;
}

std::vector<VolteCallFlow*> VolteCorrelator::getCallFlowsByType(VolteFlowType type) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<VolteCallFlow*> result;
    for (auto& flow : call_flows_) {
        if (flow->type == type) {
            result.push_back(flow.get());
        }
    }
    return result;
}

std::vector<VolteCallFlow*> VolteCorrelator::getVoiceCalls() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<VolteCallFlow*> result;
    for (auto& flow : call_flows_) {
        if (flow->type == VolteFlowType::MO_VOICE_CALL ||
            flow->type == VolteFlowType::MT_VOICE_CALL ||
            flow->type == VolteFlowType::VOICE_CALL_FORWARDING ||
            flow->type == VolteFlowType::CONFERENCE_CALL) {
            result.push_back(flow.get());
        }
    }
    return result;
}

std::vector<VolteCallFlow*> VolteCorrelator::getVideoCalls() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<VolteCallFlow*> result;
    for (auto& flow : call_flows_) {
        if (flow->type == VolteFlowType::MO_VIDEO_CALL ||
            flow->type == VolteFlowType::MT_VIDEO_CALL) {
            result.push_back(flow.get());
        }
    }
    return result;
}

// ============================================================================
// Call Flow Lookup
// ============================================================================

VolteCallFlow* VolteCorrelator::findByFlowId(const std::string& flow_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = flow_id_index_.find(flow_id);
    if (it != flow_id_index_.end()) {
        return it->second;
    }
    return nullptr;
}

std::vector<VolteCallFlow*> VolteCorrelator::findByMsisdn(const std::string& msisdn) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<VolteCallFlow*> result;

    auto normalized = MsisdnNormalizer::normalize(msisdn);
    auto range = msisdn_index_.equal_range(normalized.digits_only);

    for (auto it = range.first; it != range.second; ++it) {
        result.push_back(it->second);
    }

    return result;
}

std::vector<VolteCallFlow*> VolteCorrelator::findByImsi(const std::string& imsi) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<VolteCallFlow*> result;

    auto range = imsi_index_.equal_range(imsi);
    for (auto it = range.first; it != range.second; ++it) {
        result.push_back(it->second);
    }

    return result;
}

VolteCallFlow* VolteCorrelator::findByFrame(uint32_t frame_number) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = frame_index_.find(frame_number);
    if (it != frame_index_.end()) {
        return it->second;
    }
    return nullptr;
}

// ============================================================================
// Statistics
// ============================================================================

VolteCorrelator::Stats VolteCorrelator::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void VolteCorrelator::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    call_flows_.clear();
    flow_id_index_.clear();
    msisdn_index_.clear();
    imsi_index_.clear();
    frame_index_.clear();
    correlated_sip_sessions_.clear();
    correlated_diameter_sessions_.clear();
    correlated_gtp_sessions_.clear();
    correlated_nas_sessions_.clear();
    correlated_rtp_ssrcs_.clear();
    stats_ = Stats{};
}

// ============================================================================
// Matching Helpers
// ============================================================================

bool VolteCorrelator::matchesMsisdn(const std::string& m1, const std::string& m2) {
    if (m1.empty() || m2.empty())
        return false;

    auto n1 = MsisdnNormalizer::normalize(m1);
    auto n2 = MsisdnNormalizer::normalize(m2);

    return MsisdnNormalizer::matches(n1, n2);
}

bool VolteCorrelator::matchesUeIp(const std::string& ip1, const std::string& ip2) {
    if (ip1.empty() || ip2.empty())
        return false;

    // Exact match for IPv4
    if (ip1 == ip2)
        return true;

    // IPv6 prefix match (first 64 bits)
    if (ip1.find(':') != std::string::npos && ip2.find(':') != std::string::npos) {
        // Simplified: compare first 4 groups (64 bits)
        auto prefix1 = ip1.substr(0, ip1.find(':', ip1.find(':') + 1));
        auto prefix2 = ip2.substr(0, ip2.find(':', ip2.find(':') + 1));
        return prefix1 == prefix2;
    }

    return false;
}

bool VolteCorrelator::isWithinTimeWindow(double ts, double start, double end, double tolerance_ms) {
    double tolerance_sec = tolerance_ms / 1000.0;
    return ts >= (start - tolerance_sec) && ts <= (end + tolerance_sec);
}

// ============================================================================
// Indexing Helpers
// ============================================================================

void VolteCorrelator::updateIndices(VolteCallFlow* flow) {
    flow_id_index_[flow->flow_id] = flow;

    addToMsisdnIndex(flow->caller.msisdn, flow);
    addToMsisdnIndex(flow->callee.msisdn, flow);
    if (flow->forward_target) {
        addToMsisdnIndex(flow->forward_target->msisdn, flow);
    }

    if (flow->caller.imsi) {
        addToImsiIndex(*flow->caller.imsi, flow);
    }
    if (flow->callee.imsi) {
        addToImsiIndex(*flow->callee.imsi, flow);
    }
    if (flow->forward_target && flow->forward_target->imsi) {
        addToImsiIndex(*flow->forward_target->imsi, flow);
    }

    addToFrameIndex(flow->frame_numbers, flow);
}

void VolteCorrelator::addToMsisdnIndex(const std::string& msisdn, VolteCallFlow* flow) {
    if (msisdn.empty())
        return;
    auto normalized = MsisdnNormalizer::normalize(msisdn);
    msisdn_index_.insert({normalized.digits_only, flow});
}

void VolteCorrelator::addToImsiIndex(const std::string& imsi, VolteCallFlow* flow) {
    if (imsi.empty())
        return;
    imsi_index_.insert({imsi, flow});
}

void VolteCorrelator::addToFrameIndex(const std::vector<uint32_t>& frames, VolteCallFlow* flow) {
    for (uint32_t frame : frames) {
        frame_index_[frame] = flow;
    }
}

// ============================================================================
// Flow ID Generation
// ============================================================================

std::string VolteCorrelator::generateFlowId(const std::string& sip_call_id, double timestamp) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(6) << timestamp;
    oss << "_V_" << std::hash<std::string>{}(sip_call_id);
    return oss.str();
}

std::string VolteCorrelator::generateFlowIdForResidual(const std::string& protocol,
                                                       const std::string& session_id,
                                                       double timestamp) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(6) << timestamp;
    oss << "_V_" << protocol << "_" << std::hash<std::string>{}(session_id);
    return oss.str();
}

}  // namespace correlation
}  // namespace callflow
