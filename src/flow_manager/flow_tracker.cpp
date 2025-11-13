#include "flow_manager/flow_tracker.h"
#include "common/logger.h"
#include "common/utils.h"

namespace callflow {

FlowTracker::FlowTracker(const Config& config) : config_(config) {
    LOG_INFO("FlowTracker initialized (max_flows=" << config_.max_flows << ")");
}

void FlowTracker::updateFlow(const PacketMetadata& packet, ProtocolType protocol) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = flows_.find(packet.five_tuple);

    if (it == flows_.end()) {
        // Create new flow
        auto flow = std::make_shared<FlowInfo>();
        flow->five_tuple = packet.five_tuple;
        flow->protocol = protocol;
        flow->first_seen = packet.timestamp;
        flow->last_seen = packet.timestamp;
        flow->packet_count = 1;
        flow->byte_count = packet.packet_length;
        flow->direction = Direction::UNKNOWN;

        flows_[packet.five_tuple] = flow;

        LOG_DEBUG("Created new flow: " << packet.five_tuple.toString()
                  << " proto=" << protocolTypeToString(protocol));
    } else {
        // Update existing flow
        auto& flow = it->second;
        flow->last_seen = packet.timestamp;
        flow->packet_count++;
        flow->byte_count += packet.packet_length;

        // Update protocol if more specific
        if (protocol != ProtocolType::UNKNOWN && flow->protocol == ProtocolType::UNKNOWN) {
            flow->protocol = protocol;
        }
    }
}

std::shared_ptr<FlowInfo> FlowTracker::getFlow(const FiveTuple& ft) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = flows_.find(ft);
    if (it != flows_.end()) {
        return it->second;
    }

    return nullptr;
}

void FlowTracker::setSessionKey(const FiveTuple& ft, const std::string& session_key) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = flows_.find(ft);
    if (it != flows_.end()) {
        it->second->session_key = session_key;
        session_to_flows_[session_key].push_back(ft);

        LOG_DEBUG("Associated flow " << ft.toString() << " with session " << session_key);
    }
}

std::vector<std::shared_ptr<FlowInfo>> FlowTracker::getFlowsBySessionKey(
    const std::string& session_key) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<std::shared_ptr<FlowInfo>> result;

    auto it = session_to_flows_.find(session_key);
    if (it != session_to_flows_.end()) {
        for (const auto& ft : it->second) {
            auto flow_it = flows_.find(ft);
            if (flow_it != flows_.end()) {
                result.push_back(flow_it->second);
            }
        }
    }

    return result;
}

size_t FlowTracker::cleanupExpiredFlows() {
    std::lock_guard<std::mutex> lock(mutex_);

    size_t removed = 0;

    for (auto it = flows_.begin(); it != flows_.end();) {
        if (isFlowExpired(*it->second)) {
            // Remove from session mapping
            if (!it->second->session_key.empty()) {
                auto& flow_list = session_to_flows_[it->second->session_key];
                flow_list.erase(
                    std::remove(flow_list.begin(), flow_list.end(), it->first),
                    flow_list.end());
            }

            it = flows_.erase(it);
            removed++;
        } else {
            ++it;
        }
    }

    if (removed > 0) {
        LOG_INFO("Cleaned up " << removed << " expired flows");
    }

    return removed;
}

size_t FlowTracker::getFlowCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return flows_.size();
}

std::vector<std::shared_ptr<FlowInfo>> FlowTracker::getAllFlows() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<std::shared_ptr<FlowInfo>> result;
    result.reserve(flows_.size());

    for (const auto& [ft, flow] : flows_) {
        result.push_back(flow);
    }

    return result;
}

bool FlowTracker::isFlowExpired(const FlowInfo& flow) const {
    auto now = utils::now();
    auto age_sec = utils::timeDiffMs(flow.last_seen, now) / 1000;

    return age_sec > config_.flow_timeout_sec;
}

}  // namespace callflow
