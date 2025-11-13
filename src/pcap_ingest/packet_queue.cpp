#include "pcap_ingest/packet_queue.h"

namespace callflow {

PacketQueue::PacketQueue(size_t max_size)
    : max_size_(max_size), closed_(false) {}

bool PacketQueue::push(std::unique_ptr<PacketMetadata> packet) {
    if (!packet) {
        return false;
    }

    std::unique_lock<std::mutex> lock(mutex_);

    // Wait until queue is not full or closed
    cv_not_full_.wait(lock, [this]() {
        return queue_.size() < max_size_ || closed_.load();
    });

    if (closed_.load()) {
        return false;
    }

    queue_.push(std::move(packet));
    cv_not_empty_.notify_one();
    return true;
}

bool PacketQueue::tryPush(std::unique_ptr<PacketMetadata> packet) {
    if (!packet) {
        return false;
    }

    std::unique_lock<std::mutex> lock(mutex_);

    if (queue_.size() >= max_size_ || closed_.load()) {
        return false;
    }

    queue_.push(std::move(packet));
    cv_not_empty_.notify_one();
    return true;
}

std::unique_ptr<PacketMetadata> PacketQueue::pop() {
    std::unique_lock<std::mutex> lock(mutex_);

    // Wait until queue is not empty or closed
    cv_not_empty_.wait(lock, [this]() {
        return !queue_.empty() || closed_.load();
    });

    if (queue_.empty()) {
        return nullptr;  // Queue is closed and empty
    }

    auto packet = std::move(queue_.front());
    queue_.pop();
    cv_not_full_.notify_one();
    return packet;
}

std::unique_ptr<PacketMetadata> PacketQueue::tryPop() {
    std::unique_lock<std::mutex> lock(mutex_);

    if (queue_.empty()) {
        return nullptr;
    }

    auto packet = std::move(queue_.front());
    queue_.pop();
    cv_not_full_.notify_one();
    return packet;
}

void PacketQueue::close() {
    closed_.store(true);
    cv_not_empty_.notify_all();
    cv_not_full_.notify_all();
}

bool PacketQueue::isClosed() const {
    return closed_.load();
}

size_t PacketQueue::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
}

bool PacketQueue::empty() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.empty();
}

bool PacketQueue::full() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size() >= max_size_;
}

void PacketQueue::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    while (!queue_.empty()) {
        queue_.pop();
    }
    cv_not_full_.notify_all();
}

}  // namespace callflow
