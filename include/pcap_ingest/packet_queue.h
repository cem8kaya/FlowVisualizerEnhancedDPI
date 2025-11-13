#pragma once

#include "common/types.h"
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <memory>

namespace callflow {

/**
 * Thread-safe packet queue for producer-consumer pattern
 */
class PacketQueue {
public:
    explicit PacketQueue(size_t max_size = 10000);
    ~PacketQueue() = default;

    /**
     * Push a packet onto the queue
     * Blocks if queue is full
     * @return true if pushed, false if queue is closed
     */
    bool push(std::unique_ptr<PacketMetadata> packet);

    /**
     * Try to push a packet onto the queue
     * Does not block
     * @return true if pushed, false if full or closed
     */
    bool tryPush(std::unique_ptr<PacketMetadata> packet);

    /**
     * Pop a packet from the queue
     * Blocks if queue is empty
     * @return packet or nullptr if queue is closed and empty
     */
    std::unique_ptr<PacketMetadata> pop();

    /**
     * Try to pop a packet from the queue
     * Does not block
     * @return packet or nullptr if empty
     */
    std::unique_ptr<PacketMetadata> tryPop();

    /**
     * Close the queue (no more pushes allowed)
     */
    void close();

    /**
     * Check if queue is closed
     */
    bool isClosed() const;

    /**
     * Get current queue size
     */
    size_t size() const;

    /**
     * Get maximum queue size
     */
    size_t maxSize() const { return max_size_; }

    /**
     * Check if queue is empty
     */
    bool empty() const;

    /**
     * Check if queue is full
     */
    bool full() const;

    /**
     * Clear all packets from queue
     */
    void clear();

private:
    std::queue<std::unique_ptr<PacketMetadata>> queue_;
    mutable std::mutex mutex_;
    std::condition_variable cv_not_empty_;
    std::condition_variable cv_not_full_;
    size_t max_size_;
    std::atomic<bool> closed_;

    // Disable copy/move
    PacketQueue(const PacketQueue&) = delete;
    PacketQueue& operator=(const PacketQueue&) = delete;
};

}  // namespace callflow
