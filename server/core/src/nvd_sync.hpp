#pragma once

#include "nvd_client.hpp"
#include "nvd_db.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace yuzu::server {

class NvdSyncManager {
public:
    // Production: builds an NvdClient as the fetcher. backfill_years bounds how
    // far back the newest-first backfill walks (0 = full history to NVD's start).
    NvdSyncManager(std::shared_ptr<NvdDatabase> db, std::string api_key, std::string proxy_url,
                   std::chrono::seconds sync_interval, int backfill_years = 8);
    // Test: inject a mock fetcher (no network).
    NvdSyncManager(std::shared_ptr<NvdDatabase> db, std::unique_ptr<INvdFetcher> fetcher,
                   std::chrono::seconds sync_interval, int backfill_years);
    ~NvdSyncManager();

    NvdSyncManager(const NvdSyncManager&) = delete;
    NvdSyncManager& operator=(const NvdSyncManager&) = delete;

    void start(); // Start background sync thread
    void stop();  // Signal stop and join thread

    // Manual sync (blocks until complete)
    void sync_now();

    // Status info for UI
    struct SyncStatus {
        bool syncing = false;
        std::string last_sync_time; // ISO 8601 or empty
        std::size_t total_cves = 0;
        std::string last_error;
    };
    SyncStatus status() const;

private:
    std::shared_ptr<NvdDatabase> db_;
    std::unique_ptr<INvdFetcher> fetcher_;
    std::chrono::seconds interval_;
    int backfill_years_;

#ifdef __cpp_lib_jthread
    std::jthread sync_thread_;
#else
    std::thread sync_thread_;
    std::atomic<bool> stop_requested_{false};
#endif
    mutable std::mutex mu_;
    std::condition_variable cv_;
    SyncStatus status_;
    // Serialises do_sync(): the periodic loop and the detached POST /api/nvd/sync
    // thread both call it on the same fetcher; running two concurrently races
    // the client's rate-limit state and doubles NVD load (#1867 governance).
    std::atomic<bool> sync_active_{false};
    // Set by stop() so a long backfill/freshness pass aborts between windows
    // (cooperative cancellation — #1867 fix #2). Checked in do_backfill/do_freshness.
    std::atomic<bool> stopping_{false};

#ifdef __cpp_lib_jthread
    void sync_loop(std::stop_token stop);
#else
    void sync_loop();
#endif
    void do_sync();
    void do_backfill();  // newest-first publish-window catalog build (cursor-resumable)
    void do_freshness(); // periodic lastMod re-check once backfill reaches the floor
    bool backfill_complete() const;
};

} // namespace yuzu::server
