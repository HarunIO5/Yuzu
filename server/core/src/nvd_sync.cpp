#include "nvd_sync.hpp"

#include <spdlog/spdlog.h>

#include <chrono>
#include <format>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>

namespace yuzu::server {

namespace {

// NVD 2.0 accepts ISO-8601 date/times with millisecond precision and implicit
// UTC (no suffix), e.g. "2024-01-01T00:00:00.000".
std::string iso_of(std::chrono::system_clock::time_point tp) {
    return std::format("{:%Y-%m-%dT%H:%M:%S}.000", std::chrono::floor<std::chrono::seconds>(tp));
}

long long epoch_secs(std::chrono::system_clock::time_point tp) {
    return std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count();
}

// Cursors are stored in sync_meta as epoch-seconds strings (no ISO parsing —
// avoids std::chrono::parse portability differences). Malformed/empty → nullopt.
std::optional<std::chrono::system_clock::time_point> parse_cursor(const std::string& s) {
    if (s.empty())
        return std::nullopt;
    try {
        return std::chrono::system_clock::time_point{std::chrono::seconds{std::stoll(s)}};
    } catch (...) {
        return std::nullopt;
    }
}

} // namespace

NvdSyncManager::NvdSyncManager(std::shared_ptr<NvdDatabase> db, std::string api_key,
                               std::string proxy_url, std::chrono::seconds sync_interval,
                               int backfill_years)
    : db_{std::move(db)}, fetcher_{std::make_unique<NvdClient>(std::move(api_key),
                                                               std::move(proxy_url))},
      interval_{sync_interval}, backfill_years_{backfill_years} {}

NvdSyncManager::NvdSyncManager(std::shared_ptr<NvdDatabase> db,
                               std::unique_ptr<INvdFetcher> fetcher,
                               std::chrono::seconds sync_interval, int backfill_years)
    : db_{std::move(db)}, fetcher_{std::move(fetcher)}, interval_{sync_interval},
      backfill_years_{backfill_years} {}

NvdSyncManager::~NvdSyncManager() {
    stop();
}

void NvdSyncManager::start() {
    if (sync_thread_.joinable()) {
        return; // already running
    }
    stopping_.store(false);
#ifdef __cpp_lib_jthread
    sync_thread_ = std::jthread([this](std::stop_token stop) { sync_loop(stop); });
#else
    stop_requested_ = false;
    sync_thread_ = std::thread([this] { sync_loop(); });
#endif
    spdlog::info("NVD sync manager started (interval={}s, backfill={}y)", interval_.count(),
                 backfill_years_);
}

void NvdSyncManager::stop() {
    if (!sync_thread_.joinable()) {
        return;
    }
    stopping_.store(true); // abort a long backfill/freshness pass between windows
#ifdef __cpp_lib_jthread
    sync_thread_.request_stop();
#else
    stop_requested_ = true;
#endif
    {
        std::lock_guard<std::mutex> lock{mu_};
        cv_.notify_all();
    }
    sync_thread_.join();
    spdlog::info("NVD sync manager stopped");
}

void NvdSyncManager::sync_now() {
    do_sync();
}

NvdSyncManager::SyncStatus NvdSyncManager::status() const {
    std::lock_guard<std::mutex> lock{mu_};
    return status_;
}

bool NvdSyncManager::backfill_complete() const {
    return db_->get_meta("backfill_complete") == "1";
}

#ifdef __cpp_lib_jthread
void NvdSyncManager::sync_loop(std::stop_token stop) {
#else
void NvdSyncManager::sync_loop() {
#endif
    // Seed built-in rules on first run (offline fallback).
    try {
        db_->seed_builtin_rules();
        spdlog::info("NVD built-in rules seeded");
    } catch (const std::exception& e) {
        spdlog::error("Failed to seed built-in rules: {}", e.what());
    }

    // Immediate first sync (runs the backfill until the floor, or freshness).
    do_sync();

    while (true) {
        // While the catalog is still backfilling, retry soon (a failed window
        // shouldn't wait the full freshness interval); once complete, settle to
        // the periodic freshness cadence.
        std::chrono::seconds wait = interval_;
        if (!backfill_complete() && interval_ > std::chrono::seconds{60}) {
            wait = std::chrono::seconds{60};
        }

        std::unique_lock<std::mutex> lock{mu_};
#ifdef __cpp_lib_jthread
        cv_.wait_for(lock, wait, [&stop] { return stop.stop_requested(); });
        if (stop.stop_requested())
            break;
#else
        cv_.wait_for(lock, wait, [this] { return stop_requested_.load(); });
        if (stop_requested_.load())
            break;
#endif
        lock.unlock();
        do_sync();
    }
}

void NvdSyncManager::do_sync() {
    // Reject a concurrent sync (periodic loop vs. detached "Sync now"): running
    // two on the same fetcher races the client's rate-limit state and doubles
    // NVD load (#1867 governance).
    bool expected = false;
    if (!sync_active_.compare_exchange_strong(expected, true)) {
        spdlog::info("NVD sync already in progress — skipping this trigger");
        return;
    }
    struct ActiveGuard {
        std::atomic<bool>& flag;
        ~ActiveGuard() { flag.store(false); }
    } active_guard{sync_active_};

    {
        std::lock_guard<std::mutex> lock{mu_};
        status_.syncing = true;
        status_.last_error.clear();
    }

    try {
        if (backfill_complete()) {
            do_freshness();
        } else {
            do_backfill();
        }
        std::lock_guard<std::mutex> lock{mu_};
        status_.total_cves = db_->total_cve_count();
        status_.syncing = false;
    } catch (const std::exception& e) {
        spdlog::error("NVD sync failed: {}", e.what());
        std::lock_guard<std::mutex> lock{mu_};
        status_.last_error = e.what();
        status_.syncing = false;
    }
}

void NvdSyncManager::do_backfill() {
    const auto now = std::chrono::system_clock::now();
    // backfill_years <= 0 means "full history"; 100y back covers NVD's start.
    const int years = backfill_years_ <= 0 ? 100 : backfill_years_;
    const auto floor = now - std::chrono::years(years);
    const auto max_window = std::chrono::days(120); // NVD caps a pub/lastMod range at 120 days

    // Resume from the oldest published date reached so far (newest-first walk).
    auto cursor = parse_cursor(db_->get_meta("backfill_oldest_published")).value_or(now);
    std::size_t total = 0;

    while (cursor > floor && !stopping_.load()) {
        const auto window_start = (cursor - floor > max_window) ? cursor - max_window : floor;
        spdlog::info("NVD backfill: published {} .. {}", iso_of(window_start), iso_of(cursor));

        auto result = fetcher_->fetch_by_published_window(iso_of(window_start), iso_of(cursor));
        if (!result.ok) {
            // Transient error — leave the cursor so the next tick retries this
            // window rather than skipping unfetched CVEs (#1875).
            spdlog::warn("NVD backfill window failed — will retry next tick (cursor unchanged)");
            return;
        }
        if (!result.records.empty()) {
            db_->upsert_cves(result.records);
            total += result.records.size();
        }
        cursor = window_start;
        db_->set_meta("backfill_oldest_published", std::to_string(epoch_secs(cursor)));
        {
            std::lock_guard<std::mutex> lock{mu_};
            status_.total_cves = db_->total_cve_count();
        }
    }

    if (cursor <= floor) {
        db_->set_meta("backfill_complete", "1");
        spdlog::info("NVD backfill complete — floor reached ({} CVEs upserted this pass)", total);
    }
}

void NvdSyncManager::do_freshness() {
    const auto now = std::chrono::system_clock::now();
    const auto max_window = std::chrono::days(120);

    // Re-check everything modified since the last freshness pass, split into
    // <=120-day windows (fixes the >120-day incremental-range error).
    const auto start =
        parse_cursor(db_->get_meta("last_freshness_check")).value_or(now - std::chrono::days(2));
    std::size_t total = 0;

    for (const auto& [ws, we] : nvd_split_windows(start, now, max_window)) {
        if (stopping_.load())
            return;
        auto result = fetcher_->fetch_modified_between(iso_of(ws), iso_of(we));
        if (!result.ok) {
            spdlog::warn("NVD freshness window failed — will retry (cursor unchanged)");
            return;
        }
        if (!result.records.empty()) {
            db_->upsert_cves(result.records);
            total += result.records.size();
        }
        // Advance only after a successful window.
        db_->set_meta("last_freshness_check", std::to_string(epoch_secs(we)));
    }

    {
        std::lock_guard<std::mutex> lock{mu_};
        status_.total_cves = db_->total_cve_count();
        status_.last_sync_time = iso_of(now);
    }
    spdlog::info("NVD freshness re-check complete — {} CVEs updated", total);
}

} // namespace yuzu::server
