#include "nvd_sync.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <format>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
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

// NVD's first CVEs are from 1999; anything older than 2000 in a cursor is
// corruption, not a legitimate position. Rejecting it prevents a garbage/negative
// sync_meta value from parsing to ~1970 and either false-completing the backfill
// (cursor <= floor) or livelocking it (governance UP-3/UP-4).
constexpr long long kMinSaneEpochSecs = 946684800; // 2000-01-01T00:00:00Z

// Cursors are stored in sync_meta as epoch-seconds strings (no ISO parsing —
// avoids std::chrono::parse portability differences). Malformed/empty/insane →
// nullopt (caller restarts from `now`, which is idempotent).
std::optional<std::chrono::system_clock::time_point> parse_cursor(const std::string& s) {
    if (s.empty())
        return std::nullopt;
    try {
        const long long v = std::stoll(s);
        if (v < kMinSaneEpochSecs)
            return std::nullopt;
        return std::chrono::system_clock::time_point{std::chrono::seconds{v}};
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
    // On the detach path stop() returns false; the owner (ServerImpl::stop())
    // releases the unique_ptr so the dtor normally doesn't run there. Discard.
    (void)stop();
}

void NvdSyncManager::start() {
    if (sync_thread_.joinable()) {
        return; // already running
    }
    // Note: restarting after a stop() that DETACHED (returned false) would reset
    // stopping_/finished_ while the abandoned thread still runs — but ServerImpl
    // release()es the manager on that path and never restarts it, so this is
    // unreachable in production.
    stopping_.store(false);
    finished_.store(false);
#ifdef __cpp_lib_jthread
    sync_thread_ = std::jthread([this](std::stop_token stop) { sync_loop(stop); });
#else
    stop_requested_ = false;
    sync_thread_ = std::thread([this] { sync_loop(); });
#endif
    spdlog::info("NVD sync manager started (interval={}s, backfill={}y)", interval_.count(),
                 backfill_years_);
}

bool NvdSyncManager::stop() {
    if (!sync_thread_.joinable()) {
        return true; // never started or already cleanly stopped — safe to destroy
    }
    stopping_.store(true); // cooperative: abort a long backfill/freshness pass between windows
#ifdef __cpp_lib_jthread
    sync_thread_.request_stop();
#else
    stop_requested_ = true;
#endif
    {
        std::lock_guard<std::mutex> lock{mu_};
        cv_.notify_all();
    }

    // #1867 bounded join. Cooperative cancellation (stopping_) aborts between
    // windows, but a fetch wedged mid-page (see #1879) can still take a while;
    // wait a short grace for a clean exit, then detach + signal the owner to LEAK
    // this manager (ServerImpl::stop()) rather than hang shutdown or UAF freed
    // members from the abandoned thread.
    constexpr auto kGrace = std::chrono::seconds(5);
    const auto deadline = std::chrono::steady_clock::now() + kGrace;
    while (!finished_.load() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    if (finished_.load()) {
        sync_thread_.join();
        spdlog::info("NVD sync manager stopped");
        return true;
    }
    spdlog::warn("NVD sync thread did not exit within {}s (stuck in a fetch?); detaching + leaking "
                 "the manager to avoid wedging shutdown / a teardown UAF (see #1867)",
                 kGrace.count());
    sync_thread_.detach();
    return false;
}

void NvdSyncManager::sync_now() {
    do_sync();
}

void NvdSyncManager::request_sync() {
    {
        std::lock_guard<std::mutex> lock{mu_};
        sync_requested_ = true;
    }
    cv_.notify_all(); // wake the loop; it owns the sync so nothing outlives us
}

NvdSyncManager::SyncStatus NvdSyncManager::status() const {
    std::lock_guard<std::mutex> lock{mu_};
    SyncStatus st = status_;
    // Surface backfill progress (cpp/consistency S1 + sre): the store is the
    // source of truth for completion + the newest-first cursor.
    st.backfill_complete = db_->get_meta("backfill_complete") == "1";
    if (auto cur = parse_cursor(db_->get_meta("backfill_oldest_published")))
        st.backfill_oldest_published = iso_of(*cur);
    // Survive restart: last_sync_time lives in meta, not just memory (S1).
    if (st.last_sync_time.empty())
        st.last_sync_time = db_->get_meta("last_sync_time");
    return st;
}

bool NvdSyncManager::backfill_complete() const {
    // Defensive: this is called from the sync_loop header (outside do_sync's
    // try/catch), so a throwing SQLite read must not escape the thread and
    // std::terminate the process. Treat an unreadable flag as "not complete"
    // (safe default — keeps backfilling; do_sync's catch logs the real error).
    try {
        return db_->get_meta("backfill_complete") == "1";
    } catch (const std::exception& e) {
        spdlog::warn("NVD backfill_complete() meta read failed: {} (assuming not complete)",
                     e.what());
        return false;
    }
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
        cv_.wait_for(lock, wait, [&] { return stop.stop_requested() || sync_requested_; });
        if (stop.stop_requested())
            break;
#else
        cv_.wait_for(lock, wait,
                     [this] { return stop_requested_.load() || sync_requested_; });
        if (stop_requested_.load())
            break;
#endif
        sync_requested_ = false; // consume an on-demand request (request_sync)
        lock.unlock();
        do_sync();
    }

    // Signal a clean exit so stop() can join() within its grace instead of
    // detaching (#1867).
    finished_.store(true);
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
        const auto count = db_->total_cve_count(); // off the status lock (cpp-safety)
        std::lock_guard<std::mutex> lock{mu_};
        status_.total_cves = count;
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
    // Clamp to `now`: a future cursor (clock skew) would otherwise ask NVD for a
    // future window forever (livelock, UP-4). A missing/insane cursor restarts
    // from `now` — idempotent (re-fetch), so no corruption, just repeated work.
    auto cursor = std::min(parse_cursor(db_->get_meta("backfill_oldest_published")).value_or(now),
                           now);

    // On a fresh backfill start, pin the freshness cursor to now so that after a
    // multi-day backfill the first freshness pass re-checks everything modified
    // *during* the build, not just the last 2 days (UP-6).
    if (db_->get_meta("last_freshness_check").empty())
        db_->set_meta("last_freshness_check", std::to_string(epoch_secs(now)));

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
        db_->set_meta("last_sync_time", iso_of(now)); // persist so status survives restart (S1)
        // Compute the count OUTSIDE the status lock so a concurrent status()
        // reader never blocks on a SQLite query (cpp-safety SHOULD).
        const auto count = db_->total_cve_count();
        {
            std::lock_guard<std::mutex> lock{mu_};
            status_.total_cves = count;
            status_.last_sync_time = iso_of(now);
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

    db_->set_meta("last_sync_time", iso_of(now)); // persist for restart (S1)
    const auto count = db_->total_cve_count();     // off the status lock (cpp-safety)
    {
        std::lock_guard<std::mutex> lock{mu_};
        status_.total_cves = count;
        status_.last_sync_time = iso_of(now);
    }
    spdlog::info("NVD freshness re-check complete — {} CVEs updated", total);
}

} // namespace yuzu::server
