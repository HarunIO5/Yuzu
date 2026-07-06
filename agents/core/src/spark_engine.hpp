#pragma once

/**
 * spark_engine.hpp — SparkEngine, the agent's single detection layer
 * (ADR-0021 Decisions 1 + 3; campaign plan Stage 1).
 *
 * Watchers are multiplexed by MECHANISM, never by rule: this PR ships the
 * timer wheel (one thread servicing every interval, startup, and poll-class
 * spark); the file-notification thread, the event-handle wait pool (TP_WAIT,
 * #1907), and the multiplexed service pump land in the follow-up PRs. Arming
 * is deduped across consumers: two subscriptions to an equal SparkSpec share
 * one watcher entry and one per-spark state (N consumers, 1 watcher).
 *
 * Delivery tiers (contract in spark.hpp):
 *   - Queued  — each registered consumer owns a bounded queue + dispatch
 *               thread. Watchers enqueue without ever blocking: when a queue
 *               is full the OLDEST event is dropped and counted
 *               (queued_dropped_total), so a stuck consumer can neither stall
 *               a watcher nor starve a sibling consumer. Queued handlers may
 *               block, dispatch plugins, do network I/O.
 *   - Inline  — runs synchronously on the watcher thread. Core-internal
 *               (never reachable from the plugin ABI); enforce-class only.
 *               Every inline call is timed — the duration counters
 *               (inline_us_*, inline_over_*) are the ADR §3 watchdog that
 *               feeds the Stage-11 resource gate. SLO is µs-MEDIAN, rare-ms
 *               tolerated (owner decision 2026-07-06).
 *
 * Lifecycle: construct → register consumers / arm sparks (any order) →
 * start() → … → stop(). Single-shot: the engine does not restart after
 * stop(). stop() is prompt — undelivered queued events are dropped and
 * counted, watcher + consumer threads are joined (shutdown-budget kindness).
 *
 * Threading contract for callers: arm/disarm/register/stats are safe from any
 * thread, including from inside a handler. unregister_consumer joins that
 * consumer's thread — never call it from the consumer's own handler.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT
#include <yuzu/agent/spark.hpp>

#include "spark_mechanism.hpp" // ISparkMechanism, register_mechanism
#include "spark_types.hpp"     // DiskReaderFn, SparkFireDecision

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace yuzu::agent {

/// Point-in-time counters, surfaced via heartbeat status_tags by the agent
/// wiring (the agent has no /metrics — the dex/guardian convention).
struct SparkEngineStats {
    std::uint64_t armed_sparks{0};       ///< deduped watcher entries
    std::uint64_t subscriptions{0};      ///< live subscriptions across all armed sparks
    std::uint64_t consumers{0};          ///< registered queued consumers
    std::uint64_t watcher_threads{0};    ///< mechanism threads currently running
    std::uint64_t events_total{0};       ///< spark fires (post-dedup, pre-fan-out)
    std::uint64_t queued_delivered_total{0};
    std::uint64_t queued_dropped_total{0}; ///< bounded-queue overflow + shutdown drops
    std::uint64_t consumer_errors_total{0}; ///< queued handlers that threw
    // Inline-tier watchdog (ADR §3): duration accounting for every inline call.
    std::uint64_t inline_calls_total{0};
    std::uint64_t inline_errors_total{0}; ///< inline handlers that threw (contract breach)
    std::uint64_t inline_us_total{0};
    std::uint64_t inline_us_max{0};
    std::uint64_t inline_over_100us_total{0}; ///< tail counter (p-high proxy)
    std::uint64_t inline_over_10ms_total{0};  ///< scheduler-quantum-class outliers
};

class YUZU_EXPORT SparkEngine {
public:
    using ConsumerId = std::uint64_t;
    using SubscriptionId = std::uint64_t;
    using QueuedHandler = std::function<void(const SparkEvent&)>;
    /// Stage 2 narrows this to (event, enforce-capability) — no dispatcher, no
    /// plugin-host handle, so a plugin call from an inline handler is a
    /// compile error (ADR §3 "enforced, not conventional").
    using InlineHandler = std::function<void(const SparkEvent&)>;

    static constexpr std::size_t kDefaultQueueCap = 1024;
    /// Cadence floor for interval/poll sparks (the TriggerEngine 30 s minimum).
    static constexpr std::uint64_t kMinCadenceMs = 30'000;
    /// A disk spark's FIRST poll runs within this of start — early, but
    /// timer-driven, never at-arm (the dex_win_poll macOS lesson).
    static constexpr std::uint64_t kFirstDiskPollCapMs = 60'000;

    SparkEngine();
    ~SparkEngine();
    SparkEngine(const SparkEngine&) = delete;
    SparkEngine& operator=(const SparkEngine&) = delete;

    /// Register the watch mechanism for an event-driven spark type (File /
    /// Registry / Service). MUST be called before start(). Production wires the
    /// platform factories (make_file_mechanism / make_registry_mechanism);
    /// tests wire a fake. With NO mechanism registered for a type, arm() of
    /// that type is rejected — preserving the spark.hpp invariant "Armed means
    /// a watcher is running". Rejects a null mechanism, a timer-driven type
    /// (interval/startup/disk are the wheel's), a duplicate registration, and
    /// any call after start().
    std::expected<void, std::string>
    register_mechanism(SparkType type, std::unique_ptr<ISparkMechanism> mechanism);

    /// Register a queued consumer. Its dispatch thread starts immediately;
    /// events flow once the engine starts and the consumer arms sparks.
    std::expected<ConsumerId, std::string>
    register_consumer(std::string name, QueuedHandler handler,
                      std::size_t queue_cap = kDefaultQueueCap);

    /// Drop a consumer: disarms its subscriptions, then joins its dispatch
    /// thread. Never call from inside the consumer's own handler (self-join).
    void unregister_consumer(ConsumerId id);

    /// Arm a spark for queued delivery to `consumer`. Dedup: an equal spec
    /// already armed (by anyone) adds a subscription to the existing watcher.
    /// Rejects malformed specs and mechanisms not yet built in this slice
    /// (file / service / registry — PR 1b/1c).
    std::expected<SubscriptionId, std::string> arm(ConsumerId consumer, SparkSpec spec);

    /// Arm a spark for INLINE delivery (see tier contract above). Core-internal.
    std::expected<SubscriptionId, std::string> arm_inline(SparkSpec spec, InlineHandler handler);

    /// Remove one subscription; the watcher itself disarms when its last
    /// subscription goes. Unknown ids are ignored (idempotent).
    void disarm(SubscriptionId id);

    /// Start the mechanism threads. Interval/poll deadlines are (re)based on
    /// the start instant; startup sparks fire immediately. Single-shot.
    void start();

    /// Stop watchers, then consumer dispatch threads (prompt; undelivered
    /// events are dropped + counted). Idempotent.
    void stop();

    [[nodiscard]] bool is_running() const noexcept;

    [[nodiscard]] SparkEngineStats stats() const;

    /// Test seam: substitute the platform disk reader. Set BEFORE start().
    void set_disk_reader_for_test(DiskReaderFn reader);
    /// Test seam: lower the interval/poll cadence floor so tests run in ms.
    /// Set BEFORE any arm().
    void set_cadence_floor_for_test(std::uint64_t floor_ms);

private:
    struct Subscriber {
        SubscriptionId id{0};
        SparkTier tier{SparkTier::Queued};
        ConsumerId consumer{0};  ///< Queued only
        InlineHandler inline_fn; ///< Inline only
        /// Startup sparks only: this subscriber has not yet received its
        /// one-shot. A late subscriber re-schedules the spark, but the fire is
        /// delivered ONLY to still-pending subscribers — an earlier subscriber
        /// never sees "startup" twice.
        bool startup_pending{true};
    };

    /// One deduped armed spark: the spec, its wheel schedule, its per-spark
    /// state, and every subscription fanned out from it.
    struct Armed {
        SparkSpec spec;
        std::uint64_t cadence_ms{0}; ///< floored interval/poll cadence
        std::uint64_t seq{0};
        std::chrono::steady_clock::time_point next_due{};
        bool scheduled{false};    ///< on the wheel (false once a one-shot fired)
        bool disk_latched{false}; ///< Disk sparks: poll-and-latch state
        std::vector<Subscriber> subs;
    };

    struct Consumer {
        std::string name;
        QueuedHandler handler;
        std::size_t cap{kDefaultQueueCap};
        std::mutex mu;
        std::condition_variable cv;
        std::deque<SparkEvent> queue;
        bool stopping{false};
        std::thread thread;
    };

    std::expected<SubscriptionId, std::string> arm_impl(SparkSpec spec, Subscriber sub);
    /// Validate + normalise (cadence flooring). Returns the effective cadence
    /// (0 for the event-driven and startup types, which have no wheel cadence).
    std::expected<std::uint64_t, std::string> validate_and_floor(const SparkSpec& spec) const;
    [[nodiscard]] std::chrono::steady_clock::time_point
    initial_due(const SparkSpec& spec, std::uint64_t cadence_ms,
                std::chrono::steady_clock::time_point now) const;
    /// File / Registry / Service: serviced by a mechanism, never the wheel.
    [[nodiscard]] static bool is_event_driven(SparkType type) noexcept;
    /// The mechanism fire entry point: fan one event-driven fire out to every
    /// subscriber of `key`. Looks the key up + snapshots subs under mu_, then
    /// releases mu_ before delivering (an inline consumer that re-arms takes
    /// mu_ — delivering under it would deadlock). A key disarmed mid-flight is
    /// simply skipped. Distinct from the wheel's commit path, which also owns
    /// reschedule + per-subscriber startup semantics.
    void emit_event(const std::string& key, SparkData data);
    void wheel_loop();
    void deliver(const SparkEvent& ev, const std::vector<Subscriber>& subs);
    void consumer_loop(const std::shared_ptr<Consumer>& consumer);

    // armed sparks + subscription index + wheel state, all under mu_.
    mutable std::mutex mu_;
    std::condition_variable wheel_cv_;
    std::map<std::string, Armed> armed_; ///< by spark_key
    std::map<SubscriptionId, std::string> sub_keys_;
    bool running_{false};
    bool stopped_{false};
    std::thread wheel_thread_;
    std::uint64_t next_id_{1}; ///< shared consumer/subscription id counter

    /// Event-driven watch mechanisms by type. Registered before start(),
    /// structurally stable thereafter (entries never added/removed until
    /// destruction), so a raw pointer captured under mu_ stays valid for any
    /// operation. Mechanism methods (start/watch/unwatch/stop) are ALWAYS
    /// invoked with mu_ released — they may block on OS handle setup.
    std::map<SparkType, std::unique_ptr<ISparkMechanism>> mechanisms_;

    mutable std::mutex consumers_mu_;
    std::map<ConsumerId, std::shared_ptr<Consumer>> consumers_;

    DiskReaderFn disk_reader_; ///< test seam; null = read_disk_level (set before start; the
                               ///< wheel snapshots it once at thread start — set-then-start)
    std::atomic<std::uint64_t> cadence_floor_ms_{kMinCadenceMs}; ///< atomic: read at arm, set by test seam

    // Counters updated outside mu_ (delivery paths) — atomics.
    std::atomic<std::uint64_t> events_total_{0};
    std::atomic<std::uint64_t> queued_delivered_{0};
    std::atomic<std::uint64_t> queued_dropped_{0};
    std::atomic<std::uint64_t> consumer_errors_{0};
    std::atomic<std::uint64_t> inline_calls_{0};
    std::atomic<std::uint64_t> inline_errors_{0};
    std::atomic<std::uint64_t> inline_us_total_{0};
    std::atomic<std::uint64_t> inline_us_max_{0};
    std::atomic<std::uint64_t> inline_over_100us_{0};
    std::atomic<std::uint64_t> inline_over_10ms_{0};
};

} // namespace yuzu::agent
