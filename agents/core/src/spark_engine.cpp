/**
 * spark_engine.cpp — see spark_engine.hpp.
 *
 * Wheel design: a single timer thread scans the armed map for the earliest
 * scheduled deadline and condition-waits until it (or an arm/disarm/stop
 * nudge). Arm/disarm rates are low and armed counts are small (hundreds), so
 * the O(n) scan per wake is deliberately simpler and more robust than a heap
 * with lazy invalidation — revisit only if the resource gate says so.
 *
 * Lock discipline: per-type processing (which may do filesystem I/O for disk
 * reads) and ALL delivery run with mu_ released; state commits re-acquire mu_
 * and re-look-up by key, so a spark disarmed mid-flight is simply skipped.
 * Inline handlers therefore run on the wheel thread WITHOUT mu_ held — an
 * inline handler may safely call arm/disarm/stats.
 */

#include "spark_engine.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <optional>
#include <utility>

namespace yuzu::agent {

namespace {

bool params_match_type(const SparkSpec& spec) {
    switch (spec.type) {
    case SparkType::Interval: return std::holds_alternative<IntervalSparkParams>(spec.params);
    case SparkType::Startup:  return std::holds_alternative<StartupSparkParams>(spec.params);
    case SparkType::Disk:     return std::holds_alternative<DiskSparkParams>(spec.params);
    case SparkType::File:     return std::holds_alternative<FileSparkParams>(spec.params);
    case SparkType::Service:  return std::holds_alternative<ServiceSparkParams>(spec.params);
    case SparkType::Registry: return std::holds_alternative<RegistrySparkParams>(spec.params);
    }
    return false;
}

} // namespace

SparkEngine::SparkEngine() = default;

SparkEngine::~SparkEngine() {
    stop();
}

// ── Consumers ─────────────────────────────────────────────────────────────────

std::expected<SparkEngine::ConsumerId, std::string>
SparkEngine::register_consumer(std::string name, QueuedHandler handler, std::size_t queue_cap) {
    if (!handler)
        return std::unexpected("consumer handler must not be null");
    if (name.empty())
        return std::unexpected("consumer name must not be empty");
    if (queue_cap == 0)
        return std::unexpected("consumer queue_cap must be > 0");

    ConsumerId id = 0;
    {
        std::lock_guard lk(mu_);
        if (stopped_)
            return std::unexpected("engine is stopped");
        id = next_id_++;
    }
    auto consumer = std::make_shared<Consumer>();
    consumer->name = std::move(name);
    consumer->handler = std::move(handler);
    consumer->cap = queue_cap;
    consumer->thread = std::thread([this, consumer] { consumer_loop(consumer); });
    {
        std::lock_guard lk(consumers_mu_);
        consumers_.emplace(id, std::move(consumer));
    }
    return id;
}

void SparkEngine::unregister_consumer(ConsumerId id) {
    // 1) Remove the consumer's subscriptions so no new events are enqueued.
    {
        std::lock_guard lk(mu_);
        for (auto it = armed_.begin(); it != armed_.end();) {
            auto& subs = it->second.subs;
            std::erase_if(subs, [&](const Subscriber& s) {
                if (s.tier == SparkTier::Queued && s.consumer == id) {
                    sub_keys_.erase(s.id);
                    return true;
                }
                return false;
            });
            it = subs.empty() ? armed_.erase(it) : std::next(it);
        }
    }
    // 2) Take the consumer out of the fan-out map, then stop + join its thread.
    std::shared_ptr<Consumer> consumer;
    {
        std::lock_guard lk(consumers_mu_);
        auto it = consumers_.find(id);
        if (it == consumers_.end())
            return;
        consumer = std::move(it->second);
        consumers_.erase(it);
    }
    {
        std::lock_guard lk(consumer->mu);
        consumer->stopping = true;
    }
    consumer->cv.notify_all();
    if (consumer->thread.joinable())
        consumer->thread.join();
}

void SparkEngine::consumer_loop(const std::shared_ptr<Consumer>& consumer) {
    for (;;) {
        SparkEvent ev;
        {
            std::unique_lock lk(consumer->mu);
            consumer->cv.wait(lk, [&] { return consumer->stopping || !consumer->queue.empty(); });
            if (consumer->stopping) {
                // Prompt shutdown: whatever is still queued is dropped + counted
                // rather than delivered late into a tearing-down agent.
                queued_dropped_.fetch_add(consumer->queue.size(), std::memory_order_relaxed);
                consumer->queue.clear();
                return;
            }
            ev = std::move(consumer->queue.front());
            consumer->queue.pop_front();
        }
        try {
            consumer->handler(ev);
            queued_delivered_.fetch_add(1, std::memory_order_relaxed);
        } catch (const std::exception& e) {
            consumer_errors_.fetch_add(1, std::memory_order_relaxed);
            spdlog::warn("SparkEngine: consumer '{}' handler threw on spark '{}': {}",
                         consumer->name, ev.key, e.what());
        } catch (...) {
            consumer_errors_.fetch_add(1, std::memory_order_relaxed);
            spdlog::warn("SparkEngine: consumer '{}' handler threw on spark '{}'", consumer->name,
                         ev.key);
        }
    }
}

// ── Arming ────────────────────────────────────────────────────────────────────

std::expected<std::uint64_t, std::string>
SparkEngine::validate_and_floor(const SparkSpec& spec) const {
    if (!params_match_type(spec))
        return std::unexpected(std::string("spark params do not match type '") +
                               spark_type_token(spec.type) + "'");
    switch (spec.type) {
    case SparkType::Interval: {
        const auto& p = std::get<IntervalSparkParams>(spec.params);
        const std::uint64_t floor = cadence_floor_ms_.load(std::memory_order_relaxed);
        const std::uint64_t eff = std::max(p.interval_ms, floor);
        if (eff != p.interval_ms)
            spdlog::warn("SparkEngine: interval {}ms below the {}ms floor — clamped",
                         p.interval_ms, floor);
        return eff;
    }
    case SparkType::Startup:
        return 0;
    case SparkType::Disk: {
        const auto& p = std::get<DiskSparkParams>(spec.params);
        if (p.path.empty())
            return std::unexpected("disk spark: path must not be empty");
        if (p.used_pct_threshold == 0 || p.used_pct_threshold > 100)
            return std::unexpected("disk spark: used_pct_threshold must be 1..100");
        const std::uint64_t floor = cadence_floor_ms_.load(std::memory_order_relaxed);
        const std::uint64_t eff = std::max(p.poll_ms, floor);
        if (eff != p.poll_ms)
            spdlog::warn("SparkEngine: disk poll {}ms below the {}ms floor — clamped", p.poll_ms,
                         floor);
        return eff;
    }
    case SparkType::File:
    case SparkType::Service:
    case SparkType::Registry:
        return std::unexpected(std::string("spark type '") + spark_type_token(spec.type) +
                               "' mechanism not built yet (Stage-1 PR 1b/1c)");
    }
    return std::unexpected("unknown spark type");
}

std::chrono::steady_clock::time_point
SparkEngine::initial_due(const SparkSpec& spec, std::uint64_t cadence_ms,
                         std::chrono::steady_clock::time_point now) const {
    switch (spec.type) {
    case SparkType::Startup:
        return now; // fire as soon as the wheel runs
    case SparkType::Disk:
        // Early first reading, but timer-driven — never at-arm (macOS lesson).
        return now + std::chrono::milliseconds(std::min(cadence_ms, kFirstDiskPollCapMs));
    default:
        return now + std::chrono::milliseconds(cadence_ms);
    }
}

std::expected<SparkEngine::SubscriptionId, std::string> SparkEngine::arm(ConsumerId consumer,
                                                                         SparkSpec spec) {
    {
        std::lock_guard lk(consumers_mu_);
        if (!consumers_.contains(consumer))
            return std::unexpected("unknown consumer id");
    }
    Subscriber sub;
    sub.tier = SparkTier::Queued;
    sub.consumer = consumer;
    return arm_impl(std::move(spec), std::move(sub));
}

std::expected<SparkEngine::SubscriptionId, std::string>
SparkEngine::arm_inline(SparkSpec spec, InlineHandler handler) {
    if (!handler)
        return std::unexpected("inline handler must not be null");
    Subscriber sub;
    sub.tier = SparkTier::Inline;
    sub.inline_fn = std::move(handler);
    return arm_impl(std::move(spec), std::move(sub));
}

std::expected<SparkEngine::SubscriptionId, std::string> SparkEngine::arm_impl(SparkSpec spec,
                                                                              Subscriber sub) {
    const auto cadence = validate_and_floor(spec);
    if (!cadence)
        return std::unexpected(cadence.error());
    std::string key = spark_key(spec);

    std::lock_guard lk(mu_);
    if (stopped_)
        return std::unexpected("engine is stopped");
    sub.id = next_id_++;
    auto [it, inserted] = armed_.try_emplace(key);
    Armed& armed = it->second;
    if (inserted) {
        armed.spec = std::move(spec);
        armed.cadence_ms = *cadence;
        armed.scheduled = true;
        armed.next_due = initial_due(armed.spec, armed.cadence_ms, std::chrono::steady_clock::now());
        spdlog::info("SparkEngine: armed '{}'", key);
    } else if (armed.spec.type == SparkType::Startup && !armed.scheduled && running_) {
        // A late subscriber to an already-fired startup spark still gets its
        // one-shot: re-schedule so the arm itself is the observable "startup".
        armed.scheduled = true;
        armed.next_due = std::chrono::steady_clock::now();
    }
    const SubscriptionId id = sub.id;
    sub_keys_.emplace(id, key);
    armed.subs.push_back(std::move(sub));
    wheel_cv_.notify_all();
    return id;
}

void SparkEngine::disarm(SubscriptionId id) {
    std::lock_guard lk(mu_);
    auto ki = sub_keys_.find(id);
    if (ki == sub_keys_.end())
        return;
    auto ai = armed_.find(ki->second);
    if (ai != armed_.end()) {
        auto& subs = ai->second.subs;
        std::erase_if(subs, [&](const Subscriber& s) { return s.id == id; });
        if (subs.empty()) {
            spdlog::info("SparkEngine: disarmed '{}' (last subscription gone)", ki->second);
            armed_.erase(ai);
        }
    }
    sub_keys_.erase(ki);
    wheel_cv_.notify_all();
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────

void SparkEngine::start() {
    std::size_t armed_count = 0;
    {
        std::lock_guard lk(mu_);
        if (running_ || stopped_) {
            spdlog::warn("SparkEngine::start() called while {} — ignored",
                         stopped_ ? "stopped" : "already running");
            return;
        }
        running_ = true;
        // Re-base deadlines on the start instant: an interval armed long before
        // start must not fire immediately; a startup spark fires now.
        const auto now = std::chrono::steady_clock::now();
        for (auto& [key, armed] : armed_) {
            if (armed.scheduled)
                armed.next_due = initial_due(armed.spec, armed.cadence_ms, now);
        }
        armed_count = armed_.size();
        wheel_thread_ = std::thread([this] { wheel_loop(); });
    }
    spdlog::info("SparkEngine started ({} spark(s) armed)", armed_count);
}

void SparkEngine::stop() {
    // 1) Stop the watcher side first so nothing new is produced.
    {
        std::lock_guard lk(mu_);
        if (stopped_)
            return;
        stopped_ = true;
        running_ = false;
    }
    wheel_cv_.notify_all();
    if (wheel_thread_.joinable())
        wheel_thread_.join();

    // 2) Stop consumer dispatch threads (prompt; leftovers dropped + counted).
    std::map<ConsumerId, std::shared_ptr<Consumer>> consumers;
    {
        std::lock_guard lk(consumers_mu_);
        consumers.swap(consumers_);
    }
    for (auto& [id, consumer] : consumers) {
        {
            std::lock_guard lk(consumer->mu);
            consumer->stopping = true;
        }
        consumer->cv.notify_all();
        if (consumer->thread.joinable())
            consumer->thread.join();
    }
    spdlog::info("SparkEngine stopped");
}

bool SparkEngine::is_running() const noexcept {
    std::lock_guard lk(mu_);
    return running_;
}

// ── Wheel ─────────────────────────────────────────────────────────────────────

void SparkEngine::wheel_loop() {
    std::unique_lock lk(mu_);
    // Snapshot the disk reader once: the seam contract is set-then-start, and a
    // stable local keeps the processing path data-race-free without mu_.
    const DiskReaderFn disk_reader = disk_reader_;
    while (!stopped_) {
        // Earliest scheduled deadline (O(n) scan — see file header).
        std::optional<std::chrono::steady_clock::time_point> next;
        for (const auto& [key, armed] : armed_) {
            if (armed.scheduled && (!next || armed.next_due < *next))
                next = armed.next_due;
        }
        const auto now = std::chrono::steady_clock::now();
        if (!next) {
            wheel_cv_.wait(lk);
            continue;
        }
        if (*next > now) {
            wheel_cv_.wait_until(lk, *next);
            continue; // re-evaluate: stop / arm / disarm may have changed the world
        }

        // Collect everything due; process + deliver with mu_ RELEASED.
        struct DueItem {
            std::string key;
            SparkSpec spec;
            std::uint64_t cadence_ms{0};
            bool latched{false};
        };
        std::vector<DueItem> due;
        for (auto& [key, armed] : armed_) {
            if (armed.scheduled && armed.next_due <= now)
                due.push_back({key, armed.spec, armed.cadence_ms, armed.disk_latched});
        }
        lk.unlock();
        for (auto& item : due) {
            SparkFireDecision decision;
            switch (item.spec.type) {
            case SparkType::Interval:
                decision = interval_process_due(item.cadence_ms, now);
                break;
            case SparkType::Startup:
                decision = startup_process_due();
                break;
            case SparkType::Disk:
                decision = disk_process_due(std::get<DiskSparkParams>(item.spec.params),
                                            item.cadence_ms, item.latched, disk_reader, now);
                break;
            default:
                continue; // event-driven types never sit on the wheel
            }

            // Commit state; the spark may have been disarmed while we processed.
            std::optional<SparkEvent> event;
            std::vector<Subscriber> subs;
            lk.lock();
            auto it = armed_.find(item.key);
            if (it != armed_.end()) {
                Armed& armed = it->second;
                armed.disk_latched = item.latched;
                if (decision.reschedule)
                    armed.next_due = *decision.reschedule;
                else
                    armed.scheduled = false;
                if (decision.emit) {
                    SparkEvent ev;
                    ev.key = item.key;
                    ev.type = armed.spec.type;
                    ev.seq = ++armed.seq;
                    ev.at = std::chrono::system_clock::now();
                    ev.data = std::move(decision.data);
                    event = std::move(ev);
                    if (armed.spec.type == SparkType::Startup) {
                        // One-shot semantics are PER SUBSCRIBER: deliver only to
                        // those still pending, so a late arm's re-fire can never
                        // hand an earlier subscriber a second "startup".
                        for (auto& s : armed.subs) {
                            if (s.startup_pending) {
                                subs.push_back(s);
                                s.startup_pending = false;
                            }
                        }
                    } else {
                        subs = armed.subs; // fan-out snapshot
                    }
                }
            }
            lk.unlock();
            if (event) {
                events_total_.fetch_add(1, std::memory_order_relaxed);
                deliver(*event, subs);
            }
            lk.lock();
        }
    }
}

// ── Delivery ──────────────────────────────────────────────────────────────────

void SparkEngine::deliver(const SparkEvent& ev, const std::vector<Subscriber>& subs) {
    for (const auto& sub : subs) {
        if (sub.tier == SparkTier::Inline) {
            // ADR §3 watchdog: every inline call is timed; the counters feed the
            // Stage-11 resource gate. Handlers must not throw — but the watcher
            // must survive a contract breach, so catch + count anyway.
            const auto t0 = std::chrono::steady_clock::now();
            try {
                sub.inline_fn(ev);
            } catch (const std::exception& e) {
                inline_errors_.fetch_add(1, std::memory_order_relaxed);
                spdlog::error("SparkEngine: INLINE handler threw on spark '{}' (contract breach): {}",
                              ev.key, e.what());
            } catch (...) {
                inline_errors_.fetch_add(1, std::memory_order_relaxed);
                spdlog::error("SparkEngine: INLINE handler threw on spark '{}' (contract breach)",
                              ev.key);
            }
            const auto us = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - t0)
                    .count());
            inline_calls_.fetch_add(1, std::memory_order_relaxed);
            inline_us_total_.fetch_add(us, std::memory_order_relaxed);
            if (us > 100)
                inline_over_100us_.fetch_add(1, std::memory_order_relaxed);
            if (us > 10'000)
                inline_over_10ms_.fetch_add(1, std::memory_order_relaxed);
            std::uint64_t prev = inline_us_max_.load(std::memory_order_relaxed);
            while (us > prev && !inline_us_max_.compare_exchange_weak(prev, us,
                                                                      std::memory_order_relaxed)) {
            }
            continue;
        }
        // Queued: never block the watcher. Full queue → drop the OLDEST (the
        // consumer keeps seeing the most recent state) and count it.
        std::shared_ptr<Consumer> consumer;
        {
            std::lock_guard lk(consumers_mu_);
            auto it = consumers_.find(sub.consumer);
            if (it != consumers_.end())
                consumer = it->second;
        }
        if (!consumer)
            continue; // consumer unregistered between fan-out snapshot and here
        {
            std::lock_guard lk(consumer->mu);
            if (consumer->stopping)
                continue;
            if (consumer->queue.size() >= consumer->cap) {
                consumer->queue.pop_front();
                queued_dropped_.fetch_add(1, std::memory_order_relaxed);
                spdlog::warn("SparkEngine: consumer '{}' queue full (cap {}) — dropped oldest",
                             consumer->name, consumer->cap);
            }
            consumer->queue.push_back(ev);
        }
        consumer->cv.notify_one();
    }
}

// ── Stats / seams ─────────────────────────────────────────────────────────────

SparkEngineStats SparkEngine::stats() const {
    SparkEngineStats s;
    {
        std::lock_guard lk(mu_);
        s.armed_sparks = armed_.size();
        s.subscriptions = sub_keys_.size();
        s.watcher_threads = running_ ? 1 : 0; // the wheel; mechanisms add theirs in PR 1b/1c
    }
    {
        std::lock_guard lk(consumers_mu_);
        s.consumers = consumers_.size();
    }
    s.events_total = events_total_.load(std::memory_order_relaxed);
    s.queued_delivered_total = queued_delivered_.load(std::memory_order_relaxed);
    s.queued_dropped_total = queued_dropped_.load(std::memory_order_relaxed);
    s.consumer_errors_total = consumer_errors_.load(std::memory_order_relaxed);
    s.inline_calls_total = inline_calls_.load(std::memory_order_relaxed);
    s.inline_errors_total = inline_errors_.load(std::memory_order_relaxed);
    s.inline_us_total = inline_us_total_.load(std::memory_order_relaxed);
    s.inline_us_max = inline_us_max_.load(std::memory_order_relaxed);
    s.inline_over_100us_total = inline_over_100us_.load(std::memory_order_relaxed);
    s.inline_over_10ms_total = inline_over_10ms_.load(std::memory_order_relaxed);
    return s;
}

void SparkEngine::set_disk_reader_for_test(DiskReaderFn reader) {
    std::lock_guard lk(mu_);
    disk_reader_ = std::move(reader);
}

void SparkEngine::set_cadence_floor_for_test(std::uint64_t floor_ms) {
    cadence_floor_ms_.store(floor_ms, std::memory_order_relaxed);
}

} // namespace yuzu::agent
