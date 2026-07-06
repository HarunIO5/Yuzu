/**
 * test_spark_engine.cpp — SparkEngine core contract (spark_engine.cpp):
 * tier behaviour, arming dedup, consumer isolation, bounded-queue overflow,
 * and lifecycle. Uses the cadence-floor + disk-reader test seams so nothing
 * here waits on a real 30 s cadence or a real volume filling up.
 *
 * Timing style: assertions wait on observed effects with generous deadlines
 * (never "sleep then assert a count is exact") so the suite stays honest under
 * CI load and Defender-induced I/O serialisation (#473 lesson).
 */

#include "spark_engine.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <future>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>

using namespace yuzu::agent;
using namespace std::chrono_literals;

namespace {

constexpr std::uint64_t kGiB = 1024ULL * 1024 * 1024;

/// Poll `pred` until true or the deadline passes. Returns its final value.
template <typename Pred>
bool eventually(Pred pred, std::chrono::milliseconds deadline = 5000ms) {
    const auto until = std::chrono::steady_clock::now() + deadline;
    while (!pred()) {
        if (std::chrono::steady_clock::now() >= until)
            return pred();
        std::this_thread::sleep_for(5ms);
    }
    return true;
}

/// Thread-safe event collector handed to queued consumers.
struct Collector {
    std::mutex mu;
    std::vector<SparkEvent> events;

    SparkEngine::QueuedHandler handler() {
        return [this](const SparkEvent& ev) {
            std::lock_guard lk(mu);
            events.push_back(ev);
        };
    }
    std::size_t count() {
        std::lock_guard lk(mu);
        return events.size();
    }
    SparkEvent at(std::size_t i) {
        std::lock_guard lk(mu);
        return events.at(i);
    }
};

SparkSpec interval_spec(std::uint64_t ms) {
    return SparkSpec{SparkType::Interval, IntervalSparkParams{ms}};
}

} // namespace

TEST_CASE("SparkEngine: interval spark delivers to a queued consumer", "[spark][engine]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);
    Collector got;
    auto consumer = engine.register_consumer("test", got.handler());
    REQUIRE(consumer.has_value());
    auto sub = engine.arm(*consumer, interval_spec(50));
    REQUIRE(sub.has_value());

    engine.start();
    REQUIRE(engine.is_running());
    CHECK(eventually([&] { return got.count() >= 3; }));

    // Events carry the armed key, the type, and a monotonically increasing seq.
    const SparkEvent first = got.at(0);
    CHECK(first.key == spark_key(interval_spec(50)));
    CHECK(first.type == SparkType::Interval);
    CHECK(got.at(1).seq == first.seq + 1);
    CHECK(std::holds_alternative<std::monostate>(first.data));

    engine.stop();
    const auto stats = engine.stats();
    CHECK(stats.events_total >= 3);
    CHECK(stats.queued_delivered_total >= 3);
}

TEST_CASE("SparkEngine: equal specs dedup to one armed spark, fan out to all subscribers",
          "[spark][engine]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);
    Collector a;
    Collector b;
    auto ca = engine.register_consumer("a", a.handler());
    auto cb = engine.register_consumer("b", b.handler());
    REQUIRE(ca.has_value());
    REQUIRE(cb.has_value());
    REQUIRE(engine.arm(*ca, interval_spec(50)).has_value());
    REQUIRE(engine.arm(*cb, interval_spec(50)).has_value());

    CHECK(engine.stats().armed_sparks == 1); // deduped: N consumers, 1 watcher
    CHECK(engine.stats().subscriptions == 2);

    engine.start();
    CHECK(eventually([&] { return a.count() >= 2 && b.count() >= 2; }));
    // One fire, one seq — both consumers observe the SAME event stream.
    CHECK(a.at(0).seq == b.at(0).seq);
    engine.stop();
}

TEST_CASE("SparkEngine: startup spark fires once; late arm still fires once",
          "[spark][engine]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);
    Collector got;
    auto consumer = engine.register_consumer("test", got.handler());
    REQUIRE(consumer.has_value());
    const SparkSpec startup{SparkType::Startup, StartupSparkParams{}};
    REQUIRE(engine.arm(*consumer, startup).has_value());

    engine.start();
    CHECK(eventually([&] { return got.count() >= 1; }));
    std::this_thread::sleep_for(100ms); // one-shot: give a re-fire the chance to (not) happen
    CHECK(got.count() == 1);
    CHECK(got.at(0).type == SparkType::Startup);

    // A late subscriber to the SAME startup spec still gets its one-shot —
    // and the earlier subscriber does NOT see "startup" a second time.
    Collector late;
    auto late_consumer = engine.register_consumer("late", late.handler());
    REQUIRE(late_consumer.has_value());
    REQUIRE(engine.arm(*late_consumer, startup).has_value());
    CHECK(eventually([&] { return late.count() >= 1; }));
    std::this_thread::sleep_for(100ms);
    CHECK(late.count() == 1);
    CHECK(got.count() == 1);

    engine.stop();
}

TEST_CASE("SparkEngine: disk spark emits breach and recovery edges through the wheel",
          "[spark][engine][disk]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);
    std::atomic<bool> healthy{true};
    engine.set_disk_reader_for_test([&](const std::string&) {
        DiskReading r;
        r.valid = true;
        r.total_bytes = 100 * kGiB;
        r.free_bytes = healthy.load() ? 50 * kGiB : 1 * kGiB;
        return r;
    });
    Collector got;
    auto consumer = engine.register_consumer("dex-ish", got.handler());
    REQUIRE(consumer.has_value());
    SparkSpec spec{SparkType::Disk, DiskSparkParams{"/", 90, 5 * kGiB, 20}};
    REQUIRE(engine.arm(*consumer, spec).has_value());

    engine.start();
    // Healthy polls emit nothing; flip to bad → exactly one Breach.
    healthy = false;
    CHECK(eventually([&] { return got.count() >= 1; }));
    const SparkEvent breach_ev = got.at(0);
    const auto* breach = std::get_if<DiskSparkData>(&breach_ev.data);
    REQUIRE(breach != nullptr);
    CHECK(breach->edge == DiskEdge::Breach);

    // Back to healthy → exactly one Recovery.
    healthy = true;
    CHECK(eventually([&] { return got.count() >= 2; }));
    const SparkEvent recovery_ev = got.at(1);
    const auto* recovery = std::get_if<DiskSparkData>(&recovery_ev.data);
    REQUIRE(recovery != nullptr);
    CHECK(recovery->edge == DiskEdge::Recovery);

    // No further edges while steady.
    std::this_thread::sleep_for(150ms);
    CHECK(got.count() == 2);
    engine.stop();
}

TEST_CASE("SparkEngine: a stuck queued consumer stalls neither watchers nor siblings",
          "[spark][engine][isolation]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);

    std::promise<void> unstick;
    std::shared_future<void> unstick_f = unstick.get_future().share();
    std::atomic<int> stuck_calls{0};
    auto stuck = engine.register_consumer("stuck", [&](const SparkEvent&) {
        ++stuck_calls;
        unstick_f.wait(); // deliberately blocked (a popup open for minutes)
    });
    Collector healthy;
    auto ok = engine.register_consumer("healthy", healthy.handler());
    REQUIRE(stuck.has_value());
    REQUIRE(ok.has_value());
    REQUIRE(engine.arm(*stuck, interval_spec(30)).has_value());
    REQUIRE(engine.arm(*ok, interval_spec(30)).has_value());

    engine.start();
    CHECK(eventually([&] { return stuck_calls.load() >= 1; }));
    // The stuck consumer is wedged in its first event — the sibling keeps
    // receiving, which also proves the WATCHER thread never blocked.
    const auto before = healthy.count();
    CHECK(eventually([&] { return healthy.count() >= before + 3; }));

    unstick.set_value(); // release before stop() so the join can complete
    engine.stop();
}

TEST_CASE("SparkEngine: full queue drops oldest and counts, never blocks",
          "[spark][engine][isolation]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);

    std::promise<void> unstick;
    std::shared_future<void> unstick_f = unstick.get_future().share();
    std::atomic<int> calls{0};
    auto consumer = engine.register_consumer(
        "slow",
        [&](const SparkEvent&) {
            ++calls;
            unstick_f.wait();
        },
        /*queue_cap=*/2);
    REQUIRE(consumer.has_value());
    REQUIRE(engine.arm(*consumer, interval_spec(20)).has_value());

    engine.start();
    CHECK(eventually([&] { return calls.load() >= 1; }));
    // Handler wedged: the queue (cap 2) must overflow and drop rather than
    // block the wheel.
    CHECK(eventually([&] { return engine.stats().queued_dropped_total >= 2; }));

    unstick.set_value();
    engine.stop();
}

TEST_CASE("SparkEngine: inline tier runs on the watcher thread and is duration-accounted",
          "[spark][engine][inline]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);
    // No Catch2 assertions inside the handler — it runs on the watcher thread
    // and Catch2 macros are not thread-safe. Capture, assert on the main thread.
    std::atomic<int> inline_calls{0};
    std::atomic<bool> type_ok{true};
    auto sub = engine.arm_inline(interval_spec(30), [&](const SparkEvent& ev) {
        const int n = ++inline_calls;
        if (ev.type != SparkType::Interval)
            type_ok = false;
        if (n == 1)
            std::this_thread::sleep_for(2ms); // make the watchdog measurably time a call
        if (n == 2)
            throw std::runtime_error("contract breach"); // watcher must survive
    });
    REQUIRE(sub.has_value());

    engine.start();
    CHECK(eventually([&] { return inline_calls.load() >= 4; })); // survived the throw
    engine.stop();

    CHECK(type_ok.load());
    const auto stats = engine.stats();
    CHECK(stats.inline_calls_total >= 4);
    CHECK(stats.inline_errors_total == 1);
    CHECK(stats.inline_us_max >= 1000);      // the 2ms call was actually timed
    CHECK(stats.inline_over_100us_total >= 1); // ...and hit the tail counter
}

TEST_CASE("SparkEngine: disarm stops delivery; last disarm removes the watcher entry",
          "[spark][engine]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);
    Collector got;
    auto consumer = engine.register_consumer("test", got.handler());
    REQUIRE(consumer.has_value());
    auto sub = engine.arm(*consumer, interval_spec(30));
    REQUIRE(sub.has_value());

    engine.start();
    CHECK(eventually([&] { return got.count() >= 1; }));
    engine.disarm(*sub);
    CHECK(engine.stats().armed_sparks == 0);
    // Let anything already in-queue at disarm time drain before baselining.
    std::this_thread::sleep_for(50ms);
    const auto after = got.count();
    std::this_thread::sleep_for(150ms);
    CHECK(got.count() == after); // nothing delivered after disarm
    engine.disarm(*sub);         // idempotent
    engine.stop();
}

TEST_CASE("SparkEngine: arming validation", "[spark][engine]") {
    SparkEngine engine;
    Collector got;
    auto consumer = engine.register_consumer("test", got.handler());
    REQUIRE(consumer.has_value());

    // Unknown consumer.
    CHECK_FALSE(engine.arm(9999, interval_spec(60'000)).has_value());

    // Mechanisms not in this slice are rejected loudly, not silently inert.
    CHECK_FALSE(engine.arm(*consumer, SparkSpec{SparkType::File, FileSparkParams{"/etc/hosts"}})
                    .has_value());
    CHECK_FALSE(
        engine.arm(*consumer, SparkSpec{SparkType::Service, ServiceSparkParams{"sshd"}})
            .has_value());
    CHECK_FALSE(engine
                    .arm(*consumer,
                         SparkSpec{SparkType::Registry, RegistrySparkParams{"HKLM", "SOFTWARE"}})
                    .has_value());

    // Type/params mismatch.
    CHECK_FALSE(
        engine.arm(*consumer, SparkSpec{SparkType::Disk, IntervalSparkParams{60'000}}).has_value());

    // Disk param sanity.
    CHECK_FALSE(engine.arm(*consumer, SparkSpec{SparkType::Disk, DiskSparkParams{"", 90, 0, 0}})
                    .has_value());
    CHECK_FALSE(
        engine.arm(*consumer, SparkSpec{SparkType::Disk, DiskSparkParams{"/", 101, 0, 0}})
            .has_value());

    // Null handlers / empty names.
    CHECK_FALSE(engine.register_consumer("x", nullptr).has_value());
    CHECK_FALSE(engine.register_consumer("", got.handler()).has_value());
    CHECK_FALSE(engine.arm_inline(interval_spec(60'000), nullptr).has_value());
}

TEST_CASE("SparkEngine: unregister_consumer removes its subscriptions and joins its thread",
          "[spark][engine]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);
    Collector a;
    Collector b;
    auto ca = engine.register_consumer("a", a.handler());
    auto cb = engine.register_consumer("b", b.handler());
    REQUIRE(ca.has_value());
    REQUIRE(cb.has_value());
    REQUIRE(engine.arm(*ca, interval_spec(30)).has_value());
    REQUIRE(engine.arm(*cb, interval_spec(30)).has_value());

    engine.start();
    CHECK(eventually([&] { return a.count() >= 1 && b.count() >= 1; }));
    engine.unregister_consumer(*ca);
    CHECK(engine.stats().consumers == 1);
    CHECK(engine.stats().subscriptions == 1); // a's subscription went with it
    CHECK(engine.stats().armed_sparks == 1);  // b still holds the shared spark

    const auto a_after = a.count();
    const auto b_before = b.count();
    CHECK(eventually([&] { return b.count() >= b_before + 2; })); // b unaffected
    CHECK(a.count() == a_after);
    engine.stop();
}

TEST_CASE("SparkEngine: stop is prompt and idempotent; engine is single-shot",
          "[spark][engine]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);
    Collector got;
    auto consumer = engine.register_consumer("test", got.handler());
    REQUIRE(consumer.has_value());
    REQUIRE(engine.arm(*consumer, interval_spec(30)).has_value());

    engine.start();
    CHECK(eventually([&] { return got.count() >= 1; }));
    engine.stop();
    CHECK_FALSE(engine.is_running());
    engine.stop(); // idempotent

    // Single-shot: a restart attempt is refused, and post-stop arms fail.
    engine.start();
    CHECK_FALSE(engine.is_running());
    CHECK_FALSE(engine.arm(*consumer, interval_spec(30)).has_value());
    CHECK_FALSE(engine.register_consumer("post-stop", got.handler()).has_value());
}
