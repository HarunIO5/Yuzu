/**
 * test_spark_mechanism.cpp — the event-driven mechanism seam (spark_mechanism.hpp
 * + the SparkEngine File/Registry arm path). A FakeMechanism stands in for the
 * Windows IOCP / TP_WAIT impls so the WHOLE arm / dedup / fan-out / disarm-
 * teardown / lifecycle path is exercised on ANY platform — the point of the
 * seam (the real mechanisms compile Windows-only; the plumbing is tested here).
 *
 * The two Windows mechanism bodies (spark_file.cpp / spark_registry.cpp) are
 * validated by a DGRHP compile pass + their own resilience tests; this file
 * owns the cross-platform contract.
 */

#include "spark_engine.hpp"
#include "spark_mechanism.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

using namespace yuzu::agent;
using namespace std::chrono_literals;

namespace {

template <typename Pred> bool eventually(Pred pred, std::chrono::milliseconds deadline = 5000ms) {
    const auto until = std::chrono::steady_clock::now() + deadline;
    while (!pred()) {
        if (std::chrono::steady_clock::now() >= until)
            return pred();
        std::this_thread::sleep_for(5ms);
    }
    return true;
}

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

/// A cross-platform stand-in for the Windows watch mechanisms. Records the
/// engine's watch/unwatch/start/stop calls and lets a test drive a fire.
class FakeMechanism final : public ISparkMechanism {
public:
    void start(SparkEmitFn emit, SparkFaultFn fault) override {
        std::lock_guard lk(mu_);
        emit_ = std::move(emit);
        fault_ = std::move(fault);
        started_ = true;
        ++start_calls_;
    }
    std::expected<void, std::string> watch(const std::string& key, const SparkParams&) override {
        std::lock_guard lk(mu_);
        ++watch_calls_;
        if (fail_watch_)
            return std::unexpected("forced watch failure");
        watched_.insert(key);
        return {};
    }
    void unwatch(const std::string& key) override {
        std::lock_guard lk(mu_);
        ++unwatch_calls_;
        watched_.erase(key);
    }
    void stop() override {
        std::lock_guard lk(mu_);
        started_ = false;
        ++stop_calls_;
    }

    // ── test drivers ──
    void fire(const std::string& key) {
        SparkEmitFn e;
        {
            std::lock_guard lk(mu_);
            e = emit_;
        }
        if (e)
            e(key, SparkData{std::monostate{}});
    }
    // Drive the fault/health channel as a real mechanism would (lock released).
    void fire_fault(const std::string& key, bool faulted, std::string_view reason) {
        SparkFaultFn f;
        {
            std::lock_guard lk(mu_);
            f = fault_;
        }
        if (f)
            f(key, faulted, reason);
    }
    bool is_watching(const std::string& key) {
        std::lock_guard lk(mu_);
        return watched_.count(key) > 0;
    }
    int watch_calls() {
        std::lock_guard lk(mu_);
        return watch_calls_;
    }
    int unwatch_calls() {
        std::lock_guard lk(mu_);
        return unwatch_calls_;
    }
    int stop_calls() {
        std::lock_guard lk(mu_);
        return stop_calls_;
    }
    bool started() {
        std::lock_guard lk(mu_);
        return started_;
    }
    void set_fail_watch(bool b) {
        std::lock_guard lk(mu_);
        fail_watch_ = b;
    }

private:
    std::mutex mu_;
    SparkEmitFn emit_;
    SparkFaultFn fault_;
    std::set<std::string> watched_;
    bool started_{false};
    bool fail_watch_{false};
    int watch_calls_{0};
    int unwatch_calls_{0};
    int stop_calls_{0};
    int start_calls_{0};
};

SparkSpec file_spec(const std::string& path) {
    return SparkSpec{SparkType::File, FileSparkParams{path}};
}
SparkSpec registry_spec(const std::string& hive, const std::string& key) {
    return SparkSpec{SparkType::Registry, RegistrySparkParams{hive, key}};
}

/// Register a fake for `type` and return the borrowed pointer (engine owns it).
FakeMechanism* wire_fake(SparkEngine& engine, SparkType type) {
    auto fake = std::make_unique<FakeMechanism>();
    FakeMechanism* raw = fake.get();
    REQUIRE(engine.register_mechanism(type, std::move(fake)).has_value());
    return raw;
}

} // namespace

TEST_CASE("register_mechanism: validates null / type / duplicate / timing", "[spark][mechanism]") {
    SparkEngine engine;
    CHECK_FALSE(engine.register_mechanism(SparkType::File, nullptr).has_value());
    // Timer-driven types have no mechanism — the wheel services them.
    CHECK_FALSE(
        engine.register_mechanism(SparkType::Interval, std::make_unique<FakeMechanism>()).has_value());
    CHECK_FALSE(
        engine.register_mechanism(SparkType::Disk, std::make_unique<FakeMechanism>()).has_value());

    REQUIRE(engine.register_mechanism(SparkType::File, std::make_unique<FakeMechanism>()).has_value());
    // Duplicate registration for the same type is rejected.
    CHECK_FALSE(
        engine.register_mechanism(SparkType::File, std::make_unique<FakeMechanism>()).has_value());

    engine.start();
    // After start() it is too late to register.
    CHECK_FALSE(engine.register_mechanism(SparkType::Registry, std::make_unique<FakeMechanism>())
                    .has_value());
    engine.stop();
}

TEST_CASE("arm(File) with no mechanism is rejected (armed == a watcher runs)", "[spark][mechanism]") {
    SparkEngine engine;
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    auto sub = engine.arm(*c, file_spec("/etc/hosts"));
    CHECK_FALSE(sub.has_value()); // no File mechanism registered → reject, never inert-arm
    CHECK(engine.stats().armed_sparks == 0);
}

TEST_CASE("arm(File) validation: empty path rejected", "[spark][mechanism]") {
    SparkEngine engine;
    wire_fake(engine, SparkType::File);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    CHECK_FALSE(engine.arm(*c, file_spec("")).has_value());
}

TEST_CASE("arm(Registry) validation: hive must be HKLM/HKCU/HKCR/HKU", "[spark][mechanism]") {
    SparkEngine engine;
    wire_fake(engine, SparkType::Registry);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    CHECK_FALSE(engine.arm(*c, registry_spec("BOGUS", "Software\\Yuzu")).has_value());
    CHECK_FALSE(engine.arm(*c, registry_spec("HKLM", "")).has_value());
    CHECK(engine.arm(*c, registry_spec("HKLM", "Software\\Yuzu")).has_value());
}

TEST_CASE("File spark: arm-after-start watches, fire delivers to the consumer",
          "[spark][mechanism]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    const auto spec = file_spec("/etc/hosts");
    const std::string key = spark_key(spec);
    REQUIRE(engine.arm(*c, spec).has_value());
    CHECK(fake->is_watching(key));       // the mechanism was told to watch, live
    CHECK(fake->watch_calls() == 1);
    CHECK(engine.stats().armed_sparks == 1);

    fake->fire(key);
    REQUIRE(eventually([&] { return got.count() >= 1; }));
    const SparkEvent ev = got.at(0);
    CHECK(ev.key == key);
    CHECK(ev.type == SparkType::File);
    CHECK(std::holds_alternative<std::monostate>(ev.data));

    engine.stop();
    CHECK(fake->stop_calls() == 1); // mechanism stopped (before consumers)
}

TEST_CASE("File spark: arm-before-start is replayed to the mechanism at start()",
          "[spark][mechanism]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());

    const auto spec = file_spec("/var/log/syslog");
    const std::string key = spark_key(spec);
    REQUIRE(engine.arm(*c, spec).has_value());
    CHECK_FALSE(fake->is_watching(key)); // not watched until the engine starts
    CHECK(fake->watch_calls() == 0);

    engine.start();
    CHECK(eventually([&] { return fake->is_watching(key); })); // start() replays the watch
    CHECK(fake->watch_calls() == 1);

    fake->fire(key);
    CHECK(eventually([&] { return got.count() >= 1; }));
    engine.stop();
}

TEST_CASE("File spark: equal specs dedup to one watch, fan out to all subscribers",
          "[spark][mechanism]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    Collector a, b;
    auto ca = engine.register_consumer("a", a.handler());
    auto cb = engine.register_consumer("b", b.handler());
    REQUIRE(ca.has_value());
    REQUIRE(cb.has_value());
    engine.start();

    const auto spec = file_spec("/etc/hosts");
    const std::string key = spark_key(spec);
    REQUIRE(engine.arm(*ca, spec).has_value());
    REQUIRE(engine.arm(*cb, spec).has_value());
    CHECK(fake->watch_calls() == 1); // dedup: N subscriptions, 1 watcher
    CHECK(engine.stats().armed_sparks == 1);
    CHECK(engine.stats().subscriptions == 2);

    fake->fire(key);
    REQUIRE(eventually([&] { return a.count() >= 1 && b.count() >= 1; }));
    CHECK(a.at(0).seq == b.at(0).seq); // one fire, one seq, both observe it
    engine.stop();
}

TEST_CASE("File spark: unwatch fires only when the last subscription is disarmed",
          "[spark][mechanism]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    auto ca = engine.register_consumer("a", [](const SparkEvent&) {});
    auto cb = engine.register_consumer("b", [](const SparkEvent&) {});
    REQUIRE(ca.has_value());
    REQUIRE(cb.has_value());
    engine.start();

    const auto spec = file_spec("/etc/hosts");
    const std::string key = spark_key(spec);
    auto sa = engine.arm(*ca, spec);
    auto sb = engine.arm(*cb, spec);
    REQUIRE(sa.has_value());
    REQUIRE(sb.has_value());

    engine.disarm(*sa);
    CHECK(fake->is_watching(key));    // one subscription remains — watch stays
    CHECK(fake->unwatch_calls() == 0);
    engine.disarm(*sb);
    CHECK(eventually([&] { return !fake->is_watching(key); })); // last one gone → unwatch
    CHECK(fake->unwatch_calls() == 1);
    engine.stop();
}

TEST_CASE("File spark: a mechanism watch failure rolls the arm back", "[spark][mechanism]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    fake->set_fail_watch(true);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();

    auto sub = engine.arm(*c, file_spec("/etc/hosts"));
    CHECK_FALSE(sub.has_value());          // watch failed → arm reported failure
    CHECK(engine.stats().armed_sparks == 0); // and the whole key was torn down (B1)
    CHECK(engine.stats().subscriptions == 0);
    engine.stop();
}

TEST_CASE("File spark: a pre-start replay watch failure marks the spark faulted, not silent",
          "[spark][mechanism]") {
    // A spark armed BEFORE start defers its watch to start()'s replay. If that
    // replay fails, subscribers already hold ids, so (unlike the post-start arm
    // which rolls back) the entry stays — but it must be flagged deaf via the
    // fault channel so "armed but not watching" is observable, never silent (B1).
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    const auto spec = file_spec("/etc/hosts");
    const std::string key = spark_key(spec);
    REQUIRE(engine.arm(*c, spec).has_value()); // armed before start (watch deferred)
    fake->set_fail_watch(true);                // the start() replay watch will fail

    engine.start();
    CHECK(eventually([&] { return fake->watch_calls() == 1; }));
    CHECK_FALSE(fake->is_watching(key));       // watch never came up
    CHECK(engine.stats().armed_sparks == 1);   // entry retained (ids outstanding)
    CHECK(engine.stats().armed_faulted == 1);  // …but flagged deaf, not silent
    CHECK(engine.stats().watch_faults_total == 1);
    engine.stop();
}

TEST_CASE("Mechanism fault channel: fault flags health on the transition, recovery clears it (B1)",
          "[spark][mechanism]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();
    const auto spec = file_spec("/etc/hosts");
    const std::string key = spark_key(spec);
    REQUIRE(engine.arm(*c, spec).has_value());
    CHECK(engine.stats().armed_faulted == 0);

    fake->fire_fault(key, true, "watch died after arm");
    CHECK(engine.stats().armed_faulted == 1);
    CHECK(engine.stats().watch_faults_total == 1);
    // Re-reporting the same faulted state is a no-op edge — the counter is a
    // transition count, not a per-report count.
    fake->fire_fault(key, true, "still dead");
    CHECK(engine.stats().watch_faults_total == 1);

    fake->fire_fault(key, false, "recovered");
    CHECK(engine.stats().armed_faulted == 0);
    CHECK(engine.stats().watch_faults_total == 1); // recovery does not bump the fault counter
    // A fault for an unknown/disarmed key is ignored (no crash, no drift).
    fake->fire_fault("registry|nope", true, "ghost");
    CHECK(engine.stats().armed_faulted == 0);
    engine.stop();
}

TEST_CASE("Mechanism emit path does not deadlock an inline re-arm (TRAP 2)", "[spark][mechanism]") {
    // An inline consumer that re-arms from inside its handler must not deadlock:
    // emit_event snapshots + releases mu_ before delivering, and arm takes mu_.
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    std::atomic<bool> rearmed{false};
    const auto spec = file_spec("/etc/hosts");
    const std::string key = spark_key(spec);

    auto inline_sub = engine.arm_inline(spec, [&](const SparkEvent&) {
        // Re-enter the engine from inside the (inline) delivery.
        auto c = engine.register_consumer("late", [](const SparkEvent&) {});
        if (c)
            rearmed.store(engine.arm(*c, SparkSpec{SparkType::Interval, IntervalSparkParams{50}})
                              .has_value());
    });
    REQUIRE(inline_sub.has_value());
    engine.start();

    fake->fire(key); // drives the inline handler synchronously on this thread
    CHECK(eventually([&] { return rearmed.load(); }));
    engine.stop();
}

TEST_CASE("platform factories honor the mechanism-or-null contract", "[spark][mechanism]") {
#ifdef _WIN32
    CHECK(make_file_mechanism() != nullptr);
    CHECK(make_registry_mechanism() != nullptr);
#else
    CHECK(make_file_mechanism() == nullptr);     // off Windows → no mechanism → arm() rejects
    CHECK(make_registry_mechanism() == nullptr);
#endif
}

// ── Windows-only smoke: drive the REAL IOCP / TP_WAIT mechanisms against a live
//    file write / registry write. The cross-platform cases above prove the
//    engine plumbing via the fake; these prove the actual Windows bodies fire.
#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <filesystem>
#include <fstream>

TEST_CASE("File spark (real mechanism): a live file write fires the spark",
          "[spark][mechanism][windows]") {
    namespace fs = std::filesystem;
    // PID-salted temp name — stable, never thread-id/clock (Defender flake #473).
    const fs::path target =
        fs::temp_directory_path() /
        ("spark_file_smoke_" + std::to_string(::GetCurrentProcessId()) + ".txt");
    { std::ofstream(target) << "seed"; } // parent dir + file exist before arming

    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::File, make_file_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    const auto spec = file_spec(target.string());
    REQUIRE(engine.arm(*c, spec).has_value());
    engine.start();

    std::this_thread::sleep_for(150ms); // let the IOCP read arm
    { std::ofstream(target, std::ios::app) << "change"; }

    CHECK(eventually([&] { return got.count() >= 1; }, 8000ms));
    if (got.count() >= 1) {
        CHECK(got.at(0).type == SparkType::File);
        CHECK(got.at(0).key == spark_key(spec));
    }
    engine.stop();
    std::error_code ec;
    fs::remove(target, ec);
}

TEST_CASE("Registry spark (real mechanism): a live value write fires the spark",
          "[spark][mechanism][windows]") {
    // PID-unique subkey under HKCU so parallel CI runners can't collide.
    const std::string sub =
        "Software\\Yuzu\\SparkSmoke_" + std::to_string(::GetCurrentProcessId());
    HKEY h = nullptr;
    REQUIRE(::RegCreateKeyExA(HKEY_CURRENT_USER, sub.c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr,
                              &h, nullptr) == ERROR_SUCCESS);

    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Registry, make_registry_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    const auto spec = registry_spec("HKCU", sub);
    REQUIRE(engine.arm(*c, spec).has_value());
    engine.start();

    std::this_thread::sleep_for(150ms); // let the TP_WAIT notify arm
    const DWORD val = 42;
    ::RegSetValueExA(h, "SparkVal", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&val), sizeof(val));

    CHECK(eventually([&] { return got.count() >= 1; }, 8000ms));
    if (got.count() >= 1) {
        CHECK(got.at(0).type == SparkType::Registry);
        CHECK(got.at(0).key == spark_key(spec));
    }
    engine.stop();
    ::RegCloseKey(h);
    ::RegDeleteKeyA(HKEY_CURRENT_USER, sub.c_str());
}

TEST_CASE("File spark (real mechanism): survives parent-dir delete + recreate",
          "[spark][mechanism][windows][resilience]") {
    namespace fs = std::filesystem;
    // Nest one level so the fallback ancestor is our own quiet dir, not the
    // churny temp root: <root>/<parent>/watched.txt — we delete <parent>.
    const fs::path root =
        fs::temp_directory_path() / ("spark_res_" + std::to_string(::GetCurrentProcessId()));
    const fs::path parent = root / "watched";
    const fs::path target = parent / "file.txt";
    std::error_code ec;
    fs::remove_all(root, ec);
    fs::create_directories(parent);
    { std::ofstream(target) << "seed"; }

    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::File, make_file_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    const auto spec = file_spec(target.string());
    REQUIRE(engine.arm(*c, spec).has_value());
    engine.start();
    std::this_thread::sleep_for(200ms); // let the dir read arm

    // Blow away the watched file's parent dir → the mechanism's dir handle goes
    // bad and it must fall back to watching <root> for the parent's recreation.
    fs::remove(target, ec);
    fs::remove(parent, ec);
    std::this_thread::sleep_for(300ms);

    // Recreate parent + file, then modify → the ancestor watch must re-resolve
    // the parent dir and re-arm, so this post-recreate change still fires.
    fs::create_directories(parent);
    { std::ofstream(target) << "recreated"; }
    std::this_thread::sleep_for(150ms);
    { std::ofstream(target, std::ios::app) << "change-after-recreate"; }

    CHECK(eventually([&] { return got.count() >= 1; }, 10000ms));
    if (got.count() >= 1)
        CHECK(got.at(0).type == SparkType::File);
    engine.stop();
    fs::remove_all(root, ec);
}

TEST_CASE("Registry spark (real mechanism): survives key delete + recreate",
          "[spark][mechanism][windows][resilience]") {
    const std::string sub =
        "Software\\Yuzu\\SparkRes_" + std::to_string(::GetCurrentProcessId());
    HKEY h = nullptr;
    REQUIRE(::RegCreateKeyExA(HKEY_CURRENT_USER, sub.c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr,
                              &h, nullptr) == ERROR_SUCCESS);
    ::RegCloseKey(h);

    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Registry, make_registry_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    const auto spec = registry_spec("HKCU", sub);
    REQUIRE(engine.arm(*c, spec).has_value());
    engine.start();
    std::this_thread::sleep_for(200ms); // let the target notify arm

    // Delete the watched key → the mechanism falls back to the ancestor NAME
    // watch on the parent (Software\Yuzu).
    ::RegDeleteKeyA(HKEY_CURRENT_USER, sub.c_str());
    std::this_thread::sleep_for(300ms);

    // Recreate it + write a value → the ancestor watch must re-resolve to the
    // target key and fire.
    HKEY h2 = nullptr;
    REQUIRE(::RegCreateKeyExA(HKEY_CURRENT_USER, sub.c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr,
                              &h2, nullptr) == ERROR_SUCCESS);
    const DWORD val = 7;
    ::RegSetValueExA(h2, "V", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&val), sizeof(val));

    CHECK(eventually([&] { return got.count() >= 1; }, 10000ms));
    if (got.count() >= 1)
        CHECK(got.at(0).type == SparkType::Registry);
    engine.stop();
    ::RegCloseKey(h2);
    ::RegDeleteKeyA(HKEY_CURRENT_USER, sub.c_str());
}

// ── Inline-tier dispatch latency (the ADR-0021 §3 µs claim) ──────────────────
//
// SCOPE — read before trusting these numbers. This measures ONLY the
// in-process inline dispatch: from the fire timestamp the engine stamps in
// emit_event (SparkEvent::at) to the inline handler's entry, run synchronously
// on the mechanism's own thread. It is the queue-BYPASS latency the inline tier
// exists to provide. It deliberately does NOT include:
//   - OS notification latency (kernel → us: ReadDirectoryChangesW /
//     RegNotifyChangeKeyValue delivery) — inherently ms-scale, outside the µs
//     claim, not something we control.
//   - the queued tier (bounded queue + a dispatch-thread hop) — that path is
//     ms-ish by design and is what inline avoids.
// Reported as min/median/max over many fires; the assertion is a LOOSE
// scheduler-quantum sanity bound only. The claim is µs-MEDIAN, NOT a hard
// worst-case cap (owner decision 2026-07-06: p99 can reach 100s of µs and a
// ~10ms outlier is possible on a shared pool), so a hard per-sample assert
// would be a false contract and a flake source.

namespace {
struct LatencyStats {
    std::size_t n{0};
    std::int64_t min_us{0}, median_us{0}, p90_us{0}, max_us{0};
};
LatencyStats summarize_us(std::vector<std::int64_t> v) {
    LatencyStats s;
    s.n = v.size();
    if (v.empty())
        return s;
    std::sort(v.begin(), v.end());
    s.min_us = v.front();
    s.max_us = v.back();
    s.median_us = v[v.size() / 2];
    s.p90_us = v[(v.size() * 9) / 10];
    return s;
}
} // namespace

TEST_CASE("Registry spark (real mechanism): inline dispatch is microsecond-scale",
          "[spark][mechanism][windows][latency]") {
    const std::string sub =
        "Software\\Yuzu\\SparkLat_" + std::to_string(::GetCurrentProcessId());
    HKEY h = nullptr;
    REQUIRE(::RegCreateKeyExA(HKEY_CURRENT_USER, sub.c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr,
                              &h, nullptr) == ERROR_SUCCESS);

    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Registry, make_registry_mechanism()).has_value());

    std::mutex lat_mu;
    std::vector<std::int64_t> dispatch_us; // SparkEvent::at → inline handler entry
    std::atomic<int> fires{0};
    auto inline_sub = engine.arm_inline(registry_spec("HKCU", sub), [&](const SparkEvent& ev) {
        const auto now = std::chrono::system_clock::now(); // MSVC: precise (~100ns) clock
        const auto us = std::chrono::duration_cast<std::chrono::microseconds>(now - ev.at).count();
        {
            std::lock_guard lk(lat_mu);
            dispatch_us.push_back(us);
        }
        fires.fetch_add(1, std::memory_order_relaxed);
    });
    REQUIRE(inline_sub.has_value());
    engine.start();
    std::this_thread::sleep_for(200ms); // let the TP_WAIT notify arm

    // Many spaced writes → many independent fires (re-arm-before-emit means each
    // spaced write is its own notify, not one coalesced event).
    constexpr int kWrites = 40;
    for (int i = 0; i < kWrites; ++i) {
        const DWORD v = static_cast<DWORD>(i);
        ::RegSetValueExA(h, "V", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&v), sizeof(v));
        std::this_thread::sleep_for(12ms);
    }
    CHECK(eventually([&] { return fires.load() >= 5; }, 8000ms));
    engine.stop();
    ::RegCloseKey(h);
    ::RegDeleteKeyA(HKEY_CURRENT_USER, sub.c_str());

    std::vector<std::int64_t> samples;
    {
        std::lock_guard lk(lat_mu);
        samples = dispatch_us;
    }
    const LatencyStats s = summarize_us(samples);
    const auto st = engine.stats();
    REQUIRE(s.n >= 5);
    WARN("[registry TP_WAIT] inline DISPATCH us over " << s.n << " fires: min=" << s.min_us
         << " median=" << s.median_us << " p90=" << s.p90_us << " max=" << s.max_us
         << " | inline HANDLER-exec us: max=" << st.inline_us_max << " over " << st.inline_calls_total
         << " calls, over_100us=" << st.inline_over_100us_total
         << " over_10ms=" << st.inline_over_10ms_total
         << "  (OS-notify latency NOT included — that is ms-scale, separate)");
    // Loose sanity only (µs-MEDIAN, not a hard cap): median dispatch under one
    // scheduler quantum. Catches a gross regression, tolerates the tail.
    CHECK(s.median_us < 10000);
}

TEST_CASE("File spark (real mechanism): inline dispatch is microsecond-scale",
          "[spark][mechanism][windows][latency]") {
    namespace fs = std::filesystem;
    const fs::path target =
        fs::temp_directory_path() /
        ("spark_lat_" + std::to_string(::GetCurrentProcessId()) + ".txt");
    { std::ofstream(target) << "seed"; }

    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::File, make_file_mechanism()).has_value());

    std::mutex lat_mu;
    std::vector<std::int64_t> dispatch_us;
    std::atomic<int> fires{0};
    auto inline_sub = engine.arm_inline(file_spec(target.string()), [&](const SparkEvent& ev) {
        const auto now = std::chrono::system_clock::now();
        const auto us = std::chrono::duration_cast<std::chrono::microseconds>(now - ev.at).count();
        {
            std::lock_guard lk(lat_mu);
            dispatch_us.push_back(us);
        }
        fires.fetch_add(1, std::memory_order_relaxed);
    });
    REQUIRE(inline_sub.has_value());
    engine.start();
    std::this_thread::sleep_for(200ms); // let the IOCP read arm

    constexpr int kWrites = 40;
    for (int i = 0; i < kWrites; ++i) {
        { std::ofstream(target, std::ios::app) << "x"; }
        std::this_thread::sleep_for(12ms);
    }
    CHECK(eventually([&] { return fires.load() >= 5; }, 8000ms));
    engine.stop();
    std::error_code ec;
    fs::remove(target, ec);

    std::vector<std::int64_t> samples;
    {
        std::lock_guard lk(lat_mu);
        samples = dispatch_us;
    }
    const LatencyStats s = summarize_us(samples);
    const auto st = engine.stats();
    REQUIRE(s.n >= 5);
    WARN("[file IOCP] inline DISPATCH us over " << s.n << " fires: min=" << s.min_us
         << " median=" << s.median_us << " p90=" << s.p90_us << " max=" << s.max_us
         << " | inline HANDLER-exec us: max=" << st.inline_us_max << " over " << st.inline_calls_total
         << " calls, over_100us=" << st.inline_over_100us_total
         << " over_10ms=" << st.inline_over_10ms_total
         << "  (OS-notify latency NOT included — that is ms-scale, separate)");
    CHECK(s.median_us < 10000);
}

#endif // _WIN32
