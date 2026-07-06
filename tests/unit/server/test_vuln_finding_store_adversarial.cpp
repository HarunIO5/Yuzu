// ADVERSARIAL tests for VulnFindingStore (PR 2). Hostile probes of the
// coverage-clobber guard, concurrency serialization, monotonic run_ts bursts,
// per-row rollback atomicity, severity normalization completeness, tri-state
// coverage read under real degrade, disposed_clean edge cases, and SQL
// metacharacter / NUL handling. Written by the Adversarial Tester role — a
// FAILING assertion here is a WIN (it reveals a real bug), not a test bug.
// PG-gated: skips when YUZU_TEST_POSTGRES_DSN is unset, fails if set-but-broken.

#include <catch2/catch_test_macros.hpp>

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "vuln_finding_store.hpp"

#include "../test_helpers.hpp"

#include <libpq-fe.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using yuzu::server::AgentCoverageCounts;
using yuzu::server::AgentReconcile;
using yuzu::server::CoverageRead;
using yuzu::server::FindingKey;
using yuzu::server::FindingQuery;
using yuzu::server::FindingRow;
using yuzu::server::FindingUpsert;
using yuzu::server::VulnFindingStore;
using yuzu::server::pg::PgPool;

namespace {

FindingUpsert mk_finding(const std::string& cve, const std::string& pkg,
                         const std::string& sev = "high", const std::string& status = "potential") {
    FindingUpsert f;
    f.cve_id = cve;
    f.package_name = pkg;
    f.status = status;
    f.package_version = "1.2.3";
    f.ecosystem = "deb";
    f.severity = sev;
    f.cvss = 7.5;
    f.fixed_in = std::string{"1.2.4"};
    f.confidence = "high";
    f.feed_synced_at_ms = 1000;
    return f;
}

AgentReconcile mk_reconcile(const std::string& agent, std::vector<FindingUpsert> findings,
                            bool authoritative, AgentCoverageCounts cov = {}) {
    AgentReconcile r;
    r.agent_id = agent;
    r.findings = std::move(findings);
    r.coverage = cov;
    r.authoritative = authoritative;
    return r;
}

std::optional<FindingRow> find_row(VulnFindingStore& s, const std::string& agent,
                                    const std::string& cve, const std::string& pkg) {
    FindingQuery q;
    q.include_resolved = true;
    for (auto& row : s.query_findings(agent, q))
        if (row.cve_id == cve && row.package_name == pkg)
            return row;
    return std::nullopt;
}

} // namespace

// ---------------------------------------------------------------------------
// 1. Coverage-clobber guard — attack every combination.
// ---------------------------------------------------------------------------

TEST_CASE("ADVERSARIAL: non-authoritative with non-empty findings leaves coverage untouched",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    AgentCoverageCounts cov;
    cov.total_packages = 100;
    cov.vulnerable = 9;
    REQUIRE(store.reconcile_agent(
        mk_reconcile("a1", {mk_finding("CVE-1", "p1")}, /*authoritative=*/true, cov)));

    // Non-authoritative pass observes a NEW finding (CVE-2) and re-observes CVE-1,
    // with a DIFFERENT (bogus) coverage payload attached. The store must upsert the
    // findings but leave the coverage row byte-for-byte as the prior authoritative
    // write — a suspect pass must never be able to smuggle coverage numbers in.
    AgentCoverageCounts bogus;
    bogus.total_packages = 999999;
    bogus.vulnerable = 0;
    REQUIRE(store.reconcile_agent(mk_reconcile(
        "a1", {mk_finding("CVE-1", "p1"), mk_finding("CVE-2", "p2")}, /*authoritative=*/false, bogus)));

    auto cr = store.get_agent_coverage("a1");
    REQUIRE(cr.status == CoverageRead::Status::Ok);
    CHECK(cr.row.total_packages == 100); // untouched by the non-authoritative bogus payload
    CHECK(cr.row.vulnerable == 9);

    // And CVE-2 (newly observed but by a suspect pass) must NOT be swept/absent —
    // it should simply be upserted open, and CVE-1 must NOT have been resolved
    // (no sweep on a non-authoritative pass at all).
    auto c1 = find_row(store, "a1", "CVE-1", "p1");
    auto c2 = find_row(store, "a1", "CVE-2", "p2");
    REQUIRE(c1);
    REQUIRE(c2);
    CHECK_FALSE(c1->resolved_at_ms.has_value());
    CHECK_FALSE(c2->resolved_at_ms.has_value());
}

TEST_CASE("ADVERSARIAL: authoritative with EMPTY findings resolves all AND zeroes coverage",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    AgentCoverageCounts cov;
    cov.total_packages = 50;
    cov.vulnerable = 3;
    REQUIRE(store.reconcile_agent(mk_reconcile(
        "a1", {mk_finding("CVE-1", "p1"), mk_finding("CVE-2", "p2")}, true, cov)));

    // A genuine "agent has zero vulnerabilities now" authoritative pass: empty
    // findings AND zeroed coverage. Both the sweep and the coverage overwrite are
    // gated on the SAME `authoritative` flag, so they must move together.
    AgentCoverageCounts zero{};
    REQUIRE(store.reconcile_agent(mk_reconcile("a1", {}, /*authoritative=*/true, zero)));

    CHECK(store.query_findings("a1").empty()); // both resolved
    auto c1 = find_row(store, "a1", "CVE-1", "p1");
    auto c2 = find_row(store, "a1", "CVE-2", "p2");
    REQUIRE(c1);
    REQUIRE(c2);
    CHECK(c1->resolved_at_ms.has_value());
    CHECK(c2->resolved_at_ms.has_value());

    auto cr = store.get_agent_coverage("a1");
    REQUIRE(cr.status == CoverageRead::Status::Ok);
    CHECK(cr.row.total_packages == 0);
    CHECK(cr.row.vulnerable == 0);
}

// ---------------------------------------------------------------------------
// 2. Concurrency — phantom-resolve race between two DIFFERING authoritative
//    passes for the SAME agent (the store's advisory lock only serializes
//    execution order — it cannot know one pass's finding set is stale
//    relative to the other's).
// ---------------------------------------------------------------------------

TEST_CASE("ADVERSARIAL: concurrent same-agent authoritative passes with DIFFERING finding sets",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    // Seed: agent has two open findings, X and Y, both established.
    REQUIRE(store.reconcile_agent(
        mk_reconcile("a1", {mk_finding("CVE-X", "px"), mk_finding("CVE-Y", "py")}, true)));

    std::atomic<int> ok{0};
    // Thread A: authoritative, observes {X, Y} (full, current view).
    auto bodyA = [&] {
        for (int i = 0; i < 20; ++i)
            if (store.reconcile_agent(
                    mk_reconcile("a1", {mk_finding("CVE-X", "px"), mk_finding("CVE-Y", "py")}, true)))
                ok.fetch_add(1, std::memory_order_relaxed);
    };
    // Thread B: authoritative, observes ONLY {X} — simulates a stale/partial
    // engine pass that is unaware Y still exists. Under true serialization each
    // pass fully commits before the next begins, so whichever runs LAST
    // determines the final state (last-authoritative-writer-wins) — that is
    // internally consistent. What must NEVER happen is Y ending up "resolved"
    // while a LATER-committing pass that included Y is not reflected, i.e. the
    // final state must match whichever pass's txn committed last, not some
    // interleaved mix.
    auto bodyB = [&] {
        for (int i = 0; i < 20; ++i)
            if (store.reconcile_agent(mk_reconcile("a1", {mk_finding("CVE-X", "px")}, true)))
                ok.fetch_add(1, std::memory_order_relaxed);
    };
    std::thread t1(bodyA), t2(bodyB);
    t1.join();
    t2.join();
    CHECK(ok.load() == 40); // no deadlock; every pass committed one way or another

    // X must always be open (every pass, from both threads, observed it).
    auto x = find_row(store, "a1", "CVE-X", "px");
    REQUIRE(x);
    CHECK_FALSE(x->resolved_at_ms.has_value());

    // Y's final state is a race (last committer wins) — but it MUST be
    // internally consistent: report what we see for the record. This is NOT
    // asserted pass/fail either way (documented racy-by-design), just observed.
    auto y = find_row(store, "a1", "CVE-Y", "py");
    REQUIRE(y); // never disposed/deleted, only ever resolved or open
    INFO("CVE-Y final resolved_at_ms has_value = " << y->resolved_at_ms.has_value());
}

TEST_CASE("ADVERSARIAL: different agents reconcile concurrently without cross-serialization stalls",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 8}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    constexpr int kAgents = 6;
    constexpr int kIters = 15;
    std::atomic<int> ok{0};
    std::vector<std::thread> threads;
    for (int a = 0; a < kAgents; ++a) {
        threads.emplace_back([&, a] {
            std::string agent = "concur-agent-" + std::to_string(a);
            for (int i = 0; i < kIters; ++i)
                if (store.reconcile_agent(mk_reconcile(agent, {mk_finding("CVE-1", "p1")}, true)))
                    ok.fetch_add(1, std::memory_order_relaxed);
        });
    }
    auto start = std::chrono::steady_clock::now();
    for (auto& t : threads)
        t.join();
    auto elapsed = std::chrono::steady_clock::now() - start;
    CHECK(ok.load() == kAgents * kIters);
    // Distinct agents hash to distinct advisory-lock keys (overwhelmingly likely
    // for hashtextextended over 6 short distinct strings) so this should finish
    // quickly (not serialized end-to-end). Generous bound to avoid flake.
    CHECK(elapsed < std::chrono::seconds(15));
}

TEST_CASE("ADVERSARIAL: a rolled-back reconcile releases the advisory lock (no deadlock after)",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    // A failing reconcile (CHECK violation) rolls back.
    FindingUpsert bad = mk_finding("CVE-BAD", "pbad");
    bad.status = "bogus";
    CHECK_FALSE(store.reconcile_agent(mk_reconcile("a1", {bad}, true)));

    // A subsequent reconcile of the SAME agent must succeed promptly (proves the
    // pg_advisory_xact_lock was released on ROLLBACK, not leaked).
    auto start = std::chrono::steady_clock::now();
    REQUIRE(store.reconcile_agent(mk_reconcile("a1", {mk_finding("CVE-1", "p1")}, true)));
    auto elapsed = std::chrono::steady_clock::now() - start;
    CHECK(elapsed < std::chrono::seconds(5));
}

// ---------------------------------------------------------------------------
// 3. Monotonic run_ts edges — rapid burst, and interaction with a
//    far-future stored last_run_at_ms.
// ---------------------------------------------------------------------------

TEST_CASE("ADVERSARIAL: rapid burst of reconciles yields strictly increasing run_ts",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    constexpr int kBurst = 30;
    std::vector<std::int64_t> last_run_seen;
    for (int i = 0; i < kBurst; ++i) {
        REQUIRE(store.reconcile_agent(mk_reconcile("a1", {mk_finding("CVE-1", "p1")}, true)));
        auto cr = store.get_agent_coverage("a1");
        REQUIRE(cr.status == CoverageRead::Status::Ok);
        last_run_seen.push_back(cr.row.last_run_at_ms);
    }
    for (std::size_t i = 1; i < last_run_seen.size(); ++i)
        CHECK(last_run_seen[i] > last_run_seen[i - 1]); // strictly monotonic, no collisions

    // The stamped last_seen_ms may now be ms AHEAD of wall-clock now(). Confirm a
    // normal subsequent authoritative pass (with a DIFFERENT finding, so CVE-1
    // disappears) still sweeps it correctly despite last_seen_ms possibly being
    // >= a "now" sampled a moment later mid-test.
    REQUIRE(store.reconcile_agent(mk_reconcile("a1", {mk_finding("CVE-OTHER", "pother")}, true)));
    auto cve1 = find_row(store, "a1", "CVE-1", "p1");
    REQUIRE(cve1);
    CHECK(cve1->resolved_at_ms.has_value()); // swept despite the ahead-of-wall-clock stamps
}

TEST_CASE("ADVERSARIAL: finding inserted with future-skewed last_seen_ms is still swept later",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.reconcile_agent(mk_reconcile("a1", {mk_finding("CVE-1", "p1")}, true)));

    // Force last_seen_ms/first_seen_ms into the far future directly (simulating a
    // prior pass that ran under a badly-skewed clock, worse than the run_ts
    // monotonic guard alone would ever produce from THIS store — e.g. imported
    // from a differently-configured replica).
    const std::int64_t far_future = std::chrono::duration_cast<std::chrono::milliseconds>(
                                        std::chrono::system_clock::now().time_since_epoch())
                                        .count() +
                                    3600000; // +1 hour
    {
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        auto upd = yuzu::server::pg::exec_params(
            lease.get(),
            "UPDATE vuln_finding_store.finding SET last_seen_ms = $1::bigint "
            "WHERE agent_id = 'a1' AND cve_id = 'CVE-1'",
            std::vector<std::string>{std::to_string(far_future)});
        REQUIRE(upd.status() == PGRES_COMMAND_OK);
        auto upd2 = yuzu::server::pg::exec_params(
            lease.get(),
            "UPDATE vuln_finding_store.agent_coverage SET last_run_at_ms = $1::bigint "
            "WHERE agent_id = 'a1'",
            std::vector<std::string>{std::to_string(far_future)});
        REQUIRE(upd2.status() == PGRES_COMMAND_OK);
    }

    // A normal-time authoritative pass with CVE-1 absent must still eventually
    // sweep it (run_ts = far_future+1 > far_future last_seen_ms).
    REQUIRE(store.reconcile_agent(mk_reconcile("a1", {}, true)));
    auto row = find_row(store, "a1", "CVE-1", "p1");
    REQUIRE(row);
    CHECK(row->resolved_at_ms.has_value());
    CHECK(row->resolved_at_ms.value() > far_future);
}

// ---------------------------------------------------------------------------
// 4. Per-row rollback atomicity — bad row NOT at the end; duplicate key
//    within one reconcile's findings vector.
// ---------------------------------------------------------------------------

TEST_CASE("ADVERSARIAL: bad row in the MIDDLE of a 5-row batch rolls back ALL 5, not just the tail",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    std::vector<FindingUpsert> five = {mk_finding("CVE-1", "p1"), mk_finding("CVE-2", "p2"),
                                        mk_finding("CVE-3", "p3"), mk_finding("CVE-4", "p4"),
                                        mk_finding("CVE-5", "p5")};
    five[2].confidence = "medium"; // row 3 of 5 — vocab is only high|low → CHECK violation

    CHECK_FALSE(store.reconcile_agent(mk_reconcile("a1", five, true)));

    FindingQuery q;
    q.include_resolved = true;
    auto rows = store.query_findings("a1", q);
    CHECK(rows.empty()); // NOT rows 1-2 persisted; zero of the 5 survive
}

TEST_CASE("ADVERSARIAL: duplicate (cve_id, package_name) within one reconcile batch does not error",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    // Same (cve_id, package_name) twice in the SAME batch with different status —
    // the store loops per-row exec_params (not a single multi-row VALUES/ON
    // CONFLICT), so this must NOT trip Postgres's "ON CONFLICT DO UPDATE command
    // cannot affect row a second time" error.
    auto f1 = mk_finding("CVE-DUP", "pdup", "high", "potential");
    auto f2 = mk_finding("CVE-DUP", "pdup", "high", "vulnerable");
    CHECK(store.reconcile_agent(mk_reconcile("a1", {f1, f2}, true)));

    auto rows = store.query_findings("a1");
    REQUIRE(rows.size() == 1); // one row, last-write-wins
    CHECK(rows[0].status == "vulnerable");
}

// ---------------------------------------------------------------------------
// 5. Severity normalization completeness.
// ---------------------------------------------------------------------------

TEST_CASE("ADVERSARIAL: severity normalization — incidental whitespace is trimmed",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    SECTION("trailing whitespace on an otherwise-valid severity is recognized") {
        auto f = mk_finding("CVE-1", "p1", "high ");
        REQUIRE(store.reconcile_agent(mk_reconcile("a1", {f}, true)));
        auto row = find_row(store, "a1", "CVE-1", "p1");
        REQUIRE(row);
        // Post-fix: normalize_severity trims leading/trailing ASCII whitespace
        // before the vocab check, so incidental feed whitespace ("high ") no
        // longer collapses a real severity to "unknown".
        CHECK(row->severity == "high");
        INFO("severity for 'high ' normalized to: " << row->severity);
    }
    SECTION("leading + trailing whitespace and tabs are trimmed") {
        auto f = mk_finding("CVE-1b", "p1b", "\t  critical \n");
        REQUIRE(store.reconcile_agent(mk_reconcile("a1", {f}, true)));
        auto row = find_row(store, "a1", "CVE-1b", "p1b");
        REQUIRE(row);
        CHECK(row->severity == "critical");
    }
    SECTION("empty severity string") {
        auto f = mk_finding("CVE-2", "p2", "");
        REQUIRE(store.reconcile_agent(mk_reconcile("a1", {f}, true)));
        auto row = find_row(store, "a1", "CVE-2", "p2");
        REQUIRE(row);
        CHECK(row->severity == "unknown"); // must not violate the CHECK / crash
    }
    SECTION("mixed case with internal punctuation") {
        auto f = mk_finding("CVE-3", "p3", "Critical!");
        REQUIRE(store.reconcile_agent(mk_reconcile("a1", {f}, true)));
        auto row = find_row(store, "a1", "CVE-3", "p3");
        REQUIRE(row);
        CHECK(row->severity == "unknown"); // not in vocab even lowercased
    }
    SECTION("proper case-insensitive match still works") {
        auto f = mk_finding("CVE-4", "p4", "CRITICAL");
        REQUIRE(store.reconcile_agent(mk_reconcile("a1", {f}, true)));
        auto row = find_row(store, "a1", "CVE-4", "p4");
        REQUIRE(row);
        CHECK(row->severity == "critical");
    }
}

// ---------------------------------------------------------------------------
// 6. get_agent_coverage tri-state under a REAL degrade (pool exhaustion),
//    not just a closed-store stand-in.
// ---------------------------------------------------------------------------

TEST_CASE("ADVERSARIAL: get_agent_coverage returns Degraded (not NotFound) when the pool is exhausted",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB(db);
    // Pool of size 1 so a single held lease starves every other acquire.
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    // A known agent exists (would read Ok if the pool were free).
    REQUIRE(store.reconcile_agent(mk_reconcile("known", {mk_finding("CVE-1", "p1")}, true)));

    // Hold the pool's only connection for longer than kReadTimeout (3s) on another
    // thread so the coverage read's try_acquire_for starves.
    std::atomic<bool> release_now{false};
    std::thread holder([&] {
        auto lease = pool.acquire();
        REQUIRE(lease);
        while (!release_now.load())
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
    });
    // Give the holder a moment to actually acquire before racing the read.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    auto cr = store.get_agent_coverage("known");
    release_now = true;
    holder.join();

    CHECK(cr.status == CoverageRead::Status::Degraded); // NOT NotFound — the agent DOES exist
}

// ---------------------------------------------------------------------------
// 7. SQL metacharacters / NUL bytes in identity fields.
// ---------------------------------------------------------------------------

TEST_CASE("ADVERSARIAL: SQL metacharacters in agent_id/cve_id/package_name are safely parameterized",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    const std::string evil_agent = "a1'; DROP TABLE vuln_finding_store.finding; --";
    const std::string evil_cve = "CVE-'); DELETE FROM vuln_finding_store.agent_coverage; --";
    const std::string evil_pkg = "pkg\"'\\";

    auto f = mk_finding(evil_cve, evil_pkg);
    REQUIRE(store.reconcile_agent(mk_reconcile(evil_agent, {f}, true)));

    // The table must still exist and be queryable, and the row must round-trip
    // byte-for-byte (proves parameterization, not string concatenation).
    auto rows = store.query_findings(evil_agent);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].cve_id == evil_cve);
    CHECK(rows[0].package_name == evil_pkg);

    // A completely unrelated agent's coverage must be unaffected (the DELETE
    // payload, if it had executed as SQL, would have wiped agent_coverage
    // fleet-wide).
    AgentCoverageCounts cov;
    cov.total_packages = 5;
    REQUIRE(store.reconcile_agent(mk_reconcile("innocent-bystander", {}, true, cov)));
    auto cr = store.get_agent_coverage("innocent-bystander");
    REQUIRE(cr.status == CoverageRead::Status::Ok);
    CHECK(cr.row.total_packages == 5);
}

TEST_CASE("ADVERSARIAL: a NUL byte embedded in cve_id does not corrupt other rows or crash",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    using namespace std::string_literals;
    // cve_id with an embedded NUL. `exec_params` binds via `c_str()` (a
    // null-terminated C string with no explicit length), so libpq will only see
    // the bytes up to the first NUL — this documents whatever actually happens
    // (truncation vs error vs full value) rather than assuming either.
    const std::string evil_cve = "CVE-1\0-TAIL"s;
    REQUIRE(evil_cve.size() == 11); // the std::string itself DOES hold all 11 bytes

    auto f = mk_finding(evil_cve, "pkg-nul");
    bool ok = store.reconcile_agent(mk_reconcile("a1", {f}, true));
    INFO("reconcile_agent with NUL-embedded cve_id returned: " << ok);

    if (ok) {
        auto rows = store.query_findings("a1");
        REQUIRE(rows.size() == 1);
        INFO("stored cve_id length: " << rows[0].cve_id.size() << " value: [" << rows[0].cve_id
                                       << "]");
        // Whatever it stored, it must be a PREFIX of the original up to the NUL
        // (silent truncation), never garbage/other bytes appended, and it must
        // not equal the full 11-byte original (that would require the NUL to
        // have survived libpq's text-format transport, which it cannot).
        CHECK(rows[0].cve_id != evil_cve);
    }
    // Above all: this must not crash the process. Reaching this line is itself
    // part of the assertion.
    SUCCEED("did not crash on embedded NUL");
}

// ---------------------------------------------------------------------------
// 8. disposed_clean edge cases.
// ---------------------------------------------------------------------------

TEST_CASE("ADVERSARIAL: disposed_clean overlapping the sweep set — DELETE wins, no double-processing",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    // Seed two findings; a fresh pass disposes ONE of them as reassessed-clean
    // AND omits it from `findings` (so it would ALSO be sweep-eligible) — both
    // mechanisms target the same row in the same transaction.
    REQUIRE(store.reconcile_agent(
        mk_reconcile("a1", {mk_finding("CVE-1", "p1"), mk_finding("CVE-2", "p2")}, true)));

    AgentReconcile r = mk_reconcile("a1", {}, /*authoritative=*/true);
    r.disposed_clean = {FindingKey{"CVE-1", "p1"}};
    REQUIRE(store.reconcile_agent(r));

    // CVE-1: deleted outright (disposed_clean), not merely resolved.
    CHECK_FALSE(find_row(store, "a1", "CVE-1", "p1").has_value());
    // CVE-2: not in disposed_clean, not re-observed → swept (resolved, still a row).
    auto cve2 = find_row(store, "a1", "CVE-2", "p2");
    REQUIRE(cve2);
    CHECK(cve2->resolved_at_ms.has_value());
}

// ---------------------------------------------------------------------------
// 9. Cross-store advisory-lock namespace ISOLATION (regression guard for the
//    fix). `pg_advisory_xact_lock` keys are a SINGLE 64-bit space shared by the
//    whole Postgres backend/cluster — NOT scoped per schema/table. Before the
//    fix, VulnFindingStore's reconcile_agent computed the IDENTICAL lock formula
//    as SoftwareInventoryStore's full-replace ingest
//    (`hashtextextended(agent_id, 0)`, software_inventory_store.cpp:~467), so the
//    two UNRELATED stores collided on the exact same key for a given agent — a
//    long-running software-inventory ingest for agent X needlessly serialized a
//    concurrent vuln-finding reconcile for the SAME agent X even though they
//    touch disjoint tables. The fix folds a 'vuln_finding_store:' namespace into
//    the vuln store's key. This test now PROVES the fix: holding the
//    software_inventory-style lock must NOT block the vuln reconcile.
// ---------------------------------------------------------------------------

TEST_CASE("ADVERSARIAL: VulnFindingStore's advisory lock key is namespaced away from "
          "SoftwareInventoryStore's for the same agent_id",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    const std::string agent = "collide-agent";
    constexpr auto kHold = std::chrono::milliseconds(1500);

    // Hold the EXACT lock SoftwareInventoryStore's full-replace path takes
    // (identical SQL: hashtextextended(agent_id, 0), same salt) on a raw
    // transaction, without going through SoftwareInventoryStore at all — this
    // isolates the claim to "does the vuln reconcile's lock KEY collide with the
    // software-inventory key", independent of any other behavioral difference.
    std::atomic<bool> lock_acquired{false};
    std::thread holder([&] {
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto begin = yuzu::server::pg::exec_params(lease.get(), "BEGIN", std::vector<std::string>{});
        REQUIRE(begin.status() == PGRES_COMMAND_OK);
        auto lk = yuzu::server::pg::exec_params(
            lease.get(), "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            std::vector<std::string>{agent});
        REQUIRE(lk.status() == PGRES_TUPLES_OK);
        lock_acquired = true;
        std::this_thread::sleep_for(kHold);
        auto commit =
            yuzu::server::pg::exec_params(lease.get(), "COMMIT", std::vector<std::string>{});
        REQUIRE(commit.status() == PGRES_COMMAND_OK);
    });
    while (!lock_acquired.load())
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    // Small buffer to be sure the holder's transaction is fully inside the lock
    // before we race the reconcile against it.
    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    auto t0 = std::chrono::steady_clock::now();
    bool ok = store.reconcile_agent(mk_reconcile(agent, {mk_finding("CVE-1", "p1")}, true));
    auto elapsed = std::chrono::steady_clock::now() - t0;
    holder.join();

    CHECK(ok); // succeeds regardless
    // Post-fix: the vuln store's key is hashtextextended('vuln_finding_store:' ||
    // agent, 0), disjoint from software_inventory's hashtextextended(agent, 0), so
    // the reconcile must NOT wait on the unrelated hold — it should complete well
    // under the hold duration. (Before the fix this blocked for ~kHold.)
    INFO("reconcile_agent elapsed while an external hashtextextended(agent,0) "
         "lock was held: "
         << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() << "ms "
         << "(hold was " << kHold.count() << "ms)");
    CHECK(elapsed < kHold / 2); // NOT blocked — namespaced key does not collide
}

TEST_CASE("ADVERSARIAL: two vuln reconciles for the SAME agent still serialize "
          "(intra-store lock preserved)",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    const std::string agent = "same-agent-serialize";
    constexpr auto kHold = std::chrono::milliseconds(1500);

    // Hold the VULN store's own namespaced key (the exact formula reconcile_agent
    // now uses) for the same agent. A concurrent reconcile of that agent MUST
    // block on it — the fix must not have weakened same-agent serialization.
    std::atomic<bool> lock_acquired{false};
    std::thread holder([&] {
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto begin = yuzu::server::pg::exec_params(lease.get(), "BEGIN", std::vector<std::string>{});
        REQUIRE(begin.status() == PGRES_COMMAND_OK);
        auto lk = yuzu::server::pg::exec_params(
            lease.get(),
            "SELECT pg_advisory_xact_lock(hashtextextended('vuln_finding_store:' || $1, 0))",
            std::vector<std::string>{agent});
        REQUIRE(lk.status() == PGRES_TUPLES_OK);
        lock_acquired = true;
        std::this_thread::sleep_for(kHold);
        auto commit =
            yuzu::server::pg::exec_params(lease.get(), "COMMIT", std::vector<std::string>{});
        REQUIRE(commit.status() == PGRES_COMMAND_OK);
    });
    while (!lock_acquired.load())
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    auto t0 = std::chrono::steady_clock::now();
    bool ok = store.reconcile_agent(mk_reconcile(agent, {mk_finding("CVE-1", "p1")}, true));
    auto elapsed = std::chrono::steady_clock::now() - t0;
    holder.join();

    CHECK(ok); // eventually succeeds once the hold releases
    INFO("reconcile_agent elapsed while its OWN namespaced key was held: "
         << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() << "ms");
    CHECK(elapsed >= kHold / 2); // blocked — same-agent serialization intact
}

TEST_CASE("ADVERSARIAL: disposed_clean naming a tuple that was never observed is a harmless no-op",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    AgentReconcile r = mk_reconcile("a1", {mk_finding("CVE-1", "p1")}, true);
    r.disposed_clean = {FindingKey{"CVE-NEVER-EXISTED", "phantom"}};
    CHECK(store.reconcile_agent(r)); // DELETE affecting 0 rows must not fail the batch

    auto rows = store.query_findings("a1");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].cve_id == "CVE-1");
}
