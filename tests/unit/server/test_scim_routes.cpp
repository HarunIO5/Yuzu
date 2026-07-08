/**
 * test_scim_routes.cpp — HTTP-level coverage for the SCIM v2 provisioning
 * surface (/scim/v2/*, slice 3 of 3). Registers ScimRoutes against an
 * in-process TestRouteSink (no socket, no acceptor thread — TSan-safe,
 * #438) over a REAL AuthDB + ScimStore pair sharing one auth.db file, so
 * the AuthManager provisioning path (upsert_user/remove_user/
 * get_provisioning_source) is exercised for real rather than faked.
 *
 * Coverage: bearer gate (401 missing/wrong token), discovery documents,
 * POST provision (201 + Location/ETag, 409 duplicate userName), GET by id
 * (200/404), GET ?filter=, the full PATCH active=false -> active=true
 * deprovision/reactivate round-trip (asserts the underlying auth account
 * is ACTUALLY deactivated then reactivated — not just the SCIM resource
 * flag — and that lockout state is cleared on reactivation per AuthDB::
 * reactivate_user's contract), DELETE (204 + soft-deleted), and the
 * LOAD-BEARING provenance guard: SCIM must never mutate a LOCALLY-created
 * account, even when a scim_resource row happens to reference it
 * (defense-in-depth — see scim_routes.cpp `provenance_ok`), including on
 * the reactivate path.
 */

#include "scim_routes.hpp"

#include "audit_store.hpp"
#include "test_route_sink.hpp"

#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>
#include <yuzu/server/scim_store.hpp>

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>

using namespace yuzu::server;
using json = nlohmann::json;

namespace {

/// Wires ScimRoutes against a real AuthDB + ScimStore sharing one auth.db
/// file (mirrors production: ScimStore opens a second connection to the
/// SAME file AuthDB manages) plus a real AuditStore, all over an
/// in-process TestRouteSink.
struct Fixture {
    std::filesystem::path data_dir{yuzu::test::unique_temp_path("yuzu-scim-routes-")};
    std::unique_ptr<AuthDB> auth_db;
    auth::AuthManager auth_mgr;
    std::unique_ptr<ScimStore> scim_store;
    yuzu::test::TempDbFile audit_db_file{std::string_view{"yuzu-scim-routes-audit-"}};
    std::unique_ptr<AuditStore> audit_store;
    test::TestRouteSink sink;
    std::unique_ptr<ScimRoutes> routes;
    const std::string token{"unit-test-scim-bearer-token-0123456789"};

    Fixture() {
        std::filesystem::create_directories(data_dir);
        auth_db = std::make_unique<AuthDB>(data_dir, /*cleanup_interval_secs=*/0);
        REQUIRE(auth_db->initialize().has_value());
        auth_mgr.set_auth_db(auth_db.get());

        scim_store = std::make_unique<ScimStore>(data_dir / "auth.db");
        REQUIRE(scim_store->is_open());
        REQUIRE(scim_store->set_token(token, "test"));

        audit_store = std::make_unique<AuditStore>(audit_db_file.path);
        REQUIRE(audit_store->is_open());

        routes = std::make_unique<ScimRoutes>();
        routes->register_routes(sink, scim_store.get(), &auth_mgr, audit_store.get());
    }

    ~Fixture() {
        std::error_code ec;
        routes.reset();
        audit_store.reset();
        scim_store.reset();
        auth_db.reset();
        std::filesystem::remove_all(data_dir, ec);
    }

    std::unordered_map<std::string, std::string> auth_header() const {
        return {{"Authorization", "Bearer " + token}};
    }

    auto get(const std::string& path) {
        return sink.dispatch("GET", path, {}, "application/json", auth_header());
    }
    auto post(const std::string& path, const json& body) {
        return sink.dispatch("POST", path, body.dump(), "application/scim+json", auth_header());
    }
    auto patch(const std::string& path, const json& body) {
        return sink.dispatch("PATCH", path, body.dump(), "application/scim+json", auth_header());
    }
    auto put(const std::string& path, const json& body) {
        return sink.dispatch("PUT", path, body.dump(), "application/scim+json", auth_header());
    }
    auto del(const std::string& path) {
        return sink.dispatch("DELETE", path, {}, "application/scim+json", auth_header());
    }
};

} // namespace

// ── Bearer gate ──────────────────────────────────────────────────────────

TEST_CASE("ScimRoutes: 401 without a bearer token", "[scim][routes][auth]") {
    Fixture f;
    auto res = f.sink.dispatch("GET", "/scim/v2/Users");
    REQUIRE(res);
    CHECK(res->status == 401);
    CHECK(res->get_header_value("WWW-Authenticate") == "Bearer");
    CHECK(json::parse(res->body)["status"] == "401");
}

TEST_CASE("ScimRoutes: 401 with the wrong bearer token", "[scim][routes][auth]") {
    Fixture f;
    auto res = f.sink.dispatch("GET", "/scim/v2/Users", "", "application/json",
                               {{"Authorization", "Bearer wrong-token"}});
    REQUIRE(res);
    CHECK(res->status == 401);
}

// ── Discovery ─────────────────────────────────────────────────────────────

TEST_CASE("ScimRoutes: discovery endpoints return the right schemas", "[scim][routes][discovery]") {
    Fixture f;

    auto spc = f.get("/scim/v2/ServiceProviderConfig");
    REQUIRE(spc);
    CHECK(spc->status == 200);
    CHECK(json::parse(spc->body)["schemas"][0] ==
         "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig");

    auto rt = f.get("/scim/v2/ResourceTypes");
    REQUIRE(rt);
    CHECK(rt->status == 200);
    auto rt_body = json::parse(rt->body);
    CHECK(rt_body["schemas"][0] == "urn:ietf:params:scim:api:messages:2.0:ListResponse");
    CHECK(rt_body["Resources"][0]["schema"] == "urn:ietf:params:scim:schemas:core:2.0:User");

    auto sch = f.get("/scim/v2/Schemas");
    REQUIRE(sch);
    CHECK(sch->status == 200);
    CHECK(json::parse(sch->body)["Resources"][0]["id"] ==
         "urn:ietf:params:scim:schemas:core:2.0:User");
}

// ── POST /Users (provision) ────────────────────────────────────────────────

TEST_CASE("ScimRoutes: POST provisions a user — 201 + Location + ETag", "[scim][routes][post]") {
    Fixture f;
    auto res = f.post("/scim/v2/Users", {{"userName", "alice"}, {"externalId", "ext-1"}});
    REQUIRE(res);
    CHECK(res->status == 201);
    CHECK_FALSE(res->get_header_value("Location").empty());
    CHECK(res->get_header_value("Location").ends_with(
        json::parse(res->body)["id"].get<std::string>()));
    CHECK(res->get_header_value("ETag") == R"(W/"1")");

    auto body = json::parse(res->body);
    CHECK(body["userName"] == "alice");
    CHECK(body["active"] == true);
    CHECK(body["externalId"] == "ext-1");

    // The account is provisioned at the read-only 'user' role, and its
    // provenance is recorded so the guard can verify it later.
    auto role = f.auth_mgr.get_user_role("alice");
    REQUIRE(role.has_value());
    CHECK(*role == auth::Role::user);
    auto src = f.auth_db->get_provisioning_source("alice");
    REQUIRE(src.has_value());
    CHECK(*src == "scim");
}

TEST_CASE("ScimRoutes: POST duplicate userName — 409, existing account untouched",
         "[scim][routes][post]") {
    Fixture f;
    auto first = f.post("/scim/v2/Users", {{"userName", "bob"}});
    REQUIRE(first);
    REQUIRE(first->status == 201);

    auto dup = f.post("/scim/v2/Users", {{"userName", "bob"}});
    REQUIRE(dup);
    CHECK(dup->status == 409);
    CHECK(json::parse(dup->body)["scimType"] == "uniqueness");

    // Only one scim_resource / auth account exists for "bob".
    int total = -1;
    auto page = f.scim_store->list(1, 100, total);
    CHECK(total == 1);
}

// ── GET /Users/{id}, GET /Users?filter= ────────────────────────────────────

TEST_CASE("ScimRoutes: GET /Users/{id} — 200 known, 404 unknown", "[scim][routes][get]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "carol"}})->body);
    auto id = created["id"].get<std::string>();

    auto ok = f.get("/scim/v2/Users/" + id);
    REQUIRE(ok);
    CHECK(ok->status == 200);
    CHECK(json::parse(ok->body)["userName"] == "carol");

    auto missing = f.get("/scim/v2/Users/deadbeefdeadbeefdeadbeefdeadbeef");
    REQUIRE(missing);
    CHECK(missing->status == 404);
}

TEST_CASE("ScimRoutes: GET ?filter=userName eq \"x\" returns the one match",
         "[scim][routes][get][filter]") {
    Fixture f;
    REQUIRE(f.post("/scim/v2/Users", {{"userName", "dave"}})->status == 201);
    REQUIRE(f.post("/scim/v2/Users", {{"userName", "erin"}})->status == 201);

    auto res = f.get(R"(/scim/v2/Users?filter=userName%20eq%20%22dave%22)");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = json::parse(res->body);
    CHECK(body["totalResults"] == 1);
    CHECK(body["Resources"][0]["userName"] == "dave");
}

// ── PATCH — the critical deprovision path ──────────────────────────────────

TEST_CASE("ScimRoutes: PATCH active=false deactivates the auth account",
         "[scim][routes][patch][deprovision]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "frank"}})->body);
    auto id = created["id"].get<std::string>();
    REQUIRE(f.auth_mgr.get_user_role("frank").has_value());

    json patch_body{{"Operations", json::array({{{"op", "replace"},
                                                 {"value", {{"active", false}}}}})}};
    auto res = f.patch("/scim/v2/Users/" + id, patch_body);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(json::parse(res->body)["active"] == false);

    // The underlying auth account is ACTUALLY deactivated, not just the
    // SCIM resource flag.
    CHECK_FALSE(f.auth_mgr.get_user_role("frank").has_value());
    auto stored = f.scim_store->get_by_scim_id(id);
    REQUIRE(stored.has_value());
    CHECK_FALSE(stored->active);
}

TEST_CASE("ScimRoutes: PATCH active=false -> active=true round-trips (deprovision then "
         "reactivate), clearing stale lockout state",
         "[scim][routes][patch][reactivate]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "grace"}})->body);
    auto id = created["id"].get<std::string>();

    // Seed a REAL lockout (threshold=1 so the first recorded failure both
    // increments the counter and crosses the lock threshold) so the
    // post-reactivation assertions below prove reactivate_user actually
    // cleared it, rather than coincidentally observing an all-zero row.
    auto lockout = f.auth_db->record_failed_login("grace", /*threshold=*/1,
                                                  /*window_secs=*/3600);
    REQUIRE(lockout.has_value());
    REQUIRE(lockout->locked);
    auto pre_status = f.auth_db->lockout_status("grace");
    REQUIRE(pre_status.has_value());
    CHECK(pre_status->locked);
    CHECK(pre_status->failed_count > 0);

    json deactivate_body{{"Operations", json::array({{{"op", "replace"},
                                                      {"value", {{"active", false}}}}})}};
    auto deactivate_res = f.patch("/scim/v2/Users/" + id, deactivate_body);
    REQUIRE(deactivate_res);
    CHECK(deactivate_res->status == 200);
    CHECK_FALSE(f.auth_mgr.get_user_role("grace").has_value());

    json reactivate_body{{"Operations", json::array({{{"op", "replace"},
                                                      {"value", {{"active", true}}}}})}};
    auto res = f.patch("/scim/v2/Users/" + id, reactivate_body);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(json::parse(res->body)["active"] == true);

    // The underlying auth account actually resolves again (is_active=1)...
    auto role = f.auth_mgr.get_user_role("grace");
    REQUIRE(role.has_value());
    CHECK(*role == auth::Role::user);
    // ...the SCIM resource flag flipped back too...
    auto stored = f.scim_store->get_by_scim_id(id);
    REQUIRE(stored.has_value());
    CHECK(stored->active);
    // ...provenance is untouched (still scim, not silently reset to local)...
    CHECK(f.auth_db->get_provisioning_source("grace").value() == "scim");
    // ...and the stale lockout from before deprovisioning is CLEARED, not
    // inherited by the returning user.
    auto post_status = f.auth_db->lockout_status("grace");
    REQUIRE(post_status.has_value());
    CHECK_FALSE(post_status->locked);
    CHECK(post_status->failed_count == 0);
}

TEST_CASE("ScimRoutes: PATCH active=true is a no-op when the resource is already active",
         "[scim][routes][patch][reactivate]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "heidi2"}})->body);
    auto id = created["id"].get<std::string>();

    json reactivate_body{{"Operations", json::array({{{"op", "replace"},
                                                      {"value", {{"active", true}}}}})}};
    auto res = f.patch("/scim/v2/Users/" + id, reactivate_body);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(f.auth_mgr.get_user_role("heidi2").has_value());
}

// ── DELETE ──────────────────────────────────────────────────────────────────

TEST_CASE("ScimRoutes: DELETE — 204 + account soft-deleted", "[scim][routes][delete]") {
    Fixture f;
    auto created = json::parse(f.post("/scim/v2/Users", {{"userName", "heidi"}})->body);
    auto id = created["id"].get<std::string>();

    auto res = f.del("/scim/v2/Users/" + id);
    REQUIRE(res);
    CHECK(res->status == 204);
    CHECK(res->body.empty());

    CHECK_FALSE(f.auth_mgr.get_user_role("heidi").has_value());
    CHECK_FALSE(f.scim_store->get_by_scim_id(id).has_value());
}

// ── Provenance guard (LOAD-BEARING) ────────────────────────────────────────

TEST_CASE("ScimRoutes: provenance guard — SCIM cannot touch a locally-created account",
         "[scim][routes][provenance]") {
    Fixture f;
    // A local admin, created OUTSIDE the SCIM path (upsert_user directly —
    // mirrors first-run-setup / an operator-run `yuzu-server --add-user`).
    REQUIRE(f.auth_mgr.upsert_user("admin", "correct-horse-battery-staple", auth::Role::admin));
    REQUIRE(f.auth_db->get_provisioning_source("admin").value() == "local");

    // 1) POST /Users with a colliding userName — must 409, not silently
    //    take over the existing admin account.
    auto dup = f.post("/scim/v2/Users", {{"userName", "admin"}});
    REQUIRE(dup);
    CHECK(dup->status == 409);
    CHECK(f.auth_db->get_provisioning_source("admin").value() == "local");
    CHECK(f.auth_mgr.get_user_role("admin").value() == auth::Role::admin);

    // 2) Defense-in-depth: even if a scim_resource row somehow existed for
    //    this username (a bug, or an operator hand-editing scim_resources —
    //    ScimStore has no FK to the auth.db users table), the provenance
    //    re-check must refuse the mutation with 404 (never 403 — a 403
    //    would confirm the local account's existence to the IdP).
    auto mapped = f.scim_store->create_resource("admin");
    REQUIRE(mapped.has_value());

    json deactivate_body{{"Operations", json::array({{{"op", "replace"},
                                                      {"value", {{"active", false}}}}})}};
    auto patch_res = f.patch("/scim/v2/Users/" + mapped->scim_id, deactivate_body);
    REQUIRE(patch_res);
    CHECK(patch_res->status == 404);

    auto del_res = f.del("/scim/v2/Users/" + mapped->scim_id);
    REQUIRE(del_res);
    CHECK(del_res->status == 404);

    // The local admin account is COMPLETELY untouched throughout.
    CHECK(f.auth_db->get_provisioning_source("admin").value() == "local");
    CHECK(f.auth_mgr.get_user_role("admin").value() == auth::Role::admin);
    // The bogus scim_resource mapping itself is untouched too (refused, not
    // silently no-op'd/deleted).
    auto still_mapped = f.scim_store->get_by_scim_id(mapped->scim_id);
    REQUIRE(still_mapped.has_value());
    CHECK(still_mapped->active);
}
