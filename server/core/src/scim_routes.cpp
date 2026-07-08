#include "scim_routes.hpp"

#include "audit_store.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth_db.hpp>
#include <yuzu/server/scim_json.hpp>
#include <yuzu/server/server.hpp> // Config — scim_boot_guard_ok

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace yuzu::server {

// ── Boot guard (S-BOOTGUARD-TEST) ───────────────────────────────────────────

bool scim_boot_guard_ok(const Config& cfg, std::string& err) {
    if (!cfg.scim_enable)
        return true;
    if (cfg.scim_token.empty()) {
        err = "--scim-enable requires --scim-token (or YUZU_SCIM_TOKEN) — refusing "
              "to start an unauthenticated provisioning surface.";
        return false;
    }
    if (!cfg.https_enabled) {
        err = "--scim-enable requires HTTPS (the bearer token would otherwise cross "
              "the wire in plaintext) — refusing to start with --no-https set. Enable "
              "HTTPS or disable --scim-enable.";
        return false;
    }
    return true;
}

namespace {

using json = nlohmann::json;

constexpr const char* kScimJson = "application/scim+json";
// Bound POST/PUT/PATCH bodies before parsing — a real SCIM User payload
// (even with IdP-sent fields Yuzu ignores: name, emails, groups, ...) is a
// few KB; 64 KiB is generous headroom while refusing a multi-MB POST on this
// provisioning surface.
constexpr std::size_t kMaxBodyBytes = 64 * 1024;

void send_scim_error(httplib::Response& res, int status, std::string_view detail,
                     std::string_view scim_type = "") {
    res.status = status;
    res.set_content(scim::error(status, detail, scim_type).dump(), kScimJson);
}

void send_scim_error(httplib::Response& res, const scim::ScimError& e) {
    res.status = e.status;
    res.set_content(scim::error(e).dump(), kScimJson);
}

/// Fixed audit principal — there is no session/human operator on this
/// bearer-only surface (see scim_routes.hpp header doc).
constexpr const char* kScimPrincipal = "scim-service";

// ── Metrics (M-METRICS) ─────────────────────────────────────────────────────

/// Bucket an HTTP status into Prometheus's conventional 2xx/4xx/5xx label so
/// `yuzu_scim_requests_total` stays low-cardinality regardless of the exact
/// status code.
std::string_view status_bucket(int status) {
    if (status >= 200 && status < 300)
        return "2xx";
    if (status >= 400 && status < 500)
        return "4xx";
    if (status >= 500)
        return "5xx";
    return "other";
}

/// Record one `/scim/v2/Users` request outcome. `op` is one of
/// create/get/list/replace/patch/delete. No-op when no MetricsRegistry is
/// wired (AuthManager::metrics_registry() is null in test/CLI contexts).
void record_request(auth::AuthManager* auth_mgr, const char* op, int status) {
    if (!auth_mgr)
        return;
    auto* m = auth_mgr->metrics_registry();
    if (!m)
        return;
    m->counter("yuzu_scim_requests_total",
               {{"op", op}, {"status", std::string(status_bucket(status))}})
        .increment();
}

void bump_auth_failure(auth::AuthManager* auth_mgr) {
    if (!auth_mgr)
        return;
    if (auto* m = auth_mgr->metrics_registry())
        m->counter("yuzu_scim_auth_failures_total").increment();
}

void bump_audit_write_failure(auth::AuthManager* auth_mgr, const std::string& action) {
    if (!auth_mgr)
        return;
    if (auto* m = auth_mgr->metrics_registry())
        m->counter("yuzu_scim_audit_write_failures_total", {{"action", action}}).increment();
}

void bump_provenance_denied(auth::AuthManager* auth_mgr) {
    if (!auth_mgr)
        return;
    if (auto* m = auth_mgr->metrics_registry())
        m->counter("yuzu_scim_provenance_denied_total").increment();
}

// ── Audit ────────────────────────────────────────────────────────────────

/// Emit a SCIM audit row. AuditStore::log is [[nodiscard]] bool; per the
/// evidence-integrity contract (audit_store.hpp) most callers on this
/// surface "set-and-proceed" rather than fail the IdP's request over an
/// audit-store hiccup — the caller decides whether to inspect the return.
/// M-AUDIT-FAILCLOSED: the three termination actions
/// (deactivated/deleted/reactivated) DO check it and fail closed (500) on a
/// false return — see `deactivate`/`reactivate`/the DELETE handler below.
/// Every failure (including `audit_store == nullptr`, an equally real
/// evidence gap) bumps `yuzu_scim_audit_write_failures_total` — the
/// companion metric that makes set-and-proceed defensible for the actions
/// that keep using it.
bool audit(auth::AuthManager* auth_mgr, AuditStore* audit_store, const httplib::Request& req,
          const std::string& action, const std::string& result, const std::string& target_id,
          const std::string& detail = {}) {
    if (!audit_store) {
        bump_audit_write_failure(auth_mgr, action);
        return false;
    }
    AuditEvent ev;
    ev.principal = kScimPrincipal;
    ev.principal_role = kScimPrincipal; // S-PRINCIPAL-ROLE — every other machine principal sets one
    ev.action = action;
    ev.target_type = "User";
    ev.target_id = target_id;
    ev.detail = detail;
    ev.result = result;
    ev.source_ip = req.remote_addr;
    ev.user_agent = req.get_header_value("User-Agent");
    bool ok = audit_store->log(ev);
    if (!ok) {
        spdlog::error("ScimRoutes: audit write failed action='{}' target_id='{}' result='{}'",
                     action, target_id, result);
        bump_audit_write_failure(auth_mgr, action);
    }
    return ok;
}

/// Build the `/scim/v2/Users` collection URL for this request so
/// `scim::user_to_json`'s `meta.location` / the `Location` header point at a
/// resolvable absolute URL. `--scim-enable` refuses to start without HTTPS
/// (see main.cpp), so "https" is the safe assumed scheme when no reverse
/// proxy sets X-Forwarded-Proto.
std::string location_base(const httplib::Request& req) {
    std::string scheme = req.get_header_value("X-Forwarded-Proto");
    if (scheme.empty())
        scheme = "https";
    std::string host = req.get_header_value("Host");
    return scheme + "://" + host + "/scim/v2/Users";
}

/// Bearer gate shared by every /scim/v2/* route. Reads ONLY the
/// `Authorization: Bearer <token>` header (no cookie/CSRF — there is no
/// session on this surface) and validates it against ScimStore's hashed
/// token(s). On failure, sends 401 + WWW-Authenticate + a SCIM error body,
/// audits `scim.auth.denied` + bumps `yuzu_scim_auth_failures_total`
/// (M-BEARER-AUDIT — a rejected bearer against a surface that can
/// provision/deprovision operator accounts is a credential-guess/replay
/// signal), and returns false so the caller can bail out of the handler.
bool require_bearer(ScimStore* scim_store, auth::AuthManager* auth_mgr, AuditStore* audit_store,
                    const httplib::Request& req, httplib::Response& res) {
    constexpr std::string_view kPrefix = "Bearer ";
    std::string token;
    if (auto h = req.get_header_value("Authorization");
        h.size() > kPrefix.size() && h.compare(0, kPrefix.size(), kPrefix) == 0) {
        token = h.substr(kPrefix.size());
    }
    if (!scim_store || !scim_store->is_open() || token.empty() ||
        !scim_store->validate_token(token)) {
        res.status = 401;
        res.set_header("WWW-Authenticate", "Bearer");
        res.set_content(scim::error(401, "invalid or missing bearer token").dump(), kScimJson);
        audit(auth_mgr, audit_store, req, "scim.auth.denied", "denied", "");
        bump_auth_failure(auth_mgr);
        return false;
    }
    return true;
}

/// LOAD-BEARING SECURITY INVARIANT — the provenance guard. SCIM must only
/// ever mutate accounts IT provisioned. `ScimStore::get_by_scim_id` already
/// gives defense against a locally-created admin (which has no scim_resource
/// row at all, so the caller 404s before this is even reached) — this is a
/// SECOND, independent check straight against the auth substrate: even if a
/// scim_resource row somehow existed for a non-SCIM account (e.g. a future
/// bug, or an operator hand-editing scim_resources), we refuse to touch the
/// underlying auth account unless `provisioning_source == "scim"` RIGHT NOW.
/// Returns true iff the mutation may proceed. On refusal, sends 404 (NEVER
/// 403 — a 403 would confirm to the IdP that a local account by this name
/// exists) and audits `scim.user.provenance_denied`.
bool provenance_ok(auth::AuthManager* auth_mgr, AuditStore* audit_store,
                   const httplib::Request& req, const std::string& username,
                   const std::string& scim_id, httplib::Response& res) {
    AuthDB* db = auth_mgr ? auth_mgr->auth_db_ptr() : nullptr;
    if (!db) {
        // No persistent AuthDB configured — SCIM cannot durably record/verify
        // provenance, so refuse rather than risk mutating an account we can't
        // prove we provisioned.
        spdlog::error("ScimRoutes: provenance check unavailable (no AuthDB) — refusing "
                     "mutation of '{}'",
                     username);
        send_scim_error(res, 404, "resource not found");
        audit(auth_mgr, audit_store, req, "scim.user.provenance_denied", "denied", scim_id,
             "no AuthDB configured");
        bump_provenance_denied(auth_mgr);
        return false;
    }
    auto source = db->get_provisioning_source(username);
    if (!source || *source != kProvisioningSourceScim) {
        spdlog::warn("SCIM: refusing to mutate account '{}' (scim_id={}) — "
                    "provisioning_source is not 'scim' (this account was not created by SCIM)",
                    username, scim_id);
        send_scim_error(res, 404, "resource not found");
        audit(auth_mgr, audit_store, req, "scim.user.provenance_denied", "denied", scim_id,
             "provisioning_source is not 'scim' for username=" + username);
        bump_provenance_denied(auth_mgr);
        return false;
    }
    return true;
}

/// M-DEPROV-ROLE (sec MEDIUM): refuse to deprovision (deactivate/delete) an
/// account whose CURRENT role is not `user` — an operator who elevated a
/// SCIM-provisioned account to admin has taken its lifecycle out of SCIM's
/// read-only ownership model; SCIM only ever tears down what it still
/// recognises as its own. Checked only while the account is still ACTIVE:
/// `AuthManager::get_user_role` reads the in-memory cache, which has no
/// entry for an already-soft-deleted row, so this guard fires exactly on
/// the live-to-inactive transition — where a prior role escalation would be
/// visible. Returns true iff the deprovision may proceed. On refusal sends
/// 404 (never 403 — matches the provenance guard's no-existence-oracle
/// posture) and reuses `scim.user.provenance_denied` (same "SCIM does not
/// own this account's lifecycle right now" refusal class).
bool deprovision_role_ok(auth::AuthManager* auth_mgr, AuditStore* audit_store,
                        const httplib::Request& req, const std::string& username,
                        const std::string& scim_id, httplib::Response& res) {
    auto role = auth_mgr->get_user_role(username);
    if (role.has_value() && *role != auth::Role::user) {
        spdlog::warn("SCIM: refusing to deprovision '{}' (scim_id={}) — role is not 'user' "
                    "(an operator has elevated this account outside SCIM's ownership)",
                    username, scim_id);
        send_scim_error(res, 404, "resource not found");
        audit(auth_mgr, audit_store, req, "scim.user.provenance_denied", "denied", scim_id,
             "role is not 'user' for username=" + username);
        bump_provenance_denied(auth_mgr);
        return false;
    }
    return true;
}

/// Deactivate the auth account backing `resource` (provenance- and role-
/// guarded) and mark the SCIM resource inactive. Shared by PATCH
/// active=false, PUT active=false, and DELETE. Returns false (and has
/// already sent a response) on provenance/role refusal, an AuthManager
/// failure, a ScimStore mirror-write failure (M-ATOMICITY, UP-5), or a
/// failed termination audit (M-AUDIT-FAILCLOSED).
bool deactivate(ScimStore* scim_store, auth::AuthManager* auth_mgr, AuditStore* audit_store,
                const httplib::Request& req, httplib::Response& res, const ScimResource& resource,
                const std::string& audit_action) {
    if (!provenance_ok(auth_mgr, audit_store, req, resource.username, resource.scim_id, res))
        return false;
    if (!deprovision_role_ok(auth_mgr, audit_store, req, resource.username, resource.scim_id, res))
        return false;
    if (!auth_mgr->remove_user(resource.username)) {
        spdlog::error("ScimRoutes: AuthManager::remove_user failed for '{}' (scim_id={})",
                     resource.username, resource.scim_id);
        send_scim_error(res, 500, "failed to deactivate the underlying account");
        audit(auth_mgr, audit_store, req, audit_action, "failure", resource.scim_id);
        return false;
    }
    // M-ATOMICITY (UP-5): the AuthManager (AuthDB connection) write above
    // succeeded; now persist the SCIM-side mirror on ScimStore's SEPARATE
    // connection. If THIS write fails, the auth account is already
    // deactivated but the SCIM resource still reports active=true — fail
    // closed (500) so the IdP retries. The retry is safe/idempotent:
    // remove_user() no-ops on an already-inactive row, set_active()
    // unconditionally re-applies. The irreducible window between the two
    // writes (a crash/kill exactly between them) is a documented residual —
    // reconciled by the IdP's next full sync.
    if (!scim_store->set_active(resource.scim_id, false)) {
        spdlog::error("ScimRoutes: ScimStore::set_active(false) failed for scim_id={} after the "
                     "underlying account was already deactivated — inconsistent state, failing "
                     "closed so the IdP retries",
                     resource.scim_id);
        send_scim_error(res, 500, "failed to persist the deactivated state");
        audit(auth_mgr, audit_store, req, audit_action, "failure", resource.scim_id,
             "auth account deactivated but scim_resource mirror write failed");
        return false;
    }
    // M-AUDIT-FAILCLOSED: a lost termination audit breaks CC6.8 evidence —
    // fail closed rather than report success with no evidence row. The
    // mutation already committed either way; the IdP's retry above is
    // idempotent, so failing here costs nothing but a retry.
    if (!audit(auth_mgr, audit_store, req, audit_action, "success", resource.scim_id)) {
        send_scim_error(res, 500, "state changed but the audit record failed to persist");
        return false;
    }
    return true;
}

/// Reactivate the auth account backing `resource` (provenance-guarded) and
/// mark the SCIM resource active again. Shared by PATCH active=true and PUT
/// active=true — the un-suspend counterpart of `deactivate`. The provenance
/// guard applies here too: reactivation is itself a mutation of the auth
/// account, so it must be refused (404) if the account isn't SCIM-owned —
/// same reasoning as deactivate/delete. Returns false (and has already sent
/// a response) on provenance refusal, an AuthManager failure, a ScimStore
/// mirror-write failure (M-ATOMICITY), or a failed termination-class audit
/// (M-AUDIT-FAILCLOSED — reactivation is as evidentially significant as
/// deactivation/delete: it restores access).
bool reactivate(ScimStore* scim_store, auth::AuthManager* auth_mgr, AuditStore* audit_store,
                const httplib::Request& req, httplib::Response& res, const ScimResource& resource) {
    if (!provenance_ok(auth_mgr, audit_store, req, resource.username, resource.scim_id, res))
        return false;
    if (!auth_mgr->reactivate_user(resource.username)) {
        spdlog::error("ScimRoutes: AuthManager::reactivate_user failed for '{}' (scim_id={})",
                     resource.username, resource.scim_id);
        send_scim_error(res, 500, "failed to reactivate the underlying account");
        audit(auth_mgr, audit_store, req, "scim.user.reactivated", "failure", resource.scim_id);
        return false;
    }
    if (!scim_store->set_active(resource.scim_id, true)) {
        spdlog::error("ScimRoutes: ScimStore::set_active(true) failed for scim_id={} after the "
                     "underlying account was already reactivated — inconsistent state, failing "
                     "closed so the IdP retries",
                     resource.scim_id);
        send_scim_error(res, 500, "failed to persist the reactivated state");
        audit(auth_mgr, audit_store, req, "scim.user.reactivated", "failure", resource.scim_id,
             "auth account reactivated but scim_resource mirror write failed");
        return false;
    }
    if (!audit(auth_mgr, audit_store, req, "scim.user.reactivated", "success", resource.scim_id)) {
        send_scim_error(res, 500, "state changed but the audit record failed to persist");
        return false;
    }
    return true;
}

} // namespace

void ScimRoutes::register_routes(httplib::Server& svr, ScimStore* scim_store,
                                 auth::AuthManager* auth_mgr, AuditStore* audit_store) {
    HttplibRouteSink sink(svr);
    register_routes(sink, scim_store, auth_mgr, audit_store);
}

void ScimRoutes::register_routes(HttpRouteSink& sink, ScimStore* scim_store,
                                 auth::AuthManager* auth_mgr, AuditStore* audit_store) {
    spdlog::info("SCIM routes: registering /scim/v2/* (provisioning surface)");

    // ── Discovery documents — PUBLIC-behind-the-bearer-gate (least exposure:
    // even the capability documents require the token, matching every other
    // /scim/v2/* route rather than carving out an unauthenticated exception). ──

    sink.Get("/scim/v2/ServiceProviderConfig",
            [scim_store, auth_mgr, audit_store](const httplib::Request& req,
                                                httplib::Response& res) {
                if (!require_bearer(scim_store, auth_mgr, audit_store, req, res))
                    return;
                res.set_content(scim::service_provider_config().dump(), kScimJson);
            });

    sink.Get("/scim/v2/ResourceTypes",
            [scim_store, auth_mgr, audit_store](const httplib::Request& req,
                                                httplib::Response& res) {
                if (!require_bearer(scim_store, auth_mgr, audit_store, req, res))
                    return;
                res.set_content(scim::resource_types().dump(), kScimJson);
            });

    sink.Get("/scim/v2/Schemas",
            [scim_store, auth_mgr, audit_store](const httplib::Request& req,
                                                httplib::Response& res) {
                if (!require_bearer(scim_store, auth_mgr, audit_store, req, res))
                    return;
                res.set_content(scim::schemas().dump(), kScimJson);
            });

    // ── POST /scim/v2/Users — provision. ──────────────────────────────────

    sink.Post("/scim/v2/Users", [scim_store, auth_mgr, audit_store](const httplib::Request& req,
                                                                    httplib::Response& res) {
        if (!require_bearer(scim_store, auth_mgr, audit_store, req, res)) {
            record_request(auth_mgr, "create", res.status);
            return;
        }
        if (req.body.size() > kMaxBodyBytes) {
            send_scim_error(res, 413, "request body too large");
            record_request(auth_mgr, "create", 413);
            return;
        }
        json body;
        try {
            body = json::parse(req.body);
        } catch (const std::exception&) {
            send_scim_error(res, 400, "request body is not valid JSON", "invalidValue");
            record_request(auth_mgr, "create", 400);
            return;
        }
        auto parsed = scim::parse_user(body);
        if (!parsed) {
            send_scim_error(res, parsed.error());
            record_request(auth_mgr, "create", parsed.error().status);
            return;
        }
        const auto& input = *parsed;
        if (!is_valid_username(input.user_name)) {
            send_scim_error(res, 400,
                           "userName is not a valid Yuzu username (1-64 chars, alnum/._-)",
                           "invalidValue");
            record_request(auth_mgr, "create", 400);
            return;
        }

        // Step 1 (unchanged): a LIVE scim_resource row means this identity
        // is provisioned RIGHT NOW — a re-POST for an already-provisioned
        // (active OR PATCH-deactivated-but-not-DELETEd) identity is a
        // protocol error; the IdP should PATCH/PUT instead.
        if (scim_store->get_by_username(input.user_name).has_value()) {
            send_scim_error(res, 409, "userName already exists", "uniqueness");
            audit(auth_mgr, audit_store, req, "scim.user.provisioned", "denied", input.user_name,
                 "userName already exists");
            record_request(auth_mgr, "create", 409);
            return;
        }

        // Step 2 (M-LIFECYCLE — revive-on-reprovision): no live scim_resource
        // row, so decide fresh-create vs. revive vs. refuse from
        // provisioning_source, read INCLUSIVE of inactive rows
        // (get_provisioning_source's contract) so a DELETE-then-re-POST
        // tombstone and a half-create orphan both read back "scim" here —
        // exactly the state a returning employee's account is in
        // (fixes UP-1/2/3's deadlock: previously DELETE removed the
        // scim_resource but ON CONFLICT DO NOTHING made re-provisioning via
        // POST permanently fail).
        AuthDB* db = auth_mgr->auth_db_ptr();
        if (!db) {
            spdlog::error("ScimRoutes: cannot provision '{}' — no AuthDB configured (SCIM "
                         "provisioning requires durable provenance tracking)",
                         input.user_name);
            send_scim_error(res, 500, "SCIM provisioning is unavailable (no AuthDB configured)");
            audit(auth_mgr, audit_store, req, "scim.user.provisioned", "failure", input.user_name);
            record_request(auth_mgr, "create", 500);
            return;
        }
        auto source_result = db->get_provisioning_source(input.user_name);
        if (source_result.has_value() && *source_result != kProvisioningSourceScim) {
            // A local (or otherwise-sourced) account already owns this
            // username — SCIM must never adopt it (S-UNIQUE-DBREAD: this DB
            // read also catches a SOFT-DELETED local account the in-memory
            // get_user_role cache would have missed).
            send_scim_error(res, 409, "userName already exists", "uniqueness");
            audit(auth_mgr, audit_store, req, "scim.user.provisioned", "denied", input.user_name,
                 "userName already exists (non-SCIM account)");
            record_request(auth_mgr, "create", 409);
            return;
        }

        if (source_result.has_value()) {
            // REVIVE: a tombstoned or half-created SCIM account this IdP
            // previously provisioned. Reactivate the EXISTING auth row —
            // never upsert_user again (that would UserAlreadyExists
            // pointlessly, and reactivate_user is the correct idempotent
            // primitive: it does not touch credentials/rotate the discard
            // password).
            if (!auth_mgr->reactivate_user(input.user_name)) {
                spdlog::error("ScimRoutes: reactivate_user failed reviving '{}'",
                             input.user_name);
                send_scim_error(res, 500, "failed to revive the underlying account");
                audit(auth_mgr, audit_store, req, "scim.user.provisioned", "failure",
                     input.user_name);
                record_request(auth_mgr, "create", 500);
                return;
            }
        } else {
            // FRESH create (UP-9 duplicate-POST race handled below).
            // SCIM-provisioned accounts authenticate via the IdP/SSO only —
            // mint a long CSPRNG password and discard it immediately so
            // local password login is unusable (an unknowable password, not
            // a weak one). Always provisioned at the read-only 'user' role.
            std::vector<uint8_t> pw_bytes;
            try {
                pw_bytes = auth::AuthManager::random_bytes(32);
            } catch (const std::exception& e) {
                // S-RANDBYTES: random_bytes throws on a CSPRNG/RAND_bytes
                // failure — catch rather than let it unwind to a bare 500.
                spdlog::error(
                    "ScimRoutes: CSPRNG failure minting a discard password for '{}': {}",
                    input.user_name, e.what());
                send_scim_error(res, 503, "temporarily unable to provision (CSPRNG unavailable)");
                audit(auth_mgr, audit_store, req, "scim.user.provisioned", "failure",
                     input.user_name);
                record_request(auth_mgr, "create", 503);
                return;
            }
            auto discard_password = auth::AuthManager::bytes_to_hex(pw_bytes);
            if (!auth_mgr->upsert_user(input.user_name, discard_password, auth::Role::user)) {
                // UP-9: distinguish a genuine DB failure from a concurrent
                // duplicate POST that won the race between the uniqueness
                // check above and this write — re-read: if the account now
                // resolves, someone else just created it.
                if (auth_mgr->get_user_role(input.user_name).has_value()) {
                    send_scim_error(res, 409, "userName already exists", "uniqueness");
                    audit(auth_mgr, audit_store, req, "scim.user.provisioned", "denied",
                         input.user_name, "userName already exists (concurrent create)");
                    record_request(auth_mgr, "create", 409);
                    return;
                }
                send_scim_error(res, 500, "failed to create the underlying account");
                audit(auth_mgr, audit_store, req, "scim.user.provisioned", "failure",
                     input.user_name);
                record_request(auth_mgr, "create", 500);
                return;
            }

            // S-IDENTITY-SRC: SCIM is its own login surface (IdP-driven SSO,
            // no usable local password) — distinct from the v6 'local'
            // default, which would render this account as local-login-
            // capable in the Settings UI. Best-effort: a failure here
            // doesn't block provisioning (the account still functions; only
            // the Settings UI badge would be wrong).
            if (auto r = db->set_identity_source(input.user_name, "scim"); !r) {
                spdlog::warn("ScimRoutes: set_identity_source failed for '{}' — the account "
                            "will still function, but the Settings UI may misrender its login "
                            "surface",
                            input.user_name);
            }

            // M-ORPHAN (UP-6/B1): set provenance BEFORE creating the
            // scim_resource row, and roll back the just-created auth account
            // if it fails — never leave an orphaned account with no SCIM
            // mapping AND no provenance marker (unmanageable by SCIM
            // forever after — a future revive attempt would read
            // provisioning_source=='local' and refuse it).
            if (auto r = db->set_provisioning_source(input.user_name,
                                                     std::string(kProvisioningSourceScim));
                !r) {
                spdlog::error("ScimRoutes: set_provisioning_source failed for '{}', rolling back",
                             input.user_name);
                auth_mgr->remove_user(input.user_name);
                send_scim_error(res, 500, "failed to record provisioning provenance");
                audit(auth_mgr, audit_store, req, "scim.user.provisioned", "failure",
                     input.user_name);
                record_request(auth_mgr, "create", 500);
                return;
            }
        }

        auto resource = scim_store->create_resource(input.user_name, input.external_id);
        if (!resource) {
            // Half-create orphan (whether this POST just freshly created the
            // auth row, or revived one): roll back to a deactivated
            // tombstone rather than leaving an ACTIVE, SCIM-untracked
            // account. The next POST for the same userName retries this
            // exact step (provisioning_source == "scim" still holds).
            auth_mgr->remove_user(input.user_name);
            send_scim_error(res, 500, "failed to create the SCIM resource mapping");
            audit(auth_mgr, audit_store, req, "scim.user.provisioned", "failure",
                 input.user_name);
            record_request(auth_mgr, "create", 500);
            return;
        }

        // Honour an explicit active:false on create (some IdPs stage a user
        // deactivated) by immediately deactivating the account we just
        // made/revived.
        if (input.active.has_value() && !*input.active) {
            if (!auth_mgr->remove_user(input.user_name)) {
                spdlog::error("ScimRoutes: remove_user failed honouring active:false on create "
                             "for '{}' — the account remains active",
                             input.user_name);
            }
            scim_store->set_active(resource->scim_id, false);
            // S-POST-REFETCH: re-fetch so the 201 body's ETag/meta.version/
            // lastModified reflect the bump set_active just made — PUT/PATCH
            // already re-fetch after their own mutations; mirror that here
            // so a later GET can't disagree with what this response claimed.
            if (auto refreshed = scim_store->get_by_scim_id(resource->scim_id))
                resource = refreshed;
            else
                resource->active = false; // M-OPTDEREF fallback — shouldn't happen
        }

        auto base = location_base(req);
        res.status = 201;
        res.set_header("Location", base + "/" + resource->scim_id);
        res.set_header("ETag", "W/\"" + std::to_string(resource->etag_version) + "\"");
        res.set_content(scim::user_to_json(*resource, base).dump(), kScimJson);
        // "provisioned" is NOT a termination action — set-and-proceed per
        // the class distinction in M-AUDIT-FAILCLOSED; the 201 above already
        // committed regardless of whether this row persists.
        audit(auth_mgr, audit_store, req, "scim.user.provisioned", "success", resource->scim_id);
        record_request(auth_mgr, "create", 201);
    });

    // ── GET /scim/v2/Users/{id} ────────────────────────────────────────────

    sink.Get(R"(/scim/v2/Users/([0-9a-fA-F]+))",
            [scim_store, auth_mgr, audit_store](const httplib::Request& req,
                                                httplib::Response& res) {
                if (!require_bearer(scim_store, auth_mgr, audit_store, req, res)) {
                    record_request(auth_mgr, "get", res.status);
                    return;
                }
                auto id = req.matches[1].str();
                auto resource = scim_store->get_by_scim_id(id);
                if (!resource) {
                    send_scim_error(res, 404, "resource not found");
                    record_request(auth_mgr, "get", 404);
                    return;
                }
                res.set_content(scim::user_to_json(*resource, location_base(req)).dump(),
                               kScimJson);
                record_request(auth_mgr, "get", 200);
            });

    // ── GET /scim/v2/Users — list / filter. ───────────────────────────────

    sink.Get("/scim/v2/Users",
            [scim_store, auth_mgr, audit_store](const httplib::Request& req,
                                                httplib::Response& res) {
                if (!require_bearer(scim_store, auth_mgr, audit_store, req, res)) {
                    record_request(auth_mgr, "list", res.status);
                    return;
                }
                auto base = location_base(req);

                int start_index = 1;
                if (req.has_param("startIndex")) {
                    try {
                        start_index = std::stoi(req.get_param_value("startIndex"));
                    } catch (const std::exception&) {
                        send_scim_error(res, 400, "startIndex must be an integer",
                                       "invalidValue");
                        record_request(auth_mgr, "list", 400);
                        return;
                    }
                }
                int count = 100;
                if (req.has_param("count")) {
                    try {
                        count = std::stoi(req.get_param_value("count"));
                    } catch (const std::exception&) {
                        send_scim_error(res, 400, "count must be an integer", "invalidValue");
                        record_request(auth_mgr, "list", 400);
                        return;
                    }
                }
                // S-CLAMP-COUNT: never serve more than the maxResults this
                // server advertises in ServiceProviderConfig, regardless of
                // what the caller asks for.
                if (count > scim::kMaxScimListResults)
                    count = scim::kMaxScimListResults;

                if (req.has_param("filter")) {
                    auto filter_username = scim::parse_username_filter(req.get_param_value("filter"));
                    if (!filter_username) {
                        send_scim_error(res, filter_username.error());
                        record_request(auth_mgr, "list", filter_username.error().status);
                        return;
                    }
                    std::vector<json> resources;
                    int total = 0;
                    if (auto resource = scim_store->get_by_username(*filter_username)) {
                        resources.push_back(scim::user_to_json(*resource, base));
                        total = 1;
                    }
                    res.set_content(
                        scim::list_response(resources, total, 1,
                                           static_cast<int>(resources.size()))
                            .dump(),
                        kScimJson);
                    record_request(auth_mgr, "list", 200);
                    return;
                }

                int total = 0;
                auto page = scim_store->list(start_index, count, total);
                std::vector<json> resources;
                resources.reserve(page.size());
                for (const auto& r : page)
                    resources.push_back(scim::user_to_json(r, base));
                res.set_content(scim::list_response(resources, total, start_index,
                                                    static_cast<int>(resources.size()))
                                    .dump(),
                                kScimJson);
                record_request(auth_mgr, "list", 200);
            });

    // ── PUT /scim/v2/Users/{id} — full replace (identity fields only). ────

    sink.Put(R"(/scim/v2/Users/([0-9a-fA-F]+))",
            [scim_store, auth_mgr, audit_store](const httplib::Request& req,
                                                httplib::Response& res) {
                if (!require_bearer(scim_store, auth_mgr, audit_store, req, res)) {
                    record_request(auth_mgr, "replace", res.status);
                    return;
                }
                auto id = req.matches[1].str();
                auto resource = scim_store->get_by_scim_id(id);
                if (!resource) {
                    send_scim_error(res, 404, "resource not found");
                    record_request(auth_mgr, "replace", 404);
                    return;
                }
                if (req.body.size() > kMaxBodyBytes) {
                    send_scim_error(res, 413, "request body too large");
                    record_request(auth_mgr, "replace", 413);
                    return;
                }
                json body;
                try {
                    body = json::parse(req.body);
                } catch (const std::exception&) {
                    send_scim_error(res, 400, "request body is not valid JSON", "invalidValue");
                    record_request(auth_mgr, "replace", 400);
                    return;
                }
                auto parsed = scim::parse_user(body);
                if (!parsed) {
                    send_scim_error(res, parsed.error());
                    record_request(auth_mgr, "replace", parsed.error().status);
                    return;
                }
                const auto& input = *parsed;

                // Rename is out of scope for slice 1 (the SCIM `id`, not
                // `userName`, is the stable identifier IdPs are expected to
                // key on going forward) — refuse rather than silently
                // ignoring the IdP's intent.
                if (input.user_name != resource->username) {
                    send_scim_error(res, 400,
                                   "userName change via PUT is not supported in this slice",
                                   "mutability");
                    record_request(auth_mgr, "replace", 400);
                    return;
                }

                bool active_transitioned = false;
                if (input.active.has_value() && !*input.active && resource->active) {
                    if (!deactivate(scim_store, auth_mgr, audit_store, req, res, *resource,
                                    "scim.user.deactivated")) {
                        record_request(auth_mgr, "replace", res.status);
                        return;
                    }
                    resource->active = false;
                    active_transitioned = true;
                } else if (input.active.has_value() && *input.active && !resource->active) {
                    if (!reactivate(scim_store, auth_mgr, audit_store, req, res, *resource)) {
                        record_request(auth_mgr, "replace", res.status);
                        return;
                    }
                    resource->active = true;
                    active_transitioned = true;
                }

                if (!scim_store->update_resource(resource->scim_id, resource->username,
                                                 input.external_id)) {
                    send_scim_error(res, 500, "failed to update the SCIM resource mapping");
                    record_request(auth_mgr, "replace", 500);
                    return;
                }
                auto updated = scim_store->get_by_scim_id(resource->scim_id);
                if (!updated) {
                    // M-OPTDEREF (UP-4): a concurrent DELETE emptied the
                    // resource between the mutation above and this
                    // re-fetch. The mutation already committed — 500 (not
                    // 404, which would misleadingly imply "never existed").
                    spdlog::error("ScimRoutes: PUT — resource scim_id={} vanished mid-request",
                                 resource->scim_id);
                    send_scim_error(res, 500, "resource state changed mid-request");
                    record_request(auth_mgr, "replace", 500);
                    return;
                }
                if (!active_transitioned) {
                    // deactivate()/reactivate() already audited their own
                    // action (and already fail closed on their own audit
                    // failure); avoid a duplicate "updated" row for that
                    // case. "updated" itself is NOT a termination action —
                    // set-and-proceed.
                    audit(auth_mgr, audit_store, req, "scim.user.updated", "success",
                         resource->scim_id);
                }
                res.set_content(scim::user_to_json(*updated, location_base(req)).dump(),
                               kScimJson);
                record_request(auth_mgr, "replace", 200);
            });

    // ── PATCH /scim/v2/Users/{id} — the critical deprovision path. ────────

    sink.Patch(R"(/scim/v2/Users/([0-9a-fA-F]+))",
              [scim_store, auth_mgr, audit_store](const httplib::Request& req,
                                                  httplib::Response& res) {
                  if (!require_bearer(scim_store, auth_mgr, audit_store, req, res)) {
                      record_request(auth_mgr, "patch", res.status);
                      return;
                  }
                  auto id = req.matches[1].str();
                  auto resource = scim_store->get_by_scim_id(id);
                  if (!resource) {
                      send_scim_error(res, 404, "resource not found");
                      record_request(auth_mgr, "patch", 404);
                      return;
                  }
                  if (req.body.size() > kMaxBodyBytes) {
                      send_scim_error(res, 413, "request body too large");
                      record_request(auth_mgr, "patch", 413);
                      return;
                  }
                  json body;
                  try {
                      body = json::parse(req.body);
                  } catch (const std::exception&) {
                      send_scim_error(res, 400, "request body is not valid JSON", "invalidValue");
                      record_request(auth_mgr, "patch", 400);
                      return;
                  }
                  auto parsed = scim::parse_patch(body);
                  if (!parsed) {
                      send_scim_error(res, parsed.error());
                      record_request(auth_mgr, "patch", parsed.error().status);
                      return;
                  }
                  const auto& patch = *parsed;

                  // Validate the unsupported-mutation case BEFORE applying
                  // anything else, so a body combining an unsupported
                  // userName change with a supported active/externalId
                  // change can't leave a partial mutation committed behind
                  // a 400 response.
                  if (patch.user_name.has_value() && *patch.user_name != resource->username) {
                      send_scim_error(res, 400,
                                     "userName change via PATCH is not supported in this slice",
                                     "mutability");
                      record_request(auth_mgr, "patch", 400);
                      return;
                  }

                  bool active_transitioned = false;
                  if (patch.active.has_value()) {
                      if (!*patch.active && resource->active) {
                          if (!deactivate(scim_store, auth_mgr, audit_store, req, res, *resource,
                                          "scim.user.deactivated")) {
                              record_request(auth_mgr, "patch", res.status);
                              return;
                          }
                          resource->active = false;
                          active_transitioned = true;
                      } else if (*patch.active && !resource->active) {
                          if (!reactivate(scim_store, auth_mgr, audit_store, req, res,
                                         *resource)) {
                              record_request(auth_mgr, "patch", res.status);
                              return;
                          }
                          resource->active = true;
                          active_transitioned = true;
                      }
                      // else: no-op (already in the requested state).
                  }

                  if (patch.external_id.has_value()) {
                      if (!scim_store->update_resource(resource->scim_id, resource->username,
                                                       *patch.external_id)) {
                          send_scim_error(res, 500, "failed to update the SCIM resource mapping");
                          record_request(auth_mgr, "patch", 500);
                          return;
                      }
                  }

                  auto updated = scim_store->get_by_scim_id(resource->scim_id);
                  if (!updated) {
                      // M-OPTDEREF (UP-4): a concurrent DELETE emptied the
                      // resource between the mutation above and this
                      // re-fetch.
                      spdlog::error("ScimRoutes: PATCH — resource scim_id={} vanished "
                                   "mid-request",
                                   resource->scim_id);
                      send_scim_error(res, 500, "resource state changed mid-request");
                      record_request(auth_mgr, "patch", 500);
                      return;
                  }
                  if (!active_transitioned) {
                      // deactivate()/reactivate() already audited their own
                      // action; avoid a duplicate "updated" row for that
                      // case.
                      audit(auth_mgr, audit_store, req, "scim.user.updated", "success",
                           resource->scim_id);
                  }
                  res.set_content(scim::user_to_json(*updated, location_base(req)).dump(),
                                 kScimJson);
                  record_request(auth_mgr, "patch", 200);
              });

    // ── DELETE /scim/v2/Users/{id} ─────────────────────────────────────────

    sink.Delete(R"(/scim/v2/Users/([0-9a-fA-F]+))",
               [scim_store, auth_mgr, audit_store](const httplib::Request& req,
                                                   httplib::Response& res) {
                   if (!require_bearer(scim_store, auth_mgr, audit_store, req, res)) {
                       record_request(auth_mgr, "delete", res.status);
                       return;
                   }
                   auto id = req.matches[1].str();
                   auto resource = scim_store->get_by_scim_id(id);
                   if (!resource) {
                       send_scim_error(res, 404, "resource not found");
                       record_request(auth_mgr, "delete", 404);
                       return;
                   }
                   if (resource->active) {
                       if (!provenance_ok(auth_mgr, audit_store, req, resource->username, id,
                                         res)) {
                           record_request(auth_mgr, "delete", res.status);
                           return;
                       }
                       if (!deprovision_role_ok(auth_mgr, audit_store, req, resource->username,
                                               id, res)) {
                           record_request(auth_mgr, "delete", res.status);
                           return;
                       }
                       if (!auth_mgr->remove_user(resource->username)) {
                           send_scim_error(res, 500, "failed to deactivate the underlying account");
                           audit(auth_mgr, audit_store, req, "scim.user.deleted", "failure", id);
                           record_request(auth_mgr, "delete", 500);
                           return;
                       }
                   } else {
                       // Already deactivated — still re-verify provenance
                       // before the DELETE removes the mapping row, so a
                       // scim_resource somehow pointing at a non-SCIM
                       // account still can't be wiped out from under it. No
                       // role re-check here: the account is already
                       // inactive, so there is nothing further being torn
                       // down (see deprovision_role_ok's doc comment — the
                       // in-memory role cache has no entry to check anyway).
                       if (!provenance_ok(auth_mgr, audit_store, req, resource->username, id,
                                         res)) {
                           record_request(auth_mgr, "delete", res.status);
                           return;
                       }
                   }

                   // M-ATOMICITY (UP-5): check the ScimStore write too. On
                   // the resource->active branch above, the AuthManager
                   // write already succeeded — a failure here leaves the
                   // account deactivated but the mapping row still present;
                   // fail closed so the IdP retries (idempotent:
                   // remove_user no-ops on an already-inactive row,
                   // delete_by_scim_id re-applies against the still-present
                   // row).
                   if (!scim_store->delete_by_scim_id(id)) {
                       spdlog::error("ScimRoutes: ScimStore::delete_by_scim_id failed for "
                                    "scim_id={}",
                                    id);
                       send_scim_error(res, 500, "failed to remove the SCIM resource mapping");
                       audit(auth_mgr, audit_store, req, "scim.user.deleted", "failure", id);
                       record_request(auth_mgr, "delete", 500);
                       return;
                   }
                   // M-AUDIT-FAILCLOSED: a lost termination audit breaks
                   // CC6.8 evidence — fail closed rather than report 204
                   // with no evidence row.
                   if (!audit(auth_mgr, audit_store, req, "scim.user.deleted", "success", id)) {
                       send_scim_error(res, 500,
                                      "state changed but the audit record failed to persist");
                       record_request(auth_mgr, "delete", 500);
                       return;
                   }
                   res.status = 204;
                   record_request(auth_mgr, "delete", 204);
               });
}

} // namespace yuzu::server
