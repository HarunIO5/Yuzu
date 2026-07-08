#include "scim_routes.hpp"

#include "audit_store.hpp"

#include <yuzu/server/auth_db.hpp>
#include <yuzu/server/scim_json.hpp>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <cstddef>
#include <string>

namespace yuzu::server {

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

/// Emit a SCIM audit row. AuditStore::log is [[nodiscard]] bool; per the
/// evidence-integrity contract (audit_store.hpp) a caller whose OPERATION
/// already succeeded/failed independently of the audit write should
/// "set-and-proceed" rather than fail the IdP's request over an audit-store
/// hiccup — we log an spdlog error and rely on AuditStore's own
/// `emit_failed_` counter (already wired to a /metrics gauge in server.cpp)
/// for alerting, rather than inventing a second failure counter here.
void audit(AuditStore* audit_store, const httplib::Request& req, const std::string& action,
           const std::string& result, const std::string& target_id,
           const std::string& detail = {}) {
    if (!audit_store)
        return;
    AuditEvent ev;
    ev.principal = kScimPrincipal;
    ev.action = action;
    ev.target_type = "User";
    ev.target_id = target_id;
    ev.detail = detail;
    ev.result = result;
    ev.source_ip = req.remote_addr;
    ev.user_agent = req.get_header_value("User-Agent");
    if (!audit_store->log(ev)) {
        spdlog::error("ScimRoutes: audit write failed action='{}' target_id='{}' result='{}'",
                     action, target_id, result);
    }
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
/// token(s). On failure, sends 401 + WWW-Authenticate + a SCIM error body
/// and returns false so the caller can bail out of the handler.
bool require_bearer(ScimStore* scim_store, const httplib::Request& req, httplib::Response& res) {
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
        audit(audit_store, req, "scim.user.provenance_denied", "denied", scim_id,
             "no AuthDB configured");
        return false;
    }
    auto source = db->get_provisioning_source(username);
    if (!source || *source != "scim") {
        spdlog::warn("SCIM: refusing to mutate account '{}' (scim_id={}) — "
                    "provisioning_source is not 'scim' (this account was not created by SCIM)",
                    username, scim_id);
        send_scim_error(res, 404, "resource not found");
        audit(audit_store, req, "scim.user.provenance_denied", "denied", scim_id,
             "provisioning_source is not 'scim' for username=" + username);
        return false;
    }
    return true;
}

/// Deactivate the auth account backing `resource` (provenance-guarded) and
/// mark the SCIM resource inactive. Shared by PATCH active=false, PUT
/// active=false, and DELETE. Returns false (and has already sent a response)
/// on provenance refusal or an AuthManager failure.
bool deactivate(ScimStore* scim_store, auth::AuthManager* auth_mgr, AuditStore* audit_store,
                const httplib::Request& req, httplib::Response& res, const ScimResource& resource,
                const std::string& audit_action) {
    if (!provenance_ok(auth_mgr, audit_store, req, resource.username, resource.scim_id, res))
        return false;
    if (!auth_mgr->remove_user(resource.username)) {
        spdlog::error("ScimRoutes: AuthManager::remove_user failed for '{}' (scim_id={})",
                     resource.username, resource.scim_id);
        send_scim_error(res, 500, "failed to deactivate the underlying account");
        audit(audit_store, req, audit_action, "failure", resource.scim_id);
        return false;
    }
    scim_store->set_active(resource.scim_id, false);
    audit(audit_store, req, audit_action, "success", resource.scim_id);
    return true;
}

/// Reactivate the auth account backing `resource` (provenance-guarded) and
/// mark the SCIM resource active again. Shared by PATCH active=true and PUT
/// active=true — the un-suspend counterpart of `deactivate`. The provenance
/// guard applies here too: reactivation is itself a mutation of the auth
/// account, so it must be refused (404) if the account isn't SCIM-owned —
/// same reasoning as deactivate/delete. Returns false (and has already sent
/// a response) on provenance refusal or an AuthManager failure.
bool reactivate(ScimStore* scim_store, auth::AuthManager* auth_mgr, AuditStore* audit_store,
                const httplib::Request& req, httplib::Response& res, const ScimResource& resource) {
    if (!provenance_ok(auth_mgr, audit_store, req, resource.username, resource.scim_id, res))
        return false;
    if (!auth_mgr->reactivate_user(resource.username)) {
        spdlog::error("ScimRoutes: AuthManager::reactivate_user failed for '{}' (scim_id={})",
                     resource.username, resource.scim_id);
        send_scim_error(res, 500, "failed to reactivate the underlying account");
        audit(audit_store, req, "scim.user.reactivated", "failure", resource.scim_id);
        return false;
    }
    scim_store->set_active(resource.scim_id, true);
    audit(audit_store, req, "scim.user.reactivated", "success", resource.scim_id);
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
            [scim_store](const httplib::Request& req, httplib::Response& res) {
                if (!require_bearer(scim_store, req, res))
                    return;
                res.set_content(scim::service_provider_config().dump(), kScimJson);
            });

    sink.Get("/scim/v2/ResourceTypes",
            [scim_store](const httplib::Request& req, httplib::Response& res) {
                if (!require_bearer(scim_store, req, res))
                    return;
                res.set_content(scim::resource_types().dump(), kScimJson);
            });

    sink.Get("/scim/v2/Schemas", [scim_store](const httplib::Request& req, httplib::Response& res) {
        if (!require_bearer(scim_store, req, res))
            return;
        res.set_content(scim::schemas().dump(), kScimJson);
    });

    // ── POST /scim/v2/Users — provision. ──────────────────────────────────

    sink.Post("/scim/v2/Users", [scim_store, auth_mgr, audit_store](const httplib::Request& req,
                                                                    httplib::Response& res) {
        if (!require_bearer(scim_store, req, res))
            return;
        if (req.body.size() > kMaxBodyBytes) {
            send_scim_error(res, 413, "request body too large");
            return;
        }
        json body;
        try {
            body = json::parse(req.body);
        } catch (const std::exception&) {
            send_scim_error(res, 400, "request body is not valid JSON", "invalidValue");
            return;
        }
        auto parsed = scim::parse_user(body);
        if (!parsed) {
            send_scim_error(res, parsed.error());
            return;
        }
        const auto& input = *parsed;
        if (!is_valid_username(input.user_name)) {
            send_scim_error(res, 400,
                           "userName is not a valid Yuzu username (1-64 chars, alnum/._-)",
                           "invalidValue");
            return;
        }

        // Uniqueness (RFC 7644 §3.3): a SCIM push must NEVER take over a
        // pre-existing account, whether it's a locally-created admin or an
        // already-provisioned SCIM user (active or previously deprovisioned —
        // re-provisioning a deprovisioned identity is out of scope for this
        // slice; see scim_routes.cpp file header TODO). Check BOTH the auth
        // substrate and the SCIM resource map before mutating anything.
        if (auth_mgr->get_user_role(input.user_name).has_value() ||
            scim_store->get_by_username(input.user_name).has_value()) {
            send_scim_error(res, 409, "userName already exists", "uniqueness");
            audit(audit_store, req, "scim.user.provisioned", "denied", input.user_name,
                 "userName already exists");
            return;
        }

        // SCIM-provisioned accounts authenticate via the IdP/SSO only — mint
        // a long CSPRNG password and discard it immediately so local
        // password login is unusable (an unknowable password, not a weak
        // one). Always provisioned at the read-only 'user' role: slice 1
        // never mints admins via SCIM, so a compromised/misconfigured IdP
        // integration cannot escalate an operator to admin.
        auto discard_password = auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(32));
        if (!auth_mgr->upsert_user(input.user_name, discard_password, auth::Role::user)) {
            send_scim_error(res, 500, "failed to create the underlying account");
            audit(audit_store, req, "scim.user.provisioned", "failure", input.user_name);
            return;
        }
        if (AuthDB* db = auth_mgr->auth_db_ptr()) {
            if (auto r = db->set_provisioning_source(input.user_name, "scim"); !r) {
                spdlog::error("ScimRoutes: set_provisioning_source failed for '{}'",
                             input.user_name);
            }
        }

        auto resource = scim_store->create_resource(input.user_name, input.external_id);
        if (!resource) {
            // Roll back the just-created account so we don't leave an
            // orphaned auth row with no SCIM mapping.
            auth_mgr->remove_user(input.user_name);
            send_scim_error(res, 500, "failed to create the SCIM resource mapping");
            audit(audit_store, req, "scim.user.provisioned", "failure", input.user_name);
            return;
        }

        // Honour an explicit active:false on create (some IdPs stage a user
        // deactivated) by immediately deactivating the account we just made.
        if (input.active.has_value() && !*input.active) {
            auth_mgr->remove_user(input.user_name);
            scim_store->set_active(resource->scim_id, false);
            resource->active = false;
        }

        auto base = location_base(req);
        res.status = 201;
        res.set_header("Location", base + "/" + resource->scim_id);
        res.set_header("ETag", "W/\"" + std::to_string(resource->etag_version) + "\"");
        res.set_content(scim::user_to_json(*resource, base).dump(), kScimJson);
        audit(audit_store, req, "scim.user.provisioned", "success", resource->scim_id);
    });

    // ── GET /scim/v2/Users/{id} ────────────────────────────────────────────

    sink.Get(R"(/scim/v2/Users/([0-9a-fA-F]+))",
            [scim_store](const httplib::Request& req, httplib::Response& res) {
                if (!require_bearer(scim_store, req, res))
                    return;
                auto id = req.matches[1].str();
                auto resource = scim_store->get_by_scim_id(id);
                if (!resource) {
                    send_scim_error(res, 404, "resource not found");
                    return;
                }
                res.set_content(scim::user_to_json(*resource, location_base(req)).dump(),
                               kScimJson);
            });

    // ── GET /scim/v2/Users — list / filter. ───────────────────────────────

    sink.Get("/scim/v2/Users", [scim_store](const httplib::Request& req, httplib::Response& res) {
        if (!require_bearer(scim_store, req, res))
            return;
        auto base = location_base(req);

        int start_index = 1;
        if (req.has_param("startIndex")) {
            try {
                start_index = std::stoi(req.get_param_value("startIndex"));
            } catch (const std::exception&) {
                send_scim_error(res, 400, "startIndex must be an integer", "invalidValue");
                return;
            }
        }
        int count = 100;
        if (req.has_param("count")) {
            try {
                count = std::stoi(req.get_param_value("count"));
            } catch (const std::exception&) {
                send_scim_error(res, 400, "count must be an integer", "invalidValue");
                return;
            }
        }

        if (req.has_param("filter")) {
            auto filter_username = scim::parse_username_filter(req.get_param_value("filter"));
            if (!filter_username) {
                send_scim_error(res, filter_username.error());
                return;
            }
            std::vector<json> resources;
            int total = 0;
            if (auto resource = scim_store->get_by_username(*filter_username)) {
                resources.push_back(scim::user_to_json(*resource, base));
                total = 1;
            }
            res.set_content(
                scim::list_response(resources, total, 1, static_cast<int>(resources.size()))
                    .dump(),
                kScimJson);
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
    });

    // ── PUT /scim/v2/Users/{id} — full replace (identity fields only). ────

    sink.Put(R"(/scim/v2/Users/([0-9a-fA-F]+))",
            [scim_store, auth_mgr, audit_store](const httplib::Request& req,
                                                httplib::Response& res) {
                if (!require_bearer(scim_store, req, res))
                    return;
                auto id = req.matches[1].str();
                auto resource = scim_store->get_by_scim_id(id);
                if (!resource) {
                    send_scim_error(res, 404, "resource not found");
                    return;
                }
                if (req.body.size() > kMaxBodyBytes) {
                    send_scim_error(res, 413, "request body too large");
                    return;
                }
                json body;
                try {
                    body = json::parse(req.body);
                } catch (const std::exception&) {
                    send_scim_error(res, 400, "request body is not valid JSON", "invalidValue");
                    return;
                }
                auto parsed = scim::parse_user(body);
                if (!parsed) {
                    send_scim_error(res, parsed.error());
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
                    return;
                }

                bool active_transitioned = false;
                if (input.active.has_value() && !*input.active && resource->active) {
                    if (!deactivate(scim_store, auth_mgr, audit_store, req, res, *resource,
                                    "scim.user.deactivated"))
                        return;
                    resource->active = false;
                    active_transitioned = true;
                } else if (input.active.has_value() && *input.active && !resource->active) {
                    if (!reactivate(scim_store, auth_mgr, audit_store, req, res, *resource))
                        return;
                    resource->active = true;
                    active_transitioned = true;
                }

                scim_store->update_resource(resource->scim_id, resource->username,
                                            input.external_id);
                auto updated = scim_store->get_by_scim_id(resource->scim_id);
                if (!active_transitioned) {
                    // deactivate()/reactivate() already audited their own
                    // action; avoid a duplicate "updated" row for that case.
                    audit(audit_store, req, "scim.user.updated", "success", resource->scim_id);
                }
                res.set_content(scim::user_to_json(*updated, location_base(req)).dump(),
                               kScimJson);
            });

    // ── PATCH /scim/v2/Users/{id} — the critical deprovision path. ────────

    sink.Patch(R"(/scim/v2/Users/([0-9a-fA-F]+))",
              [scim_store, auth_mgr, audit_store](const httplib::Request& req,
                                                  httplib::Response& res) {
                  if (!require_bearer(scim_store, req, res))
                      return;
                  auto id = req.matches[1].str();
                  auto resource = scim_store->get_by_scim_id(id);
                  if (!resource) {
                      send_scim_error(res, 404, "resource not found");
                      return;
                  }
                  if (req.body.size() > kMaxBodyBytes) {
                      send_scim_error(res, 413, "request body too large");
                      return;
                  }
                  json body;
                  try {
                      body = json::parse(req.body);
                  } catch (const std::exception&) {
                      send_scim_error(res, 400, "request body is not valid JSON", "invalidValue");
                      return;
                  }
                  auto parsed = scim::parse_patch(body);
                  if (!parsed) {
                      send_scim_error(res, parsed.error());
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
                      return;
                  }

                  bool active_transitioned = false;
                  if (patch.active.has_value()) {
                      if (!*patch.active && resource->active) {
                          if (!deactivate(scim_store, auth_mgr, audit_store, req, res, *resource,
                                          "scim.user.deactivated"))
                              return;
                          resource->active = false;
                          active_transitioned = true;
                      } else if (*patch.active && !resource->active) {
                          if (!reactivate(scim_store, auth_mgr, audit_store, req, res, *resource))
                              return;
                          resource->active = true;
                          active_transitioned = true;
                      }
                      // else: no-op (already in the requested state).
                  }

                  if (patch.external_id.has_value()) {
                      scim_store->update_resource(resource->scim_id, resource->username,
                                                  *patch.external_id);
                  }

                  auto updated = scim_store->get_by_scim_id(resource->scim_id);
                  if (!active_transitioned) {
                      // deactivate()/reactivate() already audited their own
                      // action; avoid a duplicate "updated" row for that case.
                      audit(audit_store, req, "scim.user.updated", "success", resource->scim_id);
                  }
                  res.set_content(scim::user_to_json(*updated, location_base(req)).dump(),
                                 kScimJson);
              });

    // ── DELETE /scim/v2/Users/{id} ─────────────────────────────────────────

    sink.Delete(R"(/scim/v2/Users/([0-9a-fA-F]+))",
               [scim_store, auth_mgr, audit_store](const httplib::Request& req,
                                                   httplib::Response& res) {
                   if (!require_bearer(scim_store, req, res))
                       return;
                   auto id = req.matches[1].str();
                   auto resource = scim_store->get_by_scim_id(id);
                   if (!resource) {
                       send_scim_error(res, 404, "resource not found");
                       return;
                   }
                   if (resource->active) {
                       if (!provenance_ok(auth_mgr, audit_store, req, resource->username, id, res))
                           return;
                       if (!auth_mgr->remove_user(resource->username)) {
                           send_scim_error(res, 500, "failed to deactivate the underlying account");
                           audit(audit_store, req, "scim.user.deleted", "failure", id);
                           return;
                       }
                   } else {
                       // Already deactivated — still re-verify provenance
                       // before the DELETE removes the mapping row, so a
                       // scim_resource somehow pointing at a non-SCIM
                       // account still can't be wiped out from under it.
                       if (!provenance_ok(auth_mgr, audit_store, req, resource->username, id, res))
                           return;
                   }
                   scim_store->delete_by_scim_id(id);
                   audit(audit_store, req, "scim.user.deleted", "success", id);
                   res.status = 204;
               });
}

} // namespace yuzu::server
