#pragma once

#include <sqlite3.h>

#include <cstdint>
#include <expected>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

struct Approval {
    std::string id;
    std::string definition_id;
    std::string status;
    std::string submitted_by;
    int64_t submitted_at{0};
    std::string reviewed_by;
    int64_t reviewed_at{0};
    std::string review_comment;
    std::string scope_expression;
    /// Empty for an interactively-submitted ticket (workflow_routes.cpp);
    /// set to the owning schedule's id for a scheduled-fire submission
    /// (M-02, #1806) so ScheduleRunner::fire_with_approval can match a
    /// ticket to the ONE schedule occurrence that asked for it, instead of
    /// to every schedule sharing the same (submitted_by, definition_id,
    /// scope_expression) tuple.
    std::string schedule_id;
};

struct ApprovalQuery {
    std::string status;
    std::string submitted_by;
};

class ApprovalManager {
public:
    explicit ApprovalManager(sqlite3* db);
    ~ApprovalManager() = default;

    ApprovalManager(const ApprovalManager&) = delete;
    ApprovalManager& operator=(const ApprovalManager&) = delete;

    void create_tables();

    /// `schedule_id` (M-02, #1806): empty for the interactive submit path;
    /// the owning schedule's id for a scheduled-fire submission — see the
    /// `Approval::schedule_id` doc comment for why this matters.
    std::expected<std::string, std::string> submit(const std::string& definition_id,
                                                   const std::string& submitted_by,
                                                   const std::string& scope_expression,
                                                   const std::string& schedule_id = "");

    std::vector<Approval> query(const ApprovalQuery& q = {}) const;

    /// Single-approval lookup by id (read-only). Backs the versioned
    /// GET /api/v1/approvals/{id} status_url target — query() cannot serve it
    /// (its LIMIT 100 would false-404 an id that has aged past the top window).
    /// Returns std::nullopt when no row matches. Does NOT touch the approval
    /// lifecycle (submit/approve/reject/consumption are elsewhere).
    std::optional<Approval> get(const std::string& id) const;

    int pending_count() const;

    std::expected<void, std::string> approve(const std::string& id, const std::string& reviewer,
                                             const std::string& comment);

    std::expected<void, std::string> reject(const std::string& id, const std::string& reviewer,
                                            const std::string& comment);

private:
    std::expected<void, std::string> set_review_status(const std::string& id,
                                                       const std::string& status,
                                                       const std::string& reviewer,
                                                       const std::string& comment);

    sqlite3* db_;
    mutable std::mutex mtx_; // protects all db_ access (G4-UHP-MCP-005)
};

} // namespace yuzu::server
