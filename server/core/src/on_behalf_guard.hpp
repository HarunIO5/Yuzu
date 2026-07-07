// On-behalf-of assertion guard (ADR-0022 Interim rules, execution-plan PR 1.1).
//
// Until server-verifiable delegation ships (execution-plan Phase 5), the server
// accepts NO on-behalf-of assertion on ANY ingress surface — any such
// header/field is rejected, not ignored. This header defines the reserved
// names ONCE for both surfaces: the HTTP pre-routing chokepoint (REST + MCP —
// same httplib instance) and the agent-facing gRPC interceptor
// (grpc_on_behalf_interceptor.hpp). The names are reserved NOW, before any
// delegation mechanism exists, so no integration can squat on them and no
// future surface can accept them by accident.
//
// Phase 5 delegation will use a server-issued artifact, never a client-
// asserted header — so these names stay rejected permanently on client
// ingress; the list only ever grows.

#pragma once

#include <array>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::server::onbehalf {

// Reserved names, lowercase. gRPC metadata keys arrive lowercase by protocol;
// HTTP names are matched case-insensitively via is_reserved_key.
inline constexpr std::array<std::string_view, 5> kReservedKeys{
    "on-behalf-of",
    "x-on-behalf-of",
    "x-yuzu-on-behalf-of",
    "x-yuzu-delegated-operator",
    "x-yuzu-delegation-artifact",
};

// Case-insensitive match of `name` against the reserved set. ASCII-only
// folding is correct here: header/metadata names are ASCII by RFC 9110 /
// gRPC spec, and every reserved name is ASCII.
[[nodiscard]] inline bool is_reserved_key(std::string_view name) {
    auto lower = [](char c) {
        return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
    };
    for (auto reserved : kReservedKeys) {
        if (reserved.size() != name.size()) continue;
        bool match = true;
        for (size_t i = 0; i < name.size(); ++i) {
            if (lower(name[i]) != reserved[i]) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

// Scan a header/metadata collection (any range of pair-likes whose first
// element converts to string_view) for a reserved key. Returns the canonical
// (lowercase reserved-list) spelling of the first hit for logging — never the
// client-supplied value, which is untrusted input and does not belong in logs.
template <typename Range>
[[nodiscard]] std::optional<std::string> find_reserved_key(const Range& headers) {
    for (const auto& [name, value] : headers) {
        std::string_view n{name.data(), name.size()};
        if (is_reserved_key(n)) {
            auto lower = [](char c) {
                return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
            };
            std::string canonical(n.size(), '\0');
            for (size_t i = 0; i < n.size(); ++i) canonical[i] = lower(n[i]);
            return canonical;
        }
    }
    return std::nullopt;
}

}  // namespace yuzu::server::onbehalf
