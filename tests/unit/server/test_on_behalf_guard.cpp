// ADR-0022 Interim rules (execution-plan PR 1.1) — reserved on-behalf-of key
// guard. These tests pin the reserved-name set and the case-insensitive match
// the HTTP pre-routing chokepoint and the gRPC interceptor both rely on.

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>

#include "on_behalf_guard.hpp"

using yuzu::server::onbehalf::find_reserved_key;
using yuzu::server::onbehalf::is_reserved_key;
using yuzu::server::onbehalf::kReservedKeys;

TEST_CASE("every reserved key matches itself and its uppercase form", "[onbehalf][adr0022]") {
    for (auto key : kReservedKeys) {
        CHECK(is_reserved_key(key));
        std::string upper{key};
        for (auto& c : upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        CHECK(is_reserved_key(upper));
    }
}

TEST_CASE("non-reserved names do not match", "[onbehalf][adr0022]") {
    CHECK_FALSE(is_reserved_key("authorization"));
    CHECK_FALSE(is_reserved_key("x-yuzu-token"));
    CHECK_FALSE(is_reserved_key("x-correlation-id"));
    // Prefix / suffix near-misses must not match: the guard rejects exact
    // reserved names, not a substring family.
    CHECK_FALSE(is_reserved_key("x-on-behalf-of-extra"));
    CHECK_FALSE(is_reserved_key("on-behalf"));
    CHECK_FALSE(is_reserved_key(""));
}

TEST_CASE("find_reserved_key scans httplib headers case-insensitively",
          "[onbehalf][adr0022]") {
    httplib::Headers clean{{"Authorization", "Bearer tok"}, {"Accept", "application/json"}};
    CHECK_FALSE(find_reserved_key(clean).has_value());

    httplib::Headers dirty{{"Authorization", "Bearer tok"},
                           {"X-Yuzu-On-Behalf-Of", "alice"}};
    auto hit = find_reserved_key(dirty);
    REQUIRE(hit.has_value());
    // Canonical lowercase spelling is returned for logging — never the value.
    CHECK(*hit == "x-yuzu-on-behalf-of");
}

TEST_CASE("find_reserved_key catches the bare and generic spellings",
          "[onbehalf][adr0022]") {
    for (auto name : {"On-Behalf-Of", "x-on-behalf-of", "X-Yuzu-Delegated-Operator",
                      "x-yuzu-delegation-artifact"}) {
        httplib::Headers h{{name, "someone"}};
        INFO(name);
        CHECK(find_reserved_key(h).has_value());
    }
}
