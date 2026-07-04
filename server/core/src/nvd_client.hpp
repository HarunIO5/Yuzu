#pragma once

#include "nvd_db.hpp"

#include <chrono>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace httplib {
class Client;
}

namespace yuzu::server {

struct NvdFetchResult {
    std::vector<CveRecord> records;
    int total_results = 0;
    std::string last_modified_timestamp; // latest lastModified in results
    // false if a request failed (connection/HTTP error) — distinguishes a real
    // failure from a genuinely-empty window so the caller doesn't treat a
    // transient error as "sync complete" and advance its cursor (#1875).
    bool ok = true;
};

class NvdClient {
public:
    explicit NvdClient(std::string api_key = {}, std::string proxy_url = {});

    // Fetch CVEs modified in [iso_timestamp, now] (freshness re-check). The
    // caller must keep the range within NVD's 120-day cap (see nvd_split_windows).
    NvdFetchResult fetch_modified_since(const std::string& iso_timestamp);

    // Fetch CVEs PUBLISHED in [pub_start, pub_end] (newest-first backfill). Both
    // are ISO 8601; the window must be within NVD's 120-day cap.
    NvdFetchResult fetch_by_published_window(const std::string& pub_start,
                                             const std::string& pub_end);

    // Fetch CVEs matching a keyword search (for initial targeted sync).
    NvdFetchResult fetch_by_keyword(const std::string& keyword, int start_index = 0);

    /// Parse a raw NVD API JSON response into CveRecords.
    NvdFetchResult parse_response(const std::string& json_body);

private:
    std::string api_key_;
    std::string proxy_host_;
    int proxy_port_ = 0;
    // std::nullopt until the first request — a sentinel time_point overflowed
    // the rate-limit subtraction and slept ~forever on the first call (#1867).
    std::optional<std::chrono::steady_clock::time_point> last_request_time_;

    void rate_limit();
    void apply_proxy(httplib::Client& client) const;
    // Apply the shared per-request client config (timeouts, proxy).
    void configure_client(httplib::Client& client) const;
    // Paginate a query carrying the given NVD date filter (e.g.
    // "lastModStartDate=…&lastModEndDate=…" or "pubStartDate=…&pubEndDate=…").
    NvdFetchResult fetch_paginated(const std::string& date_params);
};

/// Partition [start, end] into consecutive windows each at most `max_window`
/// long (NVD caps pub/lastMod date ranges at 120 days), oldest-first. Pure.
std::vector<std::pair<std::chrono::system_clock::time_point, std::chrono::system_clock::time_point>>
nvd_split_windows(std::chrono::system_clock::time_point start,
                  std::chrono::system_clock::time_point end,
                  std::chrono::system_clock::duration max_window);

/// How long to sleep to honour `interval` since the `last` request — zero when
/// there was no prior request (nullopt) or `interval` has already elapsed.
/// Overflow-safe: a regression guard for the `time_point::min()` sentinel that
/// overflowed `now - last` and slept ~292 years on the first NVD request (#1867).
std::chrono::steady_clock::duration
nvd_rate_limit_wait(std::optional<std::chrono::steady_clock::time_point> last,
                    std::chrono::steady_clock::time_point now,
                    std::chrono::steady_clock::duration interval);

} // namespace yuzu::server
