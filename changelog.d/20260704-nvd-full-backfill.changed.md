- **The NVD sync now builds the full CVE catalog (newest-first), not ~20 keywords.** The server-side
  NVD sync was keyword-scoped (~20 hardcoded products); it now backfills every CVE published within a
  configurable window — `--nvd-backfill-years` / `YUZU_NVD_BACKFILL_YEARS` (default **8 years**; `0` =
  full history) — **newest-first and resumable across restarts**, then settles into a periodic
  last-modified freshness re-check. Product matching is prefix-anchored so it stays index-fast at
  catalog scale. **Operator-visible:** `GET /api/nvd/status` `total_cves` grows substantially and the
  local NVD database reaches into the hundreds of MB; the initial backfill is NVD-rate-limited (hours
  without an `--nvd-api-key`, minutes with one) and resumes where it left off if interrupted. Set
  `--no-nvd-sync` to disable, `--nvd-proxy` for restricted egress.
