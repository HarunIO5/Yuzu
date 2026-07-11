- **NVD sync crashed the server on the very first API request (#1908).** `main.cpp` transitively
  includes `<httplib.h>` via `scim_routes.hpp` without `CPPHTTPLIB_OPENSSL_SUPPORT` defined, while
  `yuzu_server_core_lib` (which contains `nvd_client.cpp`) compiled the same header with it. Since
  httplib is header-only with inline definitions and that macro gates real data members on
  `httplib::ClientImpl`/`SSLClient`, the two translation units disagreed on class layout — an ODR
  violation the linker silently resolved by folding one definition into the other, corrupting
  `httplib::Client` objects on first use. This produced a deterministic SIGSEGV in
  `NvdClient::fetch_paginated` seconds after boot with NVD sync enabled, on every affected build.
  `server/core/meson.build` now propagates the macro to every consumer of `yuzu_server_core_dep`
  via `compile_args`, matching Meson's standard dependency-propagation pattern.
  Operators on a pre-fix build can work around the crash with `--no-nvd-sync`.
