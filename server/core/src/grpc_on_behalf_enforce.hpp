// Enforces the on-behalf-of rejection OnBehalfRejectInterceptor already
// signaled (ADR-0022 Interim rules, execution-plan PR 1.1).
//
// The interceptor's own doc comment names the limit: ServerContext::TryCancel()
// cancels the client-visible RPC but does NOT stop a sync unary/streaming
// handler from running — the payload already arrived with the call, so the
// handler may execute fully and its side effects commit before the client
// observes CANCELLED.
//
// EARLIER VERSION OF THIS HEADER read `context->IsCancelled()` as the
// enforcement check — WRONG, discovered by the end-to-end test in
// test_grpc_on_behalf_enforce.cpp: TryCancel()'s effect on IsCancelled() is
// NOT synchronously visible to the handler thread — it propagates through
// gRPC-core's internal call machinery on its own schedule, which races
// against the sync-server thread pool picking up and invoking the handler.
// Empirically ~1-in-5 runs under test load, IsCancelled() was still false
// when the handler's first statement ran, and the handler proceeded past
// the guard. A security enforcement check that is merely usually-correct is
// wrong by definition.
//
// This version reads the ground truth directly instead: it re-runs
// onbehalf::find_reserved_key() over context->client_metadata() — the SAME
// parsed headers the interceptor itself inspected. client_metadata() carries
// no such race: gRPC cannot invoke a unary/streaming handler before all
// initial metadata for the call has been received and parsed, so the map is
// already complete and immutable by the time any handler statement runs, on
// every call, deterministically. The interceptor's TryCancel() is still
// useful (fast transport-level abort, especially for a long-lived stream)
// and stays in place unchanged; this header no longer depends on it.
//
// Call `call_rejected(context)` as the FIRST statement of every RPC handler
// reachable through the ServerBuilder the interceptor is registered on —
// before any work that could commit a side effect (registry mutation, DB
// write, audit row) — so a reserved-header call is a true no-op, not merely
// a wrong status code on an already-committed action.
//
// Deliberately a free function, not a per-class method like
// AgentServiceImpl::reject_revoked_peer: it needs no instance state, and a
// free function keeps the same one-line guard usable identically from every
// service impl class the interceptor covers (AgentServiceImpl,
// GatewayUpstreamServiceImpl, and any future one) — the same
// "no per-RPC-method gap by construction" property the interceptor itself
// has, now extended to enforcement.

#pragma once

#include <grpcpp/server_context.h>

#include "on_behalf_guard.hpp"

namespace yuzu::server::onbehalf {

[[nodiscard]] inline bool call_rejected(grpc::ServerContext* context) {
    return context != nullptr && find_reserved_key(context->client_metadata()).has_value();
}

}  // namespace yuzu::server::onbehalf
