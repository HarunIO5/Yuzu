// gRPC server interceptor rejecting on-behalf-of assertions at agent-service
// ingress (ADR-0022 Interim rules, execution-plan PR 1.1).
//
// A single interceptor — NOT a per-RPC-method check — so a future new RPC
// method cannot be added without this guard, silently reopening the gap
// (execution-plan PR 1.1 rationale). Registered on the one ServerBuilder in
// server.cpp, so it covers the agent, management, and gateway-upstream
// services alike.
//
// Rejection mechanics: gRPC server interceptors cannot synthesize a status of
// their own mid-stream, so the guard cancels the RPC via
// ServerContext::TryCancel() — the client observes CANCELLED. This is a
// defensive no-op today (no engine-principal traffic crosses the agent gRPC
// channel under the plan's Decision 3 no-machine-consumer scoping), but the
// ADR's rejection rule binds on ANY surface from acceptance, so it ships now.

#pragma once

#include <grpcpp/support/server_interceptor.h>

#include <spdlog/spdlog.h>

#include "on_behalf_guard.hpp"
#include "yuzu/metrics.hpp"

namespace yuzu::server {

class OnBehalfRejectInterceptor final : public grpc::experimental::Interceptor {
public:
    OnBehalfRejectInterceptor(grpc::experimental::ServerRpcInfo* info,
                              yuzu::MetricsRegistry* metrics)
        : info_(info), metrics_(metrics) {}

    void Intercept(grpc::experimental::InterceptorBatchMethods* methods) override {
        if (methods->QueryInterceptionHookPoint(
                grpc::experimental::InterceptionHookPoints::POST_RECV_INITIAL_METADATA)) {
            auto* ctx = info_->server_context();
            if (ctx != nullptr) {
                auto hit = onbehalf::find_reserved_key(ctx->client_metadata());
                if (hit) {
                    if (metrics_ != nullptr) {
                        metrics_
                            ->counter("yuzu_onbehalf_rejected_total",
                                      {{"surface", "grpc"}, {"event", "security"}})
                            .increment();
                    }
                    spdlog::warn(
                        "[ADR-0022] rejected gRPC call carrying reserved on-behalf-of "
                        "metadata key '{}' (method={}, peer={}); on-behalf-of assertions "
                        "are not accepted on any surface",
                        *hit, info_->method() ? info_->method() : "?", ctx->peer());
                    ctx->TryCancel();
                }
            }
        }
        methods->Proceed();
    }

private:
    grpc::experimental::ServerRpcInfo* info_;
    yuzu::MetricsRegistry* metrics_;
};

class OnBehalfRejectInterceptorFactory final
    : public grpc::experimental::ServerInterceptorFactoryInterface {
public:
    explicit OnBehalfRejectInterceptorFactory(yuzu::MetricsRegistry* metrics)
        : metrics_(metrics) {}

    grpc::experimental::Interceptor* CreateServerInterceptor(
        grpc::experimental::ServerRpcInfo* info) override {
        return new OnBehalfRejectInterceptor(info, metrics_);
    }

private:
    yuzu::MetricsRegistry* metrics_;
};

}  // namespace yuzu::server
