#ifdef _WIN32

#include "service_win.hpp"

#include <spdlog/spdlog.h>

#include <atomic>
#include <cstdlib>
#include <mutex>

namespace {

using yuzu::agent::Agent;

// SERVICE_TABLE_ENTRYW's ServiceMain callback takes no user context parameter, so
// the factory and mutable service state are process-global. This is fine: a given
// process hosts exactly one service (SERVICE_WIN32_OWN_PROCESS), so there is only
// ever one ServiceMain/handler pair alive.
std::move_only_function<std::unique_ptr<Agent>()> g_factory;

// atomic, not a plain pointer guarded by g_status_mu below: it's published once
// by RegisterServiceCtrlHandlerExW's return and then only ever READ by
// report_status() -- an unlocked write racing report_status()'s locked read
// under the C++ memory model is a data race even though it's single-writer and
// practically benign (Gate-2 finding, #1822).
std::atomic<SERVICE_STATUS_HANDLE> g_status_handle{nullptr};
// Guards both the SetServiceStatus call and the checkpoint counter: the control
// handler (SCM-invoked, its own thread) and ServiceMain can both report status
// concurrently -- e.g. a STOP arriving while ServiceMain is still transitioning
// out of START_PENDING/RUNNING -- so report_status() is not naturally single-
// threaded despite the state machine looking sequential on paper.
std::mutex g_status_mu;
DWORD g_checkpoint = 0; // guarded by g_status_mu; monotonic within a pending phase

std::mutex g_agent_mu;
Agent* g_agent = nullptr; // guarded by g_agent_mu; non-owning, published by ServiceMain
std::atomic<bool> g_stop_requested{false};

void report_status(DWORD current_state, DWORD win32_exit_code = NO_ERROR,
                    DWORD specific_exit_code = 0, DWORD wait_hint = 0) {
    std::lock_guard<std::mutex> lock(g_status_mu);

    SERVICE_STATUS status{};
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = current_state;
    status.dwWin32ExitCode = win32_exit_code;
    status.dwServiceSpecificExitCode = specific_exit_code;
    status.dwWaitHint = wait_hint;

    switch (current_state) {
    case SERVICE_START_PENDING:
    case SERVICE_STOP_PENDING:
        // No controls accepted while pending: MSDN requires it for START_PENDING,
        // and clearing it for STOP_PENDING means a duplicate STOP/SHUTDOWN control
        // simply isn't delivered again, instead of hitting the handler mid-teardown.
        status.dwControlsAccepted = 0;
        status.dwCheckPoint = ++g_checkpoint;
        break;
    case SERVICE_RUNNING:
        status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
        status.dwCheckPoint = 0;
        g_checkpoint = 0;
        break;
    default: // SERVICE_STOPPED
        status.dwControlsAccepted = 0;
        status.dwCheckPoint = 0;
        break;
    }

    if (auto handle = g_status_handle.load(std::memory_order_acquire))
        SetServiceStatus(handle, &status);
}

DWORD WINAPI handler_ex(DWORD control, DWORD /*event_type*/, LPVOID /*event_data*/,
                         LPVOID /*context*/) {
    switch (control) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        g_stop_requested.store(true, std::memory_order_relaxed);
        // 30s to match the START_PENDING hint; Agent::stop() itself is
        // non-blocking (sets flags, TryCancels in-flight stream writes), so
        // teardown is bounded well under that -- no checkpoint-bumping thread
        // needed for a single-shot pending report.
        report_status(SERVICE_STOP_PENDING, NO_ERROR, 0, 30000);
        {
            std::lock_guard<std::mutex> lock(g_agent_mu);
            if (g_agent)
                g_agent->stop();
        }
        return NO_ERROR;
    case SERVICE_CONTROL_INTERROGATE:
        // The SCM already has our most recent SetServiceStatus report; nothing to
        // resend.
        return NO_ERROR;
    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

// Clears the published g_agent pointer on destruction, under g_agent_mu.
// service_main declares its unique_ptr<Agent>, THEN this guard: C++ destroys
// locals in reverse declaration order, so the guard fires -- unpublishing
// g_agent -- before the unique_ptr's own destructor runs, on EVERY exit path
// (normal return, exception unwind, everything). Without this, a manual
// "clear g_agent" statement placed only after a (fallible) agent->run() call
// only runs on the happy path; a SERVICE_CONTROL_STOP delivered on the SCM
// control-handler thread during exception unwind would see a stale non-null
// g_agent and call stop() on an already-destructing/destructed Agent (Gate-2
// finding, #1822).
struct AgentUnpublisher {
    ~AgentUnpublisher() {
        std::lock_guard<std::mutex> lock(g_agent_mu);
        g_agent = nullptr;
    }
};

void WINAPI service_main(DWORD, LPWSTR*) noexcept {
    auto handle =
        RegisterServiceCtrlHandlerExW(yuzu::agent::win::kServiceName, handler_ex, nullptr);
    if (!handle) {
        spdlog::error("RegisterServiceCtrlHandlerExW failed: {}", GetLastError());
        return;
    }
    g_status_handle.store(handle, std::memory_order_release);

    report_status(SERVICE_START_PENDING, NO_ERROR, 0, 30000);

    try {
        auto agent = g_factory ? g_factory() : nullptr;
        if (!agent) {
            spdlog::critical(
                "Agent factory failed under SCM startup -- reporting service failure");
            report_status(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, /*specific=*/1);
            return;
        }

        {
            std::lock_guard<std::mutex> lock(g_agent_mu);
            g_agent = agent.get();
        }
        AgentUnpublisher unpublisher; // destructs before `agent` on every exit below

        // Report RUNNING now, before run() -- run()'s reconnect loop is unbounded
        // while the server is unreachable (agent.cpp), so waiting for it to return
        // would itself time out the SCM start (parity with the systemd
        // Type=simple unit, which has no readiness protocol either).
        report_status(SERVICE_RUNNING);

        agent->run(); // blocks until stop() (via handler_ex) or a fatal startup error

        spdlog::default_logger()->flush();

        if (agent->startup_failed())
            report_status(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, /*specific=*/1);
        else if (!g_stop_requested.load(std::memory_order_relaxed))
            // run() returned on its own, without a STOP/SHUTDOWN control -- unexpected.
            report_status(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, /*specific=*/2);
        else
            report_status(SERVICE_STOPPED);
    } catch (const std::exception& e) {
        // service_main is a raw WINAPI callback invoked directly by the SCM
        // dispatcher thread -- an exception must never cross that C ABI boundary
        // (UB / std::terminate). AgentUnpublisher has already run by this point
        // (stack unwind destructs it before this catch runs), so g_agent is safely
        // cleared regardless of where inside the try the throw originated.
        spdlog::critical("Unhandled exception in ServiceMain: {}", e.what());
        report_status(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, /*specific=*/3);
    } catch (...) {
        spdlog::critical("Unhandled non-standard exception in ServiceMain");
        report_status(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, /*specific=*/3);
    }
}

} // namespace

namespace yuzu::agent::win {

int run_service(std::move_only_function<std::unique_ptr<Agent>()> factory) {
    g_factory = std::move(factory);

    SERVICE_TABLE_ENTRYW table[] = {
        {const_cast<LPWSTR>(kServiceName), service_main},
        {nullptr, nullptr},
    };

    if (!StartServiceCtrlDispatcherW(table)) {
        auto err = GetLastError();
        if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            spdlog::error(
                "--service is for use by the Windows Service Control Manager; "
                "run without --service for interactive/console mode");
        } else {
            spdlog::error("StartServiceCtrlDispatcherW failed: {}", err);
        }
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

} // namespace yuzu::agent::win

#endif // _WIN32
