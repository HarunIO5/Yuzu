/**
 * spark_file.cpp — the File spark mechanism (ADR-0021 Stage 1 PR 1b).
 *
 * Windows: one IOCP + one worker thread multiplexing ReadDirectoryChangesW
 * across every watched PARENT DIRECTORY — O(mechanism), never O(rules). Two
 * file sparks in the same directory share one ReadDirectoryChangesW
 * registration; a raw directory notification is routed back to the matching
 * spark key(s) by changed filename. IOCP (not WaitForMultipleObjects) is
 * deliberate: the 64-handle MAXIMUM_WAIT_OBJECTS cap is exactly the O(rules)
 * ceiling the SparkEngine exists to remove (the trigger_engine registry-poll
 * mistake).
 *
 * This mechanism PORTS THE WATCH, NOT THE ASSERTION. Unlike guard_file.cpp it
 * does NO expected-value compare, NO hashing, NO write-back — a fired spark is
 * a raw "this path changed" fact (the old TriggerEngine FileChange trigger
 * shape). The compare + enforce move to Guardian as an inline consumer in
 * Stage 2. It DOES port guard_file's watch-resilience: the nearest-existing-
 * ancestor watch that survives a deleted+recreated parent, and arm-before-check
 * ordering (ReadDirectoryChangesW issued before anything reads state).
 *
 * Off Windows the factory returns nullptr: the SparkEngine then rejects
 * arm(File) (spark.hpp: armed == a watcher is running).
 */

#include "spark_mechanism.hpp"

#ifdef _WIN32

#include "guard_win_handle.hpp" // detail::DirHandle, detail::EventHandle

#include <spdlog/spdlog.h>

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cwctype>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

namespace yuzu::agent {
namespace {

namespace fs = std::filesystem;

using detail::DirHandle;

constexpr DWORD kFilter = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                          FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE |
                          FILE_NOTIFY_CHANGE_CREATION;

// Completion-key sentinels distinguish a directory completion (key == the
// DirWatch pointer) from a control wake (watch/unwatch/stop posted the queue).
constexpr ULONG_PTR kControlKey = 0;

std::wstring lower_w(std::wstring_view s) {
    std::wstring out(s);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(::towlower(c)); });
    return out;
}

/// One watched directory: its overlapped read, its buffer, and the set of spark
/// keys interested in each (lower-cased) filename inside it. Heap-owned and
/// kept alive until its outstanding I/O drains — the IOCP teardown contract.
struct DirWatch {
    DirHandle handle;               ///< CreateFileW(FILE_LIST_DIRECTORY, OVERLAPPED), IOCP-associated
    OVERLAPPED ov{};                ///< distinct per dir — the IOCP key back to this struct
    alignas(DWORD) std::byte buf[32 * 1024]; ///< FILE_NOTIFY_INFORMATION landing buffer
    std::wstring dir;               ///< normalised absolute directory path
    std::unordered_map<std::wstring, std::unordered_set<std::string>> keys; ///< fname → spark keys
    bool io_pending{false};         ///< a ReadDirectoryChangesW is outstanding
    bool removing{false};           ///< unwatch drained this dir; free once the last I/O returns
};

/// Windows file-change mechanism. Thread-safe: watch/unwatch (engine threads)
/// and the worker all take `mu_`. ReadDirectoryChangesW is async, so re-arming
/// under `mu_` is cheap; CreateFileW in watch() runs on the engine's arm path
/// (already off the engine lock).
class WindowsFileMechanism final : public ISparkMechanism {
public:
    ~WindowsFileMechanism() override { stop(); }

    void start(SparkEmitFn emit) override {
        std::lock_guard lk(mu_);
        if (iocp_)
            return; // idempotent
        emit_ = std::move(emit);
        iocp_.reset(::CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, kControlKey, 1));
        if (!iocp_) {
            spdlog::error("spark_file: CreateIoCompletionPort failed (err={}) — file sparks inert",
                          ::GetLastError());
            return;
        }
        stop_.store(false, std::memory_order_release);
        worker_ = std::thread([this] { run(); });
    }

    std::expected<void, std::string> watch(const std::string& key,
                                           const SparkParams& params) override {
        const auto* fp = std::get_if<FileSparkParams>(&params);
        if (!fp)
            return std::unexpected("file mechanism: params are not FileSparkParams");
        fs::path target = fs::path(fp->path);
        fs::path parent = target.has_parent_path() ? target.parent_path() : fs::current_path();
        const std::wstring fname = lower_w(target.filename().wstring());
        const std::wstring dirkey = lower_w(parent.wstring());

        std::lock_guard lk(mu_);
        if (!iocp_)
            return std::unexpected("file mechanism not started");
        auto& slot = dirs_[dirkey];
        if (!slot) {
            slot = std::make_unique<DirWatch>();
            slot->dir = parent.wstring();
            if (!arm_dir(*slot)) {
                // Directory absent/unopenable: keep the (empty-of-I/O) entry so
                // the key is recorded, and watch the nearest ancestor for the
                // parent's (re)creation. arm_ancestor is best-effort.
                arm_ancestor(parent);
            }
        }
        slot->keys[fname].insert(key);
        key_index_[key] = {dirkey, fname};
        return {};
    }

    void unwatch(const std::string& key) override {
        std::lock_guard lk(mu_);
        auto ki = key_index_.find(key);
        if (ki == key_index_.end())
            return;
        const auto [dirkey, fname] = ki->second;
        key_index_.erase(ki);
        auto di = dirs_.find(dirkey);
        if (di == dirs_.end())
            return;
        DirWatch& w = *di->second;
        auto fi = w.keys.find(fname);
        if (fi != w.keys.end()) {
            fi->second.erase(key);
            if (fi->second.empty())
                w.keys.erase(fi);
        }
        if (w.keys.empty()) {
            // No spark cares about this dir any more. If an I/O is outstanding,
            // cancel it and let the worker free the DirWatch when the (aborted)
            // completion drains — never free memory a pending completion points
            // at. If nothing is outstanding, drop it now.
            if (w.io_pending) {
                w.removing = true;
                if (w.handle)
                    ::CancelIoEx(w.handle.get(), &w.ov);
            } else {
                dirs_.erase(di);
            }
        }
    }

    void stop() override {
        {
            std::lock_guard lk(mu_);
            if (!iocp_)
                return;
        }
        stop_.store(true, std::memory_order_release);
        // Wake the worker out of GetQueuedCompletionStatus.
        ::PostQueuedCompletionStatus(iocp_.get(), 0, kControlKey, nullptr);
        if (worker_.joinable())
            worker_.join();
        std::lock_guard lk(mu_);
        dirs_.clear(); // worker is joined; safe to drop every DirWatch
        iocp_.reset();
        emit_ = nullptr;
    }

private:
    /// Issue (or re-issue) the overlapped ReadDirectoryChangesW for `w`. Opens
    /// the directory handle + associates it with the IOCP on first arm. Returns
    /// false if the directory can't be opened (caller falls back to ancestor).
    bool arm_dir(DirWatch& w) {
        if (!w.handle) {
            std::error_code ec;
            if (!fs::is_directory(w.dir, ec))
                return false;
            DirHandle h(::CreateFileW(
                w.dir.c_str(), FILE_LIST_DIRECTORY,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr));
            if (!h)
                return false;
            if (!::CreateIoCompletionPort(h.get(), iocp_.get(),
                                          reinterpret_cast<ULONG_PTR>(&w), 0)) {
                spdlog::error("spark_file: IOCP associate failed for {} (err={})",
                              fs::path(w.dir).string(), ::GetLastError());
                return false;
            }
            w.handle = std::move(h);
        }
        // Arm-before-check: the read is outstanding before anyone reads state.
        w.io_pending = ::ReadDirectoryChangesW(w.handle.get(), w.buf, sizeof(w.buf), FALSE, kFilter,
                                               nullptr, &w.ov, nullptr) != 0;
        if (!w.io_pending)
            w.handle.reset(); // dir vanished between open and read → treat as absent
        return w.io_pending;
    }

    /// Best-effort: watch the nearest existing ancestor of a missing parent for
    /// its (re)creation, so a deleted+recreated directory re-arms. The ancestor
    /// watch is itself a DirWatch keyed under its own path with an empty key set
    /// and a `removing`-immune sentinel; on any ancestor change the worker
    /// re-resolves absent dirs. Mirrors guard_file's ancestor resilience.
    void arm_ancestor(const fs::path& missing_parent) {
        fs::path anc = missing_parent;
        std::error_code ec;
        while (!anc.empty() && !fs::is_directory(anc, ec))
            anc = anc.parent_path();
        if (anc.empty())
            return;
        const std::wstring akey = lower_w(anc.wstring());
        auto& slot = ancestors_[akey];
        if (slot)
            return; // already watching this ancestor
        slot = std::make_unique<DirWatch>();
        slot->dir = anc.wstring();
        if (!arm_dir(*slot))
            ancestors_.erase(akey);
    }

    /// Re-attempt every absent directory watch (an ancestor fired). Any that now
    /// opens re-arms and drops its ancestor.
    void reresolve_absent() {
        for (auto& [dirkey, slot] : dirs_) {
            if (slot && !slot->handle && !slot->keys.empty())
                arm_dir(*slot);
        }
    }

    /// Walk the FILE_NOTIFY_INFORMATION records in `bytes` and collect each
    /// spark key whose filename changed (called under mu_; pure — the emit
    /// happens later, lock-released). `bytes == 0` = buffer overflow: we can't
    /// tell which files changed, so fire EVERY key in the dir (never miss one).
    std::vector<std::string> collect_fire(DirWatch& w, DWORD bytes) const {
        std::vector<std::string> fire;
        if (bytes == 0) {
            for (auto& [fname, keys] : w.keys)
                fire.insert(fire.end(), keys.begin(), keys.end());
            return fire;
        }
        std::size_t off = 0;
        for (;;) {
            if (off + offsetof(FILE_NOTIFY_INFORMATION, FileName) > bytes)
                break;
            auto* info = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(w.buf + off);
            const std::size_t name_bytes = info->FileNameLength;
            if (off + offsetof(FILE_NOTIFY_INFORMATION, FileName) + name_bytes > bytes)
                break;
            const std::wstring fname =
                lower_w(std::wstring_view(info->FileName, name_bytes / sizeof(WCHAR)));
            auto fi = w.keys.find(fname);
            if (fi != w.keys.end())
                fire.insert(fire.end(), fi->second.begin(), fi->second.end());
            if (info->NextEntryOffset == 0)
                break;
            off += info->NextEntryOffset;
        }
        return fire;
    }

    void run() {
        std::unique_lock lk(mu_);
        while (!stop_.load(std::memory_order_acquire)) {
            lk.unlock();
            DWORD bytes = 0;
            ULONG_PTR ckey = 0;
            LPOVERLAPPED ov = nullptr;
            const BOOL ok =
                ::GetQueuedCompletionStatus(iocp_.get(), &bytes, &ckey, &ov, INFINITE);
            lk.lock();
            if (stop_.load(std::memory_order_acquire))
                break;
            if (ckey == kControlKey)
                continue; // control wake (stop / future nudges)

            auto* w = reinterpret_cast<DirWatch*>(ckey);
            const bool is_ancestor = is_ancestor_watch(w);
            w->io_pending = false;
            if (w->removing) {
                drop_watch(w); // its aborted completion drained — free it now
                continue;
            }
            if (!ok) {
                // Directory handle went bad (deleted). Fall back to an ancestor
                // watch so a recreate re-arms us.
                w->handle.reset();
                if (!is_ancestor)
                    arm_ancestor(fs::path(w->dir));
                continue;
            }
            if (is_ancestor) {
                // Something under the ancestor changed — a previously-absent
                // parent may now exist. Re-arm the ancestor and re-resolve.
                route_noop_rearm(*w);
                reresolve_absent();
                continue;
            }
            // Re-arm BEFORE processing (the #1907 condition-4 discipline: no
            // dropped-change window), collect under the lock, then emit with the
            // lock RELEASED — emit_ re-enters the SparkEngine under its lock and
            // an inline consumer may re-arm (calling back into watch()/mu_).
            std::vector<std::string> fire = collect_fire(*w, bytes);
            arm_dir(*w);
            SparkEmitFn emit = emit_;
            lk.unlock();
            for (const auto& key : fire)
                if (emit)
                    emit(key, SparkData{std::monostate{}});
            lk.lock();
        }
    }

    bool is_ancestor_watch(DirWatch* w) const {
        for (const auto& [k, slot] : ancestors_)
            if (slot.get() == w)
                return true;
        return false;
    }

    void route_noop_rearm(DirWatch& w) {
        // Ancestor watches carry no spark keys — just keep them armed.
        w.io_pending = ::ReadDirectoryChangesW(w.handle.get(), w.buf, sizeof(w.buf), FALSE, kFilter,
                                               nullptr, &w.ov, nullptr) != 0;
    }

    void drop_watch(DirWatch* w) {
        for (auto it = dirs_.begin(); it != dirs_.end(); ++it)
            if (it->second.get() == w) {
                dirs_.erase(it);
                return;
            }
        for (auto it = ancestors_.begin(); it != ancestors_.end(); ++it)
            if (it->second.get() == w) {
                ancestors_.erase(it);
                return;
            }
    }

    std::mutex mu_;
    detail::EventHandle iocp_; ///< IOCP handle (closed via CloseHandle)
    SparkEmitFn emit_;
    std::thread worker_;
    std::atomic<bool> stop_{true};
    std::unordered_map<std::wstring, std::unique_ptr<DirWatch>> dirs_;      ///< real watched dirs
    std::unordered_map<std::wstring, std::unique_ptr<DirWatch>> ancestors_; ///< recreate-recovery
    std::unordered_map<std::string, std::pair<std::wstring, std::wstring>> key_index_; ///< key→(dir,fname)
};

} // namespace

std::unique_ptr<ISparkMechanism> make_file_mechanism() {
    return std::make_unique<WindowsFileMechanism>();
}

} // namespace yuzu::agent

#else // ── Non-Windows: file-change spark is Windows-only for the MVP ──────────

namespace yuzu::agent {

std::unique_ptr<ISparkMechanism> make_file_mechanism() {
    return nullptr; // no mechanism → SparkEngine rejects arm(File) off Windows
}

} // namespace yuzu::agent

#endif // _WIN32
