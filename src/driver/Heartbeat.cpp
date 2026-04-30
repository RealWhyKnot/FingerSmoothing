#include "Heartbeat.h"
#include "Logging.h"

#include <chrono>
#include <set>
#include <string>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>

namespace {

// Snapshot all currently-loaded module names. Used by the heartbeat to detect
// when new modules (e.g. driver_indexcontroller.dll) get loaded *after* our
// init-time module dump, which is critical for spotting Index appearing.
std::set<std::string> SnapshotModuleNames()
{
    std::set<std::string> out;
    HMODULE handles[1024];
    DWORD needed = 0;
    HANDLE proc = GetCurrentProcess();
    if (!EnumProcessModules(proc, handles, sizeof handles, &needed)) return out;
    DWORD count = needed / sizeof(HMODULE);
    if (count > 1024) count = 1024;
    for (DWORD i = 0; i < count; ++i) {
        char nameBuf[MAX_PATH] = {};
        if (GetModuleBaseNameA(proc, handles[i], nameBuf, sizeof nameBuf)) {
            out.insert(nameBuf);
        }
    }
    return out;
}

} // anonymous

void Heartbeat::Start()
{
    stopFlag.store(false);
    worker = std::thread([this]() {
        int seconds = 0;
        // Track previously-seen module names so we only log diffs, not the
        // full set every tick. Initialised on the first heartbeat against
        // the init-time module dump in InjectHooks.
        std::set<std::string> previousModules = SnapshotModuleNames();

        while (!stopFlag.load()) {
            // Sleep in small slices so Stop() can return quickly without
            // waiting up to 5s for the next wake.
            for (int i = 0; i < 50 && !stopFlag.load(); ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            if (stopFlag.load()) break;
            seconds += 5;

            LOG("FS-HEARTBEAT t=%ds  skeletalUpdates=%llu  booleanUpdates=%llu  scalarUpdates=%llu  skelCreates=%llu  boolCreates=%llu  scalarCreates=%llu  hapticCreates=%llu  poseUpdates=%llu  iobufWrites=%llu  iobufOpens=%llu  genericIfaceQueries=%llu",
                seconds,
                (unsigned long long)hook_stats::g_skeletalHits.load(),
                (unsigned long long)hook_stats::g_booleanHits.load(),
                (unsigned long long)hook_stats::g_scalarHits.load(),
                (unsigned long long)hook_stats::g_skeletonCreates.load(),
                (unsigned long long)hook_stats::g_booleanCreates.load(),
                (unsigned long long)hook_stats::g_scalarCreates.load(),
                (unsigned long long)hook_stats::g_hapticCreates.load(),
                (unsigned long long)hook_stats::g_poseUpdates.load(),
                (unsigned long long)hook_stats::g_iobufferWrites.load(),
                (unsigned long long)hook_stats::g_iobufferOpens.load(),
                (unsigned long long)hook_stats::g_genericInterfaceQueries.load());

            // Per-handle inventory: each known component handle and its
            // cumulative hit count. Two skeleton handles + two pose-device
            // handles is the expected steady-state for both Index hands.
            LogSkeletonHandleInventory();

            // Module diff: log any module that's new since last tick. The
            // expected interesting one is `driver_indexcontroller.dll`
            // appearing after watchdog phase ends.
            auto currentModules = SnapshotModuleNames();
            for (auto const &name : currentModules) {
                if (previousModules.find(name) == previousModules.end()) {
                    LOG("FS-DIAG module loaded since last heartbeat: %s", name.c_str());
                }
            }
            for (auto const &name : previousModules) {
                if (currentModules.find(name) == currentModules.end()) {
                    LOG("FS-DIAG module unloaded since last heartbeat: %s", name.c_str());
                }
            }
            previousModules = std::move(currentModules);
        }
    });
}

void Heartbeat::Stop()
{
    stopFlag.store(true);
    if (worker.joinable()) worker.join();
}
