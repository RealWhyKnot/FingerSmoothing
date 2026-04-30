#pragma once

#include <atomic>
#include <thread>

// Heartbeat thread. Started in ServerTrackedDeviceProvider::Init, joined in
// Cleanup. Every 5 seconds it logs an "alive" line plus a snapshot of every
// hook-fire counter. Two diagnostic purposes:
//   1. Confirm the DLL stays loaded long-term. SteamVR logs DLL_PROCESS_DETACH
//      ~1s after Init returns (same pattern SpaceCalibrator's log shows in
//      production), but a continuing heartbeat after that "unloaded" line
//      proves the DLL is still in vrserver.exe's address space.
//   2. Show which hooks are actually catching traffic. Zero-counts on every
//      IVRDriverInput method while pose-hook counts climb is the smoking gun
//      for the per-driver-wrapper hypothesis.
class Heartbeat
{
public:
    void Start();
    void Stop();

private:
    std::atomic<bool> stopFlag{false};
    std::thread       worker;
};

// Atomic hook-fire counters exposed for the heartbeat thread. Each detour
// bumps its corresponding counter; heartbeat reads them. Defined in
// InterfaceHookInjector.cpp.
namespace hook_stats
{
    extern std::atomic<uint64_t> g_skeletalHits;
    extern std::atomic<uint64_t> g_booleanHits;
    extern std::atomic<uint64_t> g_scalarHits;
    extern std::atomic<uint64_t> g_skeletonCreates;
    extern std::atomic<uint64_t> g_booleanCreates;
    extern std::atomic<uint64_t> g_scalarCreates;
    extern std::atomic<uint64_t> g_hapticCreates;
    extern std::atomic<uint64_t> g_poseUpdates;
    extern std::atomic<uint64_t> g_iobufferWrites;
    extern std::atomic<uint64_t> g_iobufferOpens;
    extern std::atomic<uint64_t> g_genericInterfaceQueries;
}

// Heartbeat-callable helper that walks the per-handle skeleton hit map and
// emits a snapshot of known handles + their cumulative hit counts. Defined
// in InterfaceHookInjector.cpp where the maps and their mutex live.
void LogSkeletonHandleInventory();
