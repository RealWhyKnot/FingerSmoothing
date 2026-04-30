#include "InterfaceHookInjector.h"
#include "Logging.h"
#include "Hooking.h"
#include "Heartbeat.h"
#include "ServerTrackedDeviceProvider.h"

#include <atomic>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

static ServerTrackedDeviceProvider *Driver = nullptr;

// ---------------------------------------------------------------------------
// Atomic hit counters. The heartbeat thread reads these every 5s. Per-handle
// detail is logged on first-fire and every 100th call from inside each detour;
// these counters track the *aggregate* per-hook-type so a steady heartbeat
// can show us which hooks are catching anything, period.
// ---------------------------------------------------------------------------
namespace hook_stats
{
    std::atomic<uint64_t> g_skeletalHits{0};
    std::atomic<uint64_t> g_booleanHits{0};
    std::atomic<uint64_t> g_scalarHits{0};
    std::atomic<uint64_t> g_skeletonCreates{0};
    std::atomic<uint64_t> g_poseUpdates{0};
    std::atomic<uint64_t> g_iobufferWrites{0};
    std::atomic<uint64_t> g_iobufferOpens{0};
    std::atomic<uint64_t> g_genericInterfaceQueries{0};
}

// ---------------------------------------------------------------------------
// Per-handle call counters (mutex-protected; first-fire + every 100th log).
// Kept separate from the atomics above so log output is throttled per
// component, not per type.
// ---------------------------------------------------------------------------
static std::mutex g_handleCountsMutex;
static std::unordered_map<vr::VRInputComponentHandle_t, uint64_t> g_skeletalCallCounts;
static std::unordered_map<vr::VRInputComponentHandle_t, uint64_t> g_booleanCallCounts;
static std::unordered_map<vr::VRInputComponentHandle_t, uint64_t> g_scalarCallCounts;
static std::unordered_map<uint32_t,                    uint64_t> g_poseCallCounts;
static std::unordered_map<vr::IOBufferHandle_t,        uint64_t> g_iobufferWriteCounts;

static bool ShouldLogThrottled(uint64_t &count)
{
    bool log = (count == 0 || (count % 100) == 0);
    count++;
    return log;
}

// ---------------------------------------------------------------------------
// Module-enumeration helpers. On init we snapshot every loaded module in
// vrserver.exe so we can resolve any hooked function-pointer to a (module,
// offset) pair. That tells us *where the implementation actually lives* —
// vrserver.exe, vrclient_x64.dll, driver_indexcontroller.dll, our own DLL,
// etc. Critical for the per-driver-wrapper hypothesis.
// ---------------------------------------------------------------------------
struct LoadedModule
{
    std::string name;
    uintptr_t   base;
    uintptr_t   end;
};

static std::vector<LoadedModule> g_modules;

static void RefreshModuleSnapshot()
{
    g_modules.clear();
    HMODULE handles[1024];
    DWORD needed = 0;
    HANDLE proc = GetCurrentProcess();
    if (!EnumProcessModules(proc, handles, sizeof handles, &needed)) return;
    DWORD count = needed / sizeof(HMODULE);
    if (count > 1024) count = 1024;
    for (DWORD i = 0; i < count; ++i) {
        char nameBuf[MAX_PATH] = {};
        if (!GetModuleBaseNameA(proc, handles[i], nameBuf, sizeof nameBuf)) continue;
        MODULEINFO info{};
        if (!GetModuleInformation(proc, handles[i], &info, sizeof info)) continue;
        LoadedModule m;
        m.name = nameBuf;
        m.base = (uintptr_t)info.lpBaseOfDll;
        m.end  = m.base + info.SizeOfImage;
        g_modules.push_back(m);
    }
}

static const char *ModuleForAddress(uintptr_t addr)
{
    for (auto const &m : g_modules) {
        if (addr >= m.base && addr < m.end) return m.name.c_str();
    }
    return "(unknown)";
}

static void LogModuleSnapshot()
{
    LOG("FS-DIAG ---- begin module snapshot (%zu modules) ----", g_modules.size());
    for (auto const &m : g_modules) {
        LOG("FS-DIAG module %p..%p  %s",
            (void *)m.base, (void *)m.end, m.name.c_str());
    }
    LOG("FS-DIAG ---- end module snapshot ----");
}

// Pretty-print "<modulename>+0xOFFSET" for an address, given a fresh module
// snapshot. Fallback "<raw 0xADDR>" if the address isn't in any known module.
static std::string AddressDisplay(void *p)
{
    if (!p) return "(null)";
    uintptr_t addr = (uintptr_t)p;
    for (auto const &m : g_modules) {
        if (addr >= m.base && addr < m.end) {
            char buf[256];
            std::snprintf(buf, sizeof buf, "%s+0x%llx",
                m.name.c_str(),
                (unsigned long long)(addr - m.base));
            return buf;
        }
    }
    char buf[64];
    std::snprintf(buf, sizeof buf, "<raw 0x%llx>", (unsigned long long)addr);
    return buf;
}

// ---------------------------------------------------------------------------
// IVRDriverContext::GetGenericInterface (vtable[0]).
// Hooked on OUR pDriverContext. If IVRDriverContext is a per-driver wrapper
// (current hypothesis), this only fires for OUR driver's queries. If shared,
// it fires for every driver in vrserver.exe.
// ---------------------------------------------------------------------------
static Hook<void *(*)(vr::IVRDriverContext *, const char *, vr::EVRInitError *)>
    GetGenericInterfaceHook("IVRDriverContext::GetGenericInterface");

// ---------------------------------------------------------------------------
// IVRServerDriverHost (vtable[1] = TrackedDevicePoseUpdated).
// SpaceCalibrator hooks this in production and it fires for Index pose
// updates — so this interface IS shared. Used here as a positive control:
// if our pose hook fires while the IVRDriverInput hooks don't, that's the
// definitive evidence that IVRDriverInput is wrapped per-driver.
// ---------------------------------------------------------------------------
static Hook<void(*)(vr::IVRServerDriverHost *, uint32_t, const vr::DriverPose_t &, uint32_t)>
    TrackedDevicePoseUpdatedHook005("IVRServerDriverHost005::TrackedDevicePoseUpdated");
static Hook<void(*)(vr::IVRServerDriverHost *, uint32_t, const vr::DriverPose_t &, uint32_t)>
    TrackedDevicePoseUpdatedHook006("IVRServerDriverHost006::TrackedDevicePoseUpdated");

// ---------------------------------------------------------------------------
// IVRDriverInput vtable layout (openvr_driver.h):
//   0 CreateBooleanComponent
//   1 UpdateBooleanComponent
//   2 CreateScalarComponent
//   3 UpdateScalarComponent
//   4 CreateHapticComponent
//   5 CreateSkeletonComponent
//   6 UpdateSkeletonComponent
// ---------------------------------------------------------------------------
static constexpr int kUpdateBooleanComponentVTableIndex  = 1;
static constexpr int kUpdateScalarComponentVTableIndex   = 3;
static constexpr int kCreateSkeletonComponentVTableIndex = 5;
static constexpr int kUpdateSkeletonComponentVTableIndex = 6;

static Hook<vr::EVRInputError(*)(vr::IVRDriverInput *, vr::VRInputComponentHandle_t, vr::EVRSkeletalMotionRange, const vr::VRBoneTransform_t *, uint32_t)>
    UpdateSkeletonComponentHook("IVRDriverInput003::UpdateSkeletonComponent");
static Hook<vr::EVRInputError(*)(vr::IVRDriverInput *, vr::VRInputComponentHandle_t, bool, double)>
    UpdateBooleanComponentHook("IVRDriverInput003::UpdateBooleanComponent");
static Hook<vr::EVRInputError(*)(vr::IVRDriverInput *, vr::VRInputComponentHandle_t, float, double)>
    UpdateScalarComponentHook("IVRDriverInput003::UpdateScalarComponent");
static Hook<vr::EVRInputError(*)(vr::IVRDriverInput *, vr::PropertyContainerHandle_t, const char *, const char *, const char *, vr::EVRSkeletalTrackingLevel, const vr::VRBoneTransform_t *, uint32_t, vr::VRInputComponentHandle_t *)>
    CreateSkeletonComponentHook("IVRDriverInput003::CreateSkeletonComponent");

// ---------------------------------------------------------------------------
// IVRIOBuffer vtable layout (openvr_driver.h):
//   0 Open
//   1 Close
//   2 Read
//   3 Write
//   4 PropertyContainer
//   5 HasReaders
// Hypothesis: maybe Index publishes skeletal data via a named IOBuffer that
// vrclient reads on the app side. If Open/Write fire, they'll show us the
// path name and payload size — telling us whether this is the channel.
// ---------------------------------------------------------------------------
static constexpr int kIOBufferOpenVTableIndex  = 0;
static constexpr int kIOBufferWriteVTableIndex = 3;

static Hook<vr::EIOBufferError(*)(vr::IVRIOBuffer *, const char *, vr::EIOBufferMode, uint32_t, uint32_t, vr::IOBufferHandle_t *)>
    IOBufferOpenHook("IVRIOBuffer002::Open");
static Hook<vr::EIOBufferError(*)(vr::IVRIOBuffer *, vr::IOBufferHandle_t, void *, uint32_t)>
    IOBufferWriteHook("IVRIOBuffer002::Write");

// ---------------------------------------------------------------------------
// Detours.
// ---------------------------------------------------------------------------

static void DetourTrackedDevicePoseUpdated005(vr::IVRServerDriverHost *_this, uint32_t unWhichDevice, const vr::DriverPose_t &newPose, uint32_t unPoseStructSize)
{
    hook_stats::g_poseUpdates.fetch_add(1, std::memory_order_relaxed);
    bool log;
    {
        std::lock_guard<std::mutex> lk(g_handleCountsMutex);
        log = ShouldLogThrottled(g_poseCallCounts[unWhichDevice]);
    }
    if (log) {
        LOG("FS-M1 TrackedDevicePoseUpdated005: device=%u poseValid=%d trackingResult=%d",
            unWhichDevice, (int)newPose.poseIsValid, (int)newPose.result);
    }
    TrackedDevicePoseUpdatedHook005.originalFunc(_this, unWhichDevice, newPose, unPoseStructSize);
}

static void DetourTrackedDevicePoseUpdated006(vr::IVRServerDriverHost *_this, uint32_t unWhichDevice, const vr::DriverPose_t &newPose, uint32_t unPoseStructSize)
{
    hook_stats::g_poseUpdates.fetch_add(1, std::memory_order_relaxed);
    bool log;
    {
        std::lock_guard<std::mutex> lk(g_handleCountsMutex);
        log = ShouldLogThrottled(g_poseCallCounts[unWhichDevice]);
    }
    if (log) {
        LOG("FS-M1 TrackedDevicePoseUpdated006: device=%u poseValid=%d trackingResult=%d",
            unWhichDevice, (int)newPose.poseIsValid, (int)newPose.result);
    }
    TrackedDevicePoseUpdatedHook006.originalFunc(_this, unWhichDevice, newPose, unPoseStructSize);
}

static vr::EVRInputError DetourUpdateSkeletonComponent(
    vr::IVRDriverInput *_this,
    vr::VRInputComponentHandle_t ulComponent,
    vr::EVRSkeletalMotionRange eMotionRange,
    const vr::VRBoneTransform_t *pTransforms,
    uint32_t unTransformCount)
{
    hook_stats::g_skeletalHits.fetch_add(1, std::memory_order_relaxed);
    bool log;
    {
        std::lock_guard<std::mutex> lk(g_handleCountsMutex);
        log = ShouldLogThrottled(g_skeletalCallCounts[ulComponent]);
    }
    if (log) {
        if (pTransforms && unTransformCount > 1) {
            LOG("FS-M1 UpdateSkeletonComponent: handle=%llu motionRange=%d boneCount=%u bone1.pos=(%.4f,%.4f,%.4f)",
                (unsigned long long)ulComponent, (int)eMotionRange, unTransformCount,
                pTransforms[1].position.v[0], pTransforms[1].position.v[1], pTransforms[1].position.v[2]);
        } else {
            LOG("FS-M1 UpdateSkeletonComponent: handle=%llu motionRange=%d boneCount=%u (transforms null or boneCount<2)",
                (unsigned long long)ulComponent, (int)eMotionRange, unTransformCount);
        }
    }
    return UpdateSkeletonComponentHook.originalFunc(_this, ulComponent, eMotionRange, pTransforms, unTransformCount);
}

static vr::EVRInputError DetourUpdateBooleanComponent(
    vr::IVRDriverInput *_this,
    vr::VRInputComponentHandle_t ulComponent,
    bool bNewValue,
    double fTimeOffset)
{
    hook_stats::g_booleanHits.fetch_add(1, std::memory_order_relaxed);
    bool log;
    {
        std::lock_guard<std::mutex> lk(g_handleCountsMutex);
        log = ShouldLogThrottled(g_booleanCallCounts[ulComponent]);
    }
    if (log) {
        LOG("FS-M1 UpdateBooleanComponent: handle=%llu value=%d",
            (unsigned long long)ulComponent, (int)bNewValue);
    }
    return UpdateBooleanComponentHook.originalFunc(_this, ulComponent, bNewValue, fTimeOffset);
}

static vr::EVRInputError DetourUpdateScalarComponent(
    vr::IVRDriverInput *_this,
    vr::VRInputComponentHandle_t ulComponent,
    float fNewValue,
    double fTimeOffset)
{
    hook_stats::g_scalarHits.fetch_add(1, std::memory_order_relaxed);
    bool log;
    {
        std::lock_guard<std::mutex> lk(g_handleCountsMutex);
        log = ShouldLogThrottled(g_scalarCallCounts[ulComponent]);
    }
    if (log) {
        LOG("FS-M1 UpdateScalarComponent: handle=%llu value=%.4f",
            (unsigned long long)ulComponent, fNewValue);
    }
    return UpdateScalarComponentHook.originalFunc(_this, ulComponent, fNewValue, fTimeOffset);
}

static vr::EVRInputError DetourCreateSkeletonComponent(
    vr::IVRDriverInput *_this,
    vr::PropertyContainerHandle_t ulContainer,
    const char *pchName,
    const char *pchSkeletonPath,
    const char *pchBasePosePath,
    vr::EVRSkeletalTrackingLevel eSkeletalTrackingLevel,
    const vr::VRBoneTransform_t *pGripLimitTransforms,
    uint32_t unGripLimitTransformCount,
    vr::VRInputComponentHandle_t *pHandle)
{
    auto result = CreateSkeletonComponentHook.originalFunc(
        _this, ulContainer, pchName, pchSkeletonPath, pchBasePosePath,
        eSkeletalTrackingLevel, pGripLimitTransforms, unGripLimitTransformCount, pHandle);
    hook_stats::g_skeletonCreates.fetch_add(1, std::memory_order_relaxed);
    LOG("FS-M1 CreateSkeletonComponent: container=%llu name=%s skeletonPath=%s basePose=%s tracking=%d boneCount=%u -> handle=%llu err=%d",
        (unsigned long long)ulContainer,
        pchName ? pchName : "(null)",
        pchSkeletonPath ? pchSkeletonPath : "(null)",
        pchBasePosePath ? pchBasePosePath : "(null)",
        (int)eSkeletalTrackingLevel,
        unGripLimitTransformCount,
        (unsigned long long)(pHandle ? *pHandle : 0),
        (int)result);
    return result;
}

static vr::EIOBufferError DetourIOBufferOpen(
    vr::IVRIOBuffer *_this,
    const char *pchPath,
    vr::EIOBufferMode mode,
    uint32_t unElementSize,
    uint32_t unElements,
    vr::IOBufferHandle_t *pulBuffer)
{
    auto result = IOBufferOpenHook.originalFunc(_this, pchPath, mode, unElementSize, unElements, pulBuffer);
    hook_stats::g_iobufferOpens.fetch_add(1, std::memory_order_relaxed);
    LOG("FS-M1 IOBuffer::Open: path=%s mode=%d elementSize=%u elements=%u -> handle=%llu err=%d",
        pchPath ? pchPath : "(null)",
        (int)mode, unElementSize, unElements,
        (unsigned long long)(pulBuffer ? *pulBuffer : 0),
        (int)result);
    return result;
}

static vr::EIOBufferError DetourIOBufferWrite(
    vr::IVRIOBuffer *_this,
    vr::IOBufferHandle_t ulBuffer,
    void *pSrc,
    uint32_t unBytes)
{
    hook_stats::g_iobufferWrites.fetch_add(1, std::memory_order_relaxed);
    bool log;
    {
        std::lock_guard<std::mutex> lk(g_handleCountsMutex);
        log = ShouldLogThrottled(g_iobufferWriteCounts[ulBuffer]);
    }
    if (log) {
        LOG("FS-M1 IOBuffer::Write: handle=%llu bytes=%u",
            (unsigned long long)ulBuffer, unBytes);
    }
    return IOBufferWriteHook.originalFunc(_this, ulBuffer, pSrc, unBytes);
}

// ---------------------------------------------------------------------------
// IVRDriverInput / IVRIOBuffer install helpers. Both interfaces are
// hypothesised per-driver-wrapped; we hook *our* pointer's vtable, which may
// or may not catch other drivers' calls. The heartbeat will tell us.
// ---------------------------------------------------------------------------
static void TryInstallSkeletalHooks(void *iface)
{
    if (!iface) return;
    void **vtable = *((void ***)iface);
    LOG("FS-DIAG IVRDriverInput pointer=%s vtable=%s",
        AddressDisplay(iface).c_str(), AddressDisplay(vtable).c_str());
    LOG("FS-DIAG IVRDriverInput vtable[1] UpdateBoolean   = %s", AddressDisplay(vtable[1]).c_str());
    LOG("FS-DIAG IVRDriverInput vtable[3] UpdateScalar    = %s", AddressDisplay(vtable[3]).c_str());
    LOG("FS-DIAG IVRDriverInput vtable[5] CreateSkeleton  = %s", AddressDisplay(vtable[5]).c_str());
    LOG("FS-DIAG IVRDriverInput vtable[6] UpdateSkeleton  = %s", AddressDisplay(vtable[6]).c_str());

    if (!IHook::Exists(UpdateSkeletonComponentHook.name)) {
        UpdateSkeletonComponentHook.CreateHookInObjectVTable(iface, kUpdateSkeletonComponentVTableIndex, &DetourUpdateSkeletonComponent);
        IHook::Register(&UpdateSkeletonComponentHook);
    }
    if (!IHook::Exists(UpdateBooleanComponentHook.name)) {
        UpdateBooleanComponentHook.CreateHookInObjectVTable(iface, kUpdateBooleanComponentVTableIndex, &DetourUpdateBooleanComponent);
        IHook::Register(&UpdateBooleanComponentHook);
    }
    if (!IHook::Exists(UpdateScalarComponentHook.name)) {
        UpdateScalarComponentHook.CreateHookInObjectVTable(iface, kUpdateScalarComponentVTableIndex, &DetourUpdateScalarComponent);
        IHook::Register(&UpdateScalarComponentHook);
    }
    if (!IHook::Exists(CreateSkeletonComponentHook.name)) {
        CreateSkeletonComponentHook.CreateHookInObjectVTable(iface, kCreateSkeletonComponentVTableIndex, &DetourCreateSkeletonComponent);
        IHook::Register(&CreateSkeletonComponentHook);
    }
}

static void TryInstallIOBufferHooks(void *iface)
{
    if (!iface) return;
    void **vtable = *((void ***)iface);
    LOG("FS-DIAG IVRIOBuffer pointer=%s vtable=%s",
        AddressDisplay(iface).c_str(), AddressDisplay(vtable).c_str());
    LOG("FS-DIAG IVRIOBuffer vtable[0] Open  = %s", AddressDisplay(vtable[0]).c_str());
    LOG("FS-DIAG IVRIOBuffer vtable[3] Write = %s", AddressDisplay(vtable[3]).c_str());

    if (!IHook::Exists(IOBufferOpenHook.name)) {
        IOBufferOpenHook.CreateHookInObjectVTable(iface, kIOBufferOpenVTableIndex, &DetourIOBufferOpen);
        IHook::Register(&IOBufferOpenHook);
    }
    if (!IHook::Exists(IOBufferWriteHook.name)) {
        IOBufferWriteHook.CreateHookInObjectVTable(iface, kIOBufferWriteVTableIndex, &DetourIOBufferWrite);
        IHook::Register(&IOBufferWriteHook);
    }
}

static void *DetourGetGenericInterface(vr::IVRDriverContext *_this, const char *pchInterfaceVersion, vr::EVRInitError *peError)
{
    auto originalInterface = GetGenericInterfaceHook.originalFunc(_this, pchInterfaceVersion, peError);
    hook_stats::g_genericInterfaceQueries.fetch_add(1, std::memory_order_relaxed);

    LOG("FS-M1 GetGenericInterface(%s) -> %s",
        pchInterfaceVersion ? pchInterfaceVersion : "(null)",
        AddressDisplay(originalInterface).c_str());

    if (pchInterfaceVersion) {
        std::string iface(pchInterfaceVersion);
        if (iface == "IVRServerDriverHost_005") {
            if (!IHook::Exists(TrackedDevicePoseUpdatedHook005.name)) {
                TrackedDevicePoseUpdatedHook005.CreateHookInObjectVTable(originalInterface, 1, &DetourTrackedDevicePoseUpdated005);
                IHook::Register(&TrackedDevicePoseUpdatedHook005);
            }
        } else if (iface == "IVRServerDriverHost_006") {
            if (!IHook::Exists(TrackedDevicePoseUpdatedHook006.name)) {
                TrackedDevicePoseUpdatedHook006.CreateHookInObjectVTable(originalInterface, 1, &DetourTrackedDevicePoseUpdated006);
                IHook::Register(&TrackedDevicePoseUpdatedHook006);
            }
        } else if (iface == "IVRDriverInput_003") {
            TryInstallSkeletalHooks(originalInterface);
        } else if (iface == "IVRIOBuffer_002") {
            TryInstallIOBufferHooks(originalInterface);
        }
    }

    return originalInterface;
}

// ---------------------------------------------------------------------------
// Public API.
// ---------------------------------------------------------------------------

void InjectHooks(ServerTrackedDeviceProvider *driver, vr::IVRDriverContext *pDriverContext)
{
    Driver = driver;

    LOG("FS-DIAG InjectHooks: pid=%lu pDriverContext=%p driver=%p",
        (unsigned long)GetCurrentProcessId(),
        (void *)pDriverContext, (void *)driver);

    RefreshModuleSnapshot();
    LogModuleSnapshot();

    // Log our pDriverContext's vtable[0] and which module it lives in. If
    // it's vrserver.exe / vrserver.dll, the IVRDriverContext is part of the
    // server runtime. If it's somewhere else, that's a strong hint at a
    // per-driver wrapper.
    {
        void **ctxVtable = *((void ***)pDriverContext);
        LOG("FS-DIAG IVRDriverContext pointer=%s vtable=%s vtable[0] GetGenericInterface = %s",
            AddressDisplay(pDriverContext).c_str(),
            AddressDisplay(ctxVtable).c_str(),
            AddressDisplay(ctxVtable[0]).c_str());
    }

    // MH_ERROR_ALREADY_INITIALIZED is fine — it just means another driver in
    // vrserver.exe already called MH_Initialize (typically SpaceCalibrator,
    // which loads alongside us if both drivers are installed). The MinHook
    // runtime is process-global so initialising twice is a no-op; we can
    // proceed to install our hooks against the shared runtime.
    auto err = MH_Initialize();
    if (err != MH_OK && err != MH_ERROR_ALREADY_INITIALIZED) {
        LOG("MH_Initialize hard error (%s); aborting hook install", MH_StatusToString(err));
        return;
    }
    LOG("FS-DIAG MH_Initialize: %s", MH_StatusToString(err));

    // Install GetGenericInterface detour FIRST so subsequent SDK accessor
    // calls (vr::VRDriverInput, vr::VRIOBuffer, vr::VRServerDriverHost) flow
    // through the detour and trigger interface-specific hook installation.
    GetGenericInterfaceHook.CreateHookInObjectVTable(pDriverContext, 0, &DetourGetGenericInterface);
    IHook::Register(&GetGenericInterfaceHook);

    // Pre-install via the SDK's already-cached pointers (in case our SDK
    // copy populated them during VR_INIT_SERVER_DRIVER_CONTEXT, which would
    // bypass our newly-installed GetGenericInterface detour).
    if (auto *input = vr::VRDriverInput()) {
        TryInstallSkeletalHooks(input);
    }
    if (auto *iob = vr::VRIOBuffer()) {
        TryInstallIOBufferHooks(iob);
    }
    if (auto *host = vr::VRServerDriverHost()) {
        // We don't know which interface version vr::VRServerDriverHost()
        // actually returned; the SDK calls IVRServerDriverHost_Version
        // ("_006" in this header). If 006 wasn't already cached the
        // GetGenericInterface detour just fired and hooked it; this branch
        // covers the cached-pre-our-hook case.
        if (!IHook::Exists(TrackedDevicePoseUpdatedHook006.name)) {
            TrackedDevicePoseUpdatedHook006.CreateHookInObjectVTable(host, 1, &DetourTrackedDevicePoseUpdated006);
            IHook::Register(&TrackedDevicePoseUpdatedHook006);
            LOG("FS-DIAG fallback-installed TrackedDevicePoseUpdatedHook006 from cached vr::VRServerDriverHost()");
        }
    }
}

void DisableHooks()
{
    // Tear down OUR hooks only. We deliberately do NOT call MH_Uninitialize:
    // the MinHook runtime is process-global, and another driver in
    // vrserver.exe (e.g. SpaceCalibrator) may still be using it. Uninitialize
    // would remove ALL hooks process-wide — silently breaking any neighbour
    // who hooked something. IHook::DestroyAll only removes the hooks we
    // registered with our IHook bookkeeping, leaving the runtime intact for
    // anyone else still attached.
    IHook::DestroyAll();
}
