#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

using NTSTATUS_T = LONG;
using KPRIORITY = LONG;

struct NativeUnicodeString {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
};

struct NativeClientId {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
};

struct NativeObjectAttributes {
    ULONG Length;
    HANDLE RootDirectory;
    PVOID ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
};

struct NativeSystemThreadInformation {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    NativeClientId ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
};

struct NativeSystemProcessInformation {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    NativeUnicodeString ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    NativeSystemThreadInformation Threads[1];
};

struct NativeThreadBasicInformation {
    NTSTATUS_T ExitStatus;
    PVOID TebBaseAddress;
    NativeClientId ClientId;
    ULONG_PTR AffinityMask;
    KPRIORITY Priority;
    LONG BasePriority;
};

using RtlAllocateHeapFn = PVOID(NTAPI*)(PVOID, ULONG, SIZE_T);
using RtlFreeHeapFn = BOOLEAN(NTAPI*)(PVOID, ULONG, PVOID);
using RtlCreateHeapFn = PVOID(NTAPI*)(ULONG, PVOID, SIZE_T, SIZE_T, PVOID, PVOID);
using RtlDestroyHeapFn = PVOID(NTAPI*)(PVOID);
using RtlReAllocateHeapFn = PVOID(NTAPI*)(PVOID, ULONG, PVOID, SIZE_T);
using NtOpenProcessTokenFn = NTSTATUS_T(NTAPI*)(HANDLE, ACCESS_MASK, PHANDLE);
using NtAdjustPrivilegesTokenFn = NTSTATUS_T(NTAPI*)(HANDLE, BOOLEAN, PTOKEN_PRIVILEGES, ULONG, PTOKEN_PRIVILEGES, PULONG);
using NtQueryInformationTokenFn = NTSTATUS_T(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtOpenThreadFn = NTSTATUS_T(NTAPI*)(PHANDLE, ACCESS_MASK, NativeObjectAttributes*, NativeClientId*);
using NtOpenProcessFn = NTSTATUS_T(NTAPI*)(PHANDLE, ACCESS_MASK, NativeObjectAttributes*, NativeClientId*);
using NtQuerySystemInformationFn = NTSTATUS_T(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
using NtQueryInformationThreadFn = NTSTATUS_T(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtSetInformationThreadFn = NTSTATUS_T(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
using NtGetNextThreadFn = NTSTATUS_T(NTAPI*)(HANDLE, HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);
using NtCloseFn = NTSTATUS_T(NTAPI*)(HANDLE);
using NtDelayExecutionFn = NTSTATUS_T(NTAPI*)(BOOLEAN, PLARGE_INTEGER);

constexpr NTSTATUS_T kStatusInfoLengthMismatch = static_cast<NTSTATUS_T>(0xC0000004L);
constexpr NTSTATUS_T kStatusAccessDenied = static_cast<NTSTATUS_T>(0xC0000022L);
constexpr NTSTATUS_T kStatusInvalidCid = static_cast<NTSTATUS_T>(0xC000000BL);
constexpr NTSTATUS_T kStatusInvalidParameter = static_cast<NTSTATUS_T>(0xC000000DL);

constexpr ULONG kSystemProcessInformation = 5;
constexpr ULONG kThreadBasicInformation = 0;
constexpr ULONG kThreadBasePriority = 3;

constexpr KPRIORITY kTargetPriority = 16;
constexpr KPRIORITY kNormalThreadBasePriority = 0;

constexpr ULONG kHeapGrowable = 2;
constexpr uint32_t kDefaultIntervalMs = 1000;
constexpr uint32_t kFullRefreshMs = 120000;

constexpr uint32_t kRetryCooldownScans = 4096;
constexpr uint32_t kRetryCooldownFixedScans = 1;
constexpr size_t kThreadCacheSize = 1024;

constexpr size_t kProcessCacheSize = 192;
constexpr size_t kProcessIncrementalBudget = 1;

struct ScanStats {
    uint32_t seenPriority16 = 0;
    uint32_t fixedPriority16 = 0;
    uint32_t cachedSkipped = 0;
    uint32_t openFailures = 0;
    uint32_t protectedFailures = 0;
    uint32_t transientFailures = 0;
    uint32_t fixFailures = 0;
};

struct ThreadCacheEntry {
    DWORD processId = 0;
    DWORD threadId = 0;
    uint32_t lastScan = 0;
    uint8_t state = 0;
};

struct ThreadCache {
    ThreadCacheEntry entries[kThreadCacheSize]{};
};

struct ProcessCacheEntry {
    DWORD processId = 0;
    uint32_t lastSeenScan = 0;
};

struct ProcessCache {
    ProcessCacheEntry entries[kProcessCacheSize]{};
    size_t cursor = 0;
};

static uint32_t HashThreadKey(DWORD processId, DWORD threadId) noexcept {
    uint32_t x = processId * 16777619u ^ threadId;
    x ^= x >> 16;
    x *= 0x7feb352dU;
    x ^= x >> 15;
    return x;
}

static bool ShouldSkipCachedThread(ThreadCache& cache, DWORD processId, DWORD threadId, uint32_t scanId) noexcept {
    const size_t start = HashThreadKey(processId, threadId) & (kThreadCacheSize - 1);
    for (size_t probe = 0; probe < 4; ++probe) {
        ThreadCacheEntry& entry = cache.entries[(start + probe) & (kThreadCacheSize - 1)];
        if (entry.state == 0) {
            return false;
        }

        if (entry.processId == processId && entry.threadId == threadId) {
            const uint32_t age = scanId - entry.lastScan;
            if (entry.state == 1) {
                return age < kRetryCooldownFixedScans;
            }
            return age < kRetryCooldownScans;
        }
    }

    return false;
}

static void RememberThread(ThreadCache& cache, DWORD processId, DWORD threadId, uint32_t scanId, uint8_t state) noexcept {
    const size_t start = HashThreadKey(processId, threadId) & (kThreadCacheSize - 1);
    size_t selected = start;
    uint32_t oldestAge = 0;

    for (size_t probe = 0; probe < 4; ++probe) {
        ThreadCacheEntry& entry = cache.entries[(start + probe) & (kThreadCacheSize - 1)];
        if (entry.state == 0 || (entry.processId == processId && entry.threadId == threadId)) {
            selected = (start + probe) & (kThreadCacheSize - 1);
            break;
        }

        const uint32_t age = scanId - entry.lastScan;
        if (age >= oldestAge) {
            oldestAge = age;
            selected = (start + probe) & (kThreadCacheSize - 1);
        }
    }

    cache.entries[selected] = ThreadCacheEntry{ processId, threadId, scanId, state };
}

static void RememberProcess(ProcessCache& processCache, DWORD processId, uint32_t scanId) noexcept {
    if (processId == 0) {
        return;
    }

    size_t freeSlot = kProcessCacheSize;
    size_t oldestSlot = 0;
    uint32_t oldestSeen = UINT32_MAX;

    for (size_t i = 0; i < kProcessCacheSize; ++i) {
        ProcessCacheEntry& entry = processCache.entries[i];
        if (entry.processId == processId) {
            entry.lastSeenScan = scanId;
            return;
        }

        if (entry.processId == 0 && freeSlot == kProcessCacheSize) {
            freeSlot = i;
        }

        if (entry.lastSeenScan < oldestSeen) {
            oldestSeen = entry.lastSeenScan;
            oldestSlot = i;
        }
    }

    const size_t slot = (freeSlot != kProcessCacheSize) ? freeSlot : oldestSlot;
    processCache.entries[slot] = ProcessCacheEntry{ processId, scanId };
}

static uint32_t ReadIntervalMs(int argc, wchar_t** argv) noexcept {
    if (argc < 2) {
        return kDefaultIntervalMs;
    }

    wchar_t* end = nullptr;
    const unsigned long value = wcstoul(argv[1], &end, 10);
    if (end == argv[1] || *end != L'\0' || value > 60000UL) {
        return kDefaultIntervalMs;
    }
    return static_cast<uint32_t>(value);
}

static bool QueryProcessSnapshot(NtQuerySystemInformationFn query, RtlReAllocateHeapFn reallocateHeap, PVOID heap, PVOID& buffer, ULONG& capacity) noexcept {
    ULONG required = 0;
    NTSTATUS_T status = query(kSystemProcessInformation, buffer, capacity, &required);

    while (status == kStatusInfoLengthMismatch) {
        const ULONG nextCapacity = required > capacity ? required + 65536U : capacity * 2U;
        PVOID nextBuffer = reallocateHeap(heap, 0, buffer, nextCapacity);
        if (nextBuffer == nullptr) {
            return false;
        }

        buffer = nextBuffer;
        capacity = nextCapacity;
        required = 0;
        status = query(kSystemProcessInformation, buffer, capacity, &required);
    }

    return status >= 0;
}

static HANDLE NtCurrentProcessHandle() noexcept {
    return reinterpret_cast<HANDLE>(static_cast<LONG_PTR>(-1));
}

static void EnableAllTokenPrivileges(RtlAllocateHeapFn allocateHeap,
    RtlFreeHeapFn freeHeap,
    PVOID heap,
    NtOpenProcessTokenFn openProcessToken,
    NtQueryInformationTokenFn queryToken,
    NtAdjustPrivilegesTokenFn adjustToken,
    NtCloseFn closeHandle) noexcept {
    HANDLE token = nullptr;
    if (openProcessToken(NtCurrentProcessHandle(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token) < 0) {
        return;
    }

    ULONG required = 0;
    queryToken(token, TokenPrivileges, nullptr, 0, &required);
    if (required == 0) {
        closeHandle(token);
        return;
    }

    PVOID privileges = allocateHeap(heap, 0, required);
    if (privileges == nullptr) {
        closeHandle(token);
        return;
    }

    auto* tokenPrivileges = reinterpret_cast<TOKEN_PRIVILEGES*>(privileges);
    if (queryToken(token, TokenPrivileges, tokenPrivileges, required, &required) < 0) {
        freeHeap(heap, 0, privileges);
        closeHandle(token);
        return;
    }

    for (DWORD i = 0; i < tokenPrivileges->PrivilegeCount; ++i) {
        tokenPrivileges->Privileges[i].Attributes |= SE_PRIVILEGE_ENABLED;
    }

    adjustToken(token, FALSE, tokenPrivileges, required, nullptr, nullptr);
    freeHeap(heap, 0, privileges);
    closeHandle(token);
}

static bool FixThreadPriority(NtOpenThreadFn openThread,
    NtSetInformationThreadFn setThread,
    NtCloseFn closeHandle,
    DWORD processId,
    DWORD threadId,
    DWORD& error,
    uint8_t& failureKind) noexcept {
    NativeObjectAttributes attributes{ sizeof(attributes), nullptr, nullptr, 0, nullptr, nullptr };
    NativeClientId clientId{ reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(processId)), reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(threadId)) };

    HANDLE thread = nullptr;
    const NTSTATUS_T openStatus = openThread(&thread, THREAD_SET_INFORMATION, &attributes, &clientId);
    if (openStatus < 0 || thread == nullptr) {
        error = ERROR_ACCESS_DENIED;
        if (openStatus == kStatusInvalidCid || openStatus == kStatusInvalidParameter) {
            failureKind = 2;
        }
        else if (openStatus == kStatusAccessDenied) {
            failureKind = 1;
        }
        else {
            failureKind = 3;
        }
        return false;
    }

    KPRIORITY normalPriority = kNormalThreadBasePriority;
    const NTSTATUS_T setStatus = setThread(thread, kThreadBasePriority, &normalPriority, sizeof(normalPriority));
    closeHandle(thread);

    if (setStatus < 0) {
        error = (setStatus == kStatusAccessDenied) ? ERROR_ACCESS_DENIED : ERROR_GEN_FAILURE;
        return false;
    }

    error = ERROR_SUCCESS;
    return true;
}

static HANDLE OpenProcessForThreadWalk(NtOpenProcessFn openProcess, DWORD processId) noexcept {
    NativeObjectAttributes attributes{ sizeof(attributes), nullptr, nullptr, 0, nullptr, nullptr };
    NativeClientId clientId{ reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(processId)), nullptr };

    HANDLE process = nullptr;
    if (openProcess(&process, PROCESS_QUERY_INFORMATION, &attributes, &clientId) < 0) {
        return nullptr;
    }
    return process;
}


static void SeedActiveProcessesLight(ProcessCache& processCache, uint32_t scanId) noexcept {
    DWORD pid = 0;
    HWND fg = GetForegroundWindow();
    if (fg != nullptr) {
        GetWindowThreadProcessId(fg, &pid);
        if (pid != 0) {
            RememberProcess(processCache, pid, scanId);
        }
    }

}

static ScanStats FullRefreshAndSeedProcesses(NtQuerySystemInformationFn query,
    RtlReAllocateHeapFn reallocateHeap,
    PVOID heap,
    PVOID& buffer,
    ULONG& capacity,
    NtOpenThreadFn openThread,
    NtSetInformationThreadFn setThread,
    NtCloseFn closeHandle,
    ThreadCache& threadCache,
    ProcessCache& processCache,
    uint32_t scanId) noexcept {
    ScanStats stats{};
    if (!QueryProcessSnapshot(query, reallocateHeap, heap, buffer, capacity)) {
        return stats;
    }

    const DWORD currentThreadId = GetCurrentThreadId();
    auto* process = reinterpret_cast<NativeSystemProcessInformation*>(buffer);
    for (;;) {
        const NativeSystemThreadInformation* thread = process->Threads;
        for (ULONG i = 0; i < process->NumberOfThreads; ++i, ++thread) {
            if (thread->Priority != kTargetPriority && thread->BasePriority != kTargetPriority) {
                continue;
            }

            const DWORD processId = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(thread->ClientId.UniqueProcess));
            const DWORD threadId = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(thread->ClientId.UniqueThread));
            if (threadId == 0 || threadId == currentThreadId) {
                continue;
            }

            ++stats.seenPriority16;
            RememberProcess(processCache, processId, scanId);

            if (ShouldSkipCachedThread(threadCache, processId, threadId, scanId)) {
                ++stats.cachedSkipped;
                continue;
            }

            DWORD error = ERROR_SUCCESS;
            uint8_t failureKind = 3;
            if (FixThreadPriority(openThread, setThread, closeHandle, processId, threadId, error, failureKind)) {
                ++stats.fixedPriority16;
                RememberThread(threadCache, processId, threadId, scanId, 1);
            }
            else if (error == ERROR_ACCESS_DENIED) {
                if (failureKind == 2) {
                    ++stats.openFailures;
                    ++stats.transientFailures;
                    RememberThread(threadCache, processId, threadId, scanId, 0);
                }
                else if (failureKind == 1) {
                    ++stats.protectedFailures;
                    RememberThread(threadCache, processId, threadId, scanId, 2);
                }
                else {
                    ++stats.openFailures;
                    RememberThread(threadCache, processId, threadId, scanId, 2);
                }
            }
            else {
                ++stats.fixFailures;
                RememberThread(threadCache, processId, threadId, scanId, 3);
            }
        }

        if (process->NextEntryOffset == 0) {
            break;
        }

        process = reinterpret_cast<NativeSystemProcessInformation*>(reinterpret_cast<BYTE*>(process) + process->NextEntryOffset);
    }

    return stats;
}

static ScanStats IncrementalProcessCheck(NtOpenProcessFn openProcess,
    NtGetNextThreadFn getNextThread,
    NtQueryInformationThreadFn queryThread,
    NtSetInformationThreadFn setThread,
    NtCloseFn closeHandle,
    ThreadCache& threadCache,
    ProcessCache& processCache,
    uint32_t scanId) noexcept {
    ScanStats stats{};
    const DWORD currentThreadId = GetCurrentThreadId();

    auto scanOneProcess = [&](DWORD processId) {
        if (processId == 0) {
            return;
        }

        HANDLE process = OpenProcessForThreadWalk(openProcess, processId);
        if (process == nullptr) {
            return;
        }

        HANDLE previousThread = nullptr;
        for (;;) {
            HANDLE thread = nullptr;
            const NTSTATUS_T walkStatus = getNextThread(process,
                previousThread,
                THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION,
                0,
                0,
                &thread);

            if (previousThread != nullptr) {
                closeHandle(previousThread);
            }
            previousThread = thread;

            if (walkStatus < 0 || thread == nullptr) {
                break;
            }

            NativeThreadBasicInformation basic{};
            if (queryThread(thread, kThreadBasicInformation, &basic, sizeof(basic), nullptr) < 0) {
                continue;
            }

            const DWORD threadId = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(basic.ClientId.UniqueThread));
            if (threadId == 0 || threadId == currentThreadId) {
                continue;
            }

            if (basic.Priority != kTargetPriority && basic.BasePriority != kTargetPriority) {
                continue;
            }

            ++stats.seenPriority16;
            if (ShouldSkipCachedThread(threadCache, processId, threadId, scanId)) {
                ++stats.cachedSkipped;
                continue;
            }

            KPRIORITY normalPriority = kNormalThreadBasePriority;
            const NTSTATUS_T setStatus = setThread(thread, kThreadBasePriority, &normalPriority, sizeof(normalPriority));
            if (setStatus >= 0) {
                ++stats.fixedPriority16;
                RememberThread(threadCache, processId, threadId, scanId, 1);
            }
            else if (setStatus == kStatusAccessDenied) {
                ++stats.openFailures;
                RememberThread(threadCache, processId, threadId, scanId, 2);
            }
            else {
                ++stats.fixFailures;
                RememberThread(threadCache, processId, threadId, scanId, 3);
            }
        }

        if (previousThread != nullptr) {
            closeHandle(previousThread);
        }
        closeHandle(process);
    };

    for (size_t budget = 0; budget < kProcessIncrementalBudget; ++budget) {
        ProcessCacheEntry& processEntry = processCache.entries[(processCache.cursor + budget) % kProcessCacheSize];
        scanOneProcess(processEntry.processId);
    }

    processCache.cursor = (processCache.cursor + kProcessIncrementalBudget) % kProcessCacheSize;
    return stats;
}

static ScanStats FastForegroundCheck(NtOpenProcessFn openProcess,
    NtGetNextThreadFn getNextThread,
    NtQueryInformationThreadFn queryThread,
    NtSetInformationThreadFn setThread,
    NtCloseFn closeHandle,
    ThreadCache& threadCache,
    uint32_t scanId) noexcept {
    ScanStats stats{};

    DWORD processId = 0;
    const HWND foreground = GetForegroundWindow();
    if (foreground == nullptr) {
        return stats;
    }

    GetWindowThreadProcessId(foreground, &processId);
    if (processId == 0) {
        return stats;
    }

    ProcessCache foregroundOnly{};
    foregroundOnly.entries[0].processId = processId;
    return IncrementalProcessCheck(openProcess, getNextThread, queryThread, setThread, closeHandle, threadCache, foregroundOnly, scanId);
}

int wmain(int argc, wchar_t** argv) {
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) {
        return 1;
    }

    const auto allocateHeap = reinterpret_cast<RtlAllocateHeapFn>(GetProcAddress(ntdll, "RtlAllocateHeap"));
    const auto freeHeap = reinterpret_cast<RtlFreeHeapFn>(GetProcAddress(ntdll, "RtlFreeHeap"));
    const auto reallocateHeap = reinterpret_cast<RtlReAllocateHeapFn>(GetProcAddress(ntdll, "RtlReAllocateHeap"));
    const auto createHeap = reinterpret_cast<RtlCreateHeapFn>(GetProcAddress(ntdll, "RtlCreateHeap"));
    const auto destroyHeap = reinterpret_cast<RtlDestroyHeapFn>(GetProcAddress(ntdll, "RtlDestroyHeap"));
    const auto openProcessToken = reinterpret_cast<NtOpenProcessTokenFn>(GetProcAddress(ntdll, "NtOpenProcessToken"));
    const auto queryToken = reinterpret_cast<NtQueryInformationTokenFn>(GetProcAddress(ntdll, "NtQueryInformationToken"));
    const auto adjustToken = reinterpret_cast<NtAdjustPrivilegesTokenFn>(GetProcAddress(ntdll, "NtAdjustPrivilegesToken"));
    const auto openThread = reinterpret_cast<NtOpenThreadFn>(GetProcAddress(ntdll, "NtOpenThread"));
    const auto openProcess = reinterpret_cast<NtOpenProcessFn>(GetProcAddress(ntdll, "NtOpenProcess"));
    const auto query = reinterpret_cast<NtQuerySystemInformationFn>(GetProcAddress(ntdll, "NtQuerySystemInformation"));
    const auto queryThread = reinterpret_cast<NtQueryInformationThreadFn>(GetProcAddress(ntdll, "NtQueryInformationThread"));
    const auto setThread = reinterpret_cast<NtSetInformationThreadFn>(GetProcAddress(ntdll, "NtSetInformationThread"));
    const auto getNextThread = reinterpret_cast<NtGetNextThreadFn>(GetProcAddress(ntdll, "NtGetNextThread"));
    const auto closeHandle = reinterpret_cast<NtCloseFn>(GetProcAddress(ntdll, "NtClose"));
    const auto delayExecution = reinterpret_cast<NtDelayExecutionFn>(GetProcAddress(ntdll, "NtDelayExecution"));

    if (allocateHeap == nullptr || freeHeap == nullptr || reallocateHeap == nullptr ||
        createHeap == nullptr || destroyHeap == nullptr ||
        openProcessToken == nullptr || queryToken == nullptr || adjustToken == nullptr ||
        openThread == nullptr || openProcess == nullptr || query == nullptr || queryThread == nullptr ||
        setThread == nullptr || getNextThread == nullptr || closeHandle == nullptr || delayExecution == nullptr) {
        return 1;
    }

    PVOID heap = createHeap(kHeapGrowable, nullptr, 0, 0, nullptr, nullptr);
    if (heap == nullptr) {
        return 1;
    }

    EnableAllTokenPrivileges(allocateHeap, freeHeap, heap, openProcessToken, queryToken, adjustToken, closeHandle);

    ULONG capacity = 256U * 1024U;
    PVOID buffer = allocateHeap(heap, 0, capacity);
    if (buffer == nullptr) {
        capacity = 64U * 1024U;
        buffer = allocateHeap(heap, 0, capacity);
    }
    if (buffer == nullptr) {
        destroyHeap(heap);
        return 1;
    }

    ThreadCache threadCache{};
    ProcessCache processCache{};

    uint32_t scanId = 1;
    const uint32_t intervalMs = ReadIntervalMs(argc, argv);
    const uint32_t scansPerFullRefresh = intervalMs == 0 ? 1 : (kFullRefreshMs / intervalMs == 0 ? 1 : kFullRefreshMs / intervalMs);

    std::printf("interval=%u ms, full refresh cadence=%u scans (~120s), incremental budget=%zu processes/scan\n",
        intervalMs,
        scansPerFullRefresh,
        kProcessIncrementalBudget);

    do {
        const bool doFullRefresh = (intervalMs == 0) || (scanId == 1) || ((scanId % scansPerFullRefresh) == 0);
        if (!doFullRefresh) {
            SeedActiveProcessesLight(processCache, scanId);
        }

        const ScanStats stats = doFullRefresh
            ? FullRefreshAndSeedProcesses(query, reallocateHeap, heap, buffer, capacity, openThread, setThread, closeHandle, threadCache, processCache, scanId)
            : IncrementalProcessCheck(openProcess, getNextThread, queryThread, setThread, closeHandle, threadCache, processCache, scanId);

        ScanStats merged = stats;
        if (!doFullRefresh) {
            const ScanStats foregroundStats = FastForegroundCheck(openProcess,
                getNextThread,
                queryThread,
                setThread,
                closeHandle,
                threadCache,
                scanId);
            merged.seenPriority16 += foregroundStats.seenPriority16;
            merged.fixedPriority16 += foregroundStats.fixedPriority16;
            merged.cachedSkipped += foregroundStats.cachedSkipped;
            merged.openFailures += foregroundStats.openFailures;
            merged.protectedFailures += foregroundStats.protectedFailures;
            merged.transientFailures += foregroundStats.transientFailures;
            merged.fixFailures += foregroundStats.fixFailures;
        }

        if (intervalMs == 0 || merged.fixedPriority16 != 0 || merged.openFailures != 0 || merged.fixFailures != 0) {
            std::printf("full=%u seen=%u fixed=%u skipped=%u open_fail=%u protected=%u transient=%u fix_fail=%u\n",
                doFullRefresh ? 1u : 0u,
                merged.seenPriority16,
                merged.fixedPriority16,
                merged.cachedSkipped,
                merged.openFailures,
                merged.protectedFailures,
                merged.transientFailures,
                merged.fixFailures);
        }

        if (intervalMs == 0) {
            break;
        }

        ++scanId;
        LARGE_INTEGER delay{};
        delay.QuadPart = -static_cast<LONGLONG>(intervalMs) * 10000LL;
        delayExecution(FALSE, &delay);
    } while (true);

    freeHeap(heap, 0, buffer);
    destroyHeap(heap);
    return 0;
}
