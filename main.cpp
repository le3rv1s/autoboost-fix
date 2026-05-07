#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

#ifndef THREAD_QUERY_LIMITED_INFORMATION
#define THREAD_QUERY_LIMITED_INFORMATION 0x0800
#endif

#ifndef THREAD_SET_LIMITED_INFORMATION
#define THREAD_SET_LIMITED_INFORMATION 0x0400
#endif

using NTSTATUS_T = LONG;
using KPRIORITY = LONG;

struct UNICODE_STRING_T {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
};

constexpr NTSTATUS_T STATUS_INFO_LENGTH_MISMATCH = static_cast<NTSTATUS_T>(0xC0000004L);
constexpr ULONG SystemProcessInformation = 5;
constexpr KPRIORITY kTargetPriority = 16;
constexpr uint32_t kDefaultIntervalMs = 1000;
constexpr uint32_t kGlobalRefreshScans = 60;
constexpr uint32_t kRetryCooldownScans = 256;
constexpr size_t kThreadCacheSize = 512;
constexpr size_t kProcessCacheSize = 64;
constexpr uint8_t kCacheEmpty = 0;
constexpr uint8_t kCacheFixed = 1;
constexpr uint8_t kCacheDenied = 2;
constexpr uint8_t kCacheFailed = 3;
constexpr ACCESS_MASK kThreadFixAccess = THREAD_SET_LIMITED_INFORMATION;
constexpr ACCESS_MASK kThreadQueryFixAccess = THREAD_QUERY_LIMITED_INFORMATION | THREAD_SET_LIMITED_INFORMATION;
constexpr DWORD kProcessEnumAccess = PROCESS_QUERY_LIMITED_INFORMATION;
constexpr DWORD kProcessBoostAccess = PROCESS_SET_INFORMATION;

struct CLIENT_ID_T {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
};

struct OBJECT_ATTRIBUTES_T {
    ULONG Length;
    HANDLE RootDirectory;
    PVOID ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
};

struct SYSTEM_THREAD_INFORMATION_T {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID_T ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
};

struct SYSTEM_PROCESS_INFORMATION_T {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING_T ImageName;
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
    SYSTEM_THREAD_INFORMATION_T Threads[1];
};

using RtlAllocateHeapFn = PVOID(NTAPI*)(PVOID, ULONG, SIZE_T);
using RtlFreeHeapFn = BOOLEAN(NTAPI*)(PVOID, ULONG, PVOID);
using RtlCreateHeapFn = PVOID(NTAPI*)(ULONG, PVOID, SIZE_T, SIZE_T, PVOID, PVOID);
using RtlDestroyHeapFn = PVOID(NTAPI*)(PVOID);
using NtOpenProcessTokenFn = NTSTATUS_T(NTAPI*)(HANDLE, ACCESS_MASK, PHANDLE);
using NtAdjustPrivilegesTokenFn = NTSTATUS_T(NTAPI*)(HANDLE, BOOLEAN, PTOKEN_PRIVILEGES, ULONG, PTOKEN_PRIVILEGES, PULONG);
using NtQueryInformationTokenFn = NTSTATUS_T(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtOpenThreadFn = NTSTATUS_T(NTAPI*)(PHANDLE, ACCESS_MASK, OBJECT_ATTRIBUTES_T*, CLIENT_ID_T*);
using NtOpenProcessFn = NTSTATUS_T(NTAPI*)(PHANDLE, ACCESS_MASK, OBJECT_ATTRIBUTES_T*, CLIENT_ID_T*);
using NtSetInformationProcessFn = NTSTATUS_T(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
using NtQuerySystemInformationFn = NTSTATUS_T(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
using NtQueryInformationThreadFn = NTSTATUS_T(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtSetInformationThreadFn = NTSTATUS_T(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
using NtGetNextThreadFn = NTSTATUS_T(NTAPI*)(HANDLE, HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);
using NtCloseFn = NTSTATUS_T(NTAPI*)(HANDLE);
using NtDelayExecutionFn = NTSTATUS_T(NTAPI*)(BOOLEAN, PLARGE_INTEGER);

struct THREAD_BASIC_INFORMATION_T {
    NTSTATUS_T ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID_T ClientId;
    ULONG_PTR AffinityMask;
    KPRIORITY Priority;
    LONG BasePriority;
};

constexpr ULONG ThreadBasicInformation = 0;
constexpr ULONG ThreadPriorityBoost = 14;
constexpr ULONG ProcessPriorityBoost = 22;

struct ScanStats {
    uint32_t seenPriority16 = 0;
    uint32_t fixedPriority16 = 0;
    uint32_t cachedSkipped = 0;
    uint32_t openFailures = 0;
    uint32_t fixFailures = 0;
};

struct ThreadCacheEntry {
    DWORD processId = 0;
    DWORD threadId = 0;
    uint32_t lastScan = 0;
    uint8_t state = kCacheEmpty;
};

struct ThreadCache {
    ThreadCacheEntry entries[kThreadCacheSize]{};
};

struct ProcessCacheEntry {
    DWORD processId = 0;
    HANDLE process = nullptr;
    uint32_t lastSeenScan = 0;
};

struct ProcessCache {
    ProcessCacheEntry entries[kProcessCacheSize]{};
};


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

static uint32_t HashThreadKey(DWORD processId, DWORD threadId) noexcept {
    uint32_t x = processId * 16777619u ^ threadId;
    x ^= x >> 16;
    x *= 0x7feb352du;
    x ^= x >> 15;
    return x;
}

static bool ShouldSkipCachedThread(ThreadCache& cache, DWORD processId, DWORD threadId, uint32_t scanId) noexcept {
    const size_t start = HashThreadKey(processId, threadId) & (kThreadCacheSize - 1);
    for (size_t probe = 0; probe < 4; ++probe) {
        ThreadCacheEntry& entry = cache.entries[(start + probe) & (kThreadCacheSize - 1)];
        if (entry.state == kCacheEmpty) {
            return false;
        }

        if (entry.processId == processId && entry.threadId == threadId) {
            return scanId - entry.lastScan < kRetryCooldownScans;
        }
    }

    return false;
}

static void RememberThread(ThreadCache& cache, DWORD processId, DWORD threadId, uint32_t scanId, uint8_t state) noexcept {
    const size_t start = HashThreadKey(processId, threadId) & (kThreadCacheSize - 1);
    size_t slot = start;
    uint32_t oldestAge = 0;

    for (size_t probe = 0; probe < 4; ++probe) {
        ThreadCacheEntry& entry = cache.entries[(start + probe) & (kThreadCacheSize - 1)];
        if (entry.state == kCacheEmpty || (entry.processId == processId && entry.threadId == threadId)) {
            slot = (start + probe) & (kThreadCacheSize - 1);
            break;
        }

        const uint32_t age = scanId - entry.lastScan;
        if (age >= oldestAge) {
            oldestAge = age;
            slot = (start + probe) & (kThreadCacheSize - 1);
        }
    }

    cache.entries[slot] = ThreadCacheEntry{processId, threadId, scanId, state};
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

static bool QueryProcessSnapshot(NtQuerySystemInformationFn query,
                                 RtlAllocateHeapFn allocateHeap,
                                 RtlFreeHeapFn freeHeap,
                                 PVOID heap,
                                 PVOID& buffer,
                                 ULONG& capacity) noexcept {
    ULONG required = 0;
    NTSTATUS_T status = query(SystemProcessInformation, buffer, capacity, &required);
    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        const ULONG nextCapacity = required > capacity ? required + (64U * 1024U) : capacity * 2U;
        PVOID nextBuffer = allocateHeap(heap, 0, nextCapacity);
        if (nextBuffer == nullptr) {
            return false;
        }

        status = query(SystemProcessInformation, nextBuffer, nextCapacity, &required);
        if (status < 0) {
            freeHeap(heap, 0, nextBuffer);
            return false;
        }

        freeHeap(heap, 0, buffer);
        buffer = nextBuffer;
        capacity = nextCapacity;
        return true;
    }

    return status >= 0;
}

static bool FixPriority16ThreadHandle(NtSetInformationThreadFn setThread, HANDLE thread, DWORD& error) noexcept {
    error = ERROR_SUCCESS;

    ULONG disableBoost = TRUE;
    const NTSTATUS_T status = setThread(thread, ThreadPriorityBoost, &disableBoost, sizeof(disableBoost));
    if (status < 0) {
        error = ERROR_ACCESS_DENIED;
        return false;
    }

    return true;
}

static bool FixPriority16Thread(NtOpenThreadFn openThread,
                                NtSetInformationThreadFn setThread,
                                NtCloseFn closeHandle,
                                DWORD processId,
                                DWORD threadId,
                                DWORD& error) noexcept {
    error = ERROR_SUCCESS;
    HANDLE thread = nullptr;
    OBJECT_ATTRIBUTES_T attributes{sizeof(attributes), nullptr, nullptr, 0, nullptr, nullptr};
    CLIENT_ID_T clientId{reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(processId)),
                         reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(threadId))};
    const NTSTATUS_T status = openThread(&thread, kThreadFixAccess, &attributes, &clientId);
    if (status < 0 || thread == nullptr) {
        error = ERROR_ACCESS_DENIED;
        return false;
    }

    const bool ok = FixPriority16ThreadHandle(setThread, thread, error);
    closeHandle(thread);
    return ok;
}

static HANDLE OpenProcessNative(NtOpenProcessFn openProcess, DWORD processId, ACCESS_MASK access) noexcept {
    HANDLE process = nullptr;
    OBJECT_ATTRIBUTES_T attributes{sizeof(attributes), nullptr, nullptr, 0, nullptr, nullptr};
    CLIENT_ID_T clientId{reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(processId)), nullptr};
    if (openProcess(&process, access, &attributes, &clientId) < 0) {
        return nullptr;
    }

    return process;
}

static HANDLE OpenCachedProcess(NtOpenProcessFn openProcess, DWORD processId) noexcept {
    return OpenProcessNative(openProcess, processId, kProcessEnumAccess);
}

static void DisableProcessPriorityBoost(NtOpenProcessFn openProcess,
                                        NtSetInformationProcessFn setProcess,
                                        NtCloseFn closeHandle,
                                        DWORD processId) noexcept {
    HANDLE process = OpenProcessNative(openProcess, processId, kProcessBoostAccess);
    if (process == nullptr) {
        return;
    }

    ULONG disableBoost = TRUE;
    setProcess(process, ProcessPriorityBoost, &disableBoost, sizeof(disableBoost));
    closeHandle(process);
}

static void RememberProcess(ProcessCache& cache,
                            NtOpenProcessFn openProcess,
                            NtSetInformationProcessFn setProcess,
                            NtCloseFn closeHandle,
                            DWORD processId,
                            uint32_t scanId) noexcept {
    if (processId == 0) {
        return;
    }

    size_t slot = kProcessCacheSize;
    uint32_t oldestAge = 0;
    for (size_t i = 0; i < kProcessCacheSize; ++i) {
        ProcessCacheEntry& entry = cache.entries[i];
        if (entry.processId == processId) {
            entry.lastSeenScan = scanId;
            return;
        }

        if (entry.processId == 0) {
            slot = i;
            break;
        }

        const uint32_t age = scanId - entry.lastSeenScan;
        if (age >= oldestAge) {
            oldestAge = age;
            slot = i;
        }
    }

    if (slot == kProcessCacheSize) {
        return;
    }

    if (cache.entries[slot].process != nullptr) {
        closeHandle(cache.entries[slot].process);
    }

    DisableProcessPriorityBoost(openProcess, setProcess, closeHandle, processId);
    cache.entries[slot] = ProcessCacheEntry{processId, OpenCachedProcess(openProcess, processId), scanId};
}

static ScanStats ScanAndFixPriority16(NtQuerySystemInformationFn query,
                                       RtlAllocateHeapFn allocateHeap,
                                       RtlFreeHeapFn freeHeap,
                                       PVOID heap,
                                       NtOpenThreadFn openThread,
                                       NtSetInformationThreadFn setThread,
                                       NtOpenProcessFn openProcess,
                                       NtSetInformationProcessFn setProcess,
                                       NtCloseFn closeHandle,
                                       PVOID& buffer,
                                       ULONG& capacity,
                                       ThreadCache& threadCache,
                                       ProcessCache& processCache,
                                       uint32_t scanId) noexcept {
    ScanStats stats{};
    if (!QueryProcessSnapshot(query, allocateHeap, freeHeap, heap, buffer, capacity)) {
        return stats;
    }

    const DWORD currentThreadId = GetCurrentThreadId();
    auto* process = reinterpret_cast<SYSTEM_PROCESS_INFORMATION_T*>(buffer);

    for (;;) {
        const ULONG threadCount = process->NumberOfThreads;
        const SYSTEM_THREAD_INFORMATION_T* thread = process->Threads;

        for (ULONG i = 0; i < threadCount; ++i, ++thread) {
            if (thread->Priority != kTargetPriority && thread->BasePriority != kTargetPriority) {
                continue;
            }

            const DWORD processId = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(thread->ClientId.UniqueProcess));
            const DWORD threadId = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(thread->ClientId.UniqueThread));
            if (threadId == 0 || threadId == currentThreadId) {
                continue;
            }

            ++stats.seenPriority16;
            RememberProcess(processCache, openProcess, setProcess, closeHandle, processId, scanId);
            if (ShouldSkipCachedThread(threadCache, processId, threadId, scanId)) {
                ++stats.cachedSkipped;
                continue;
            }

            DWORD error = ERROR_SUCCESS;
            if (FixPriority16Thread(openThread, setThread, closeHandle, processId, threadId, error)) {
                ++stats.fixedPriority16;
                RememberThread(threadCache, processId, threadId, scanId, kCacheFixed);
            } else if (error == ERROR_ACCESS_DENIED || error == ERROR_INVALID_PARAMETER) {
                ++stats.openFailures;
                RememberThread(threadCache, processId, threadId, scanId, kCacheDenied);
            } else {
                ++stats.fixFailures;
                RememberThread(threadCache, processId, threadId, scanId, kCacheFailed);
            }
        }

        if (process->NextEntryOffset == 0) {
            break;
        }

        process = reinterpret_cast<SYSTEM_PROCESS_INFORMATION_T*>(
            reinterpret_cast<BYTE*>(process) + process->NextEntryOffset);
    }

    return stats;
}

static ScanStats ScanCachedPriority16Processes(NtGetNextThreadFn getNextThread,
                                             NtQueryInformationThreadFn queryThread,
                                             NtSetInformationThreadFn setThread,
                                             NtOpenProcessFn openProcess,
                                             NtSetInformationProcessFn setProcess,
                                             NtCloseFn closeHandle,
                                             ThreadCache& threadCache,
                                             ProcessCache& processCache,
                                             uint32_t scanId) noexcept {
    ScanStats stats{};
    const DWORD currentThreadId = GetCurrentThreadId();

    for (ProcessCacheEntry& processEntry : processCache.entries) {
        if (processEntry.processId == 0) {
            continue;
        }

        if (processEntry.process == nullptr) {
            processEntry.process = OpenCachedProcess(openProcess, processEntry.processId);
            if (processEntry.process == nullptr) {
                continue;
            }

            DisableProcessPriorityBoost(openProcess, setProcess, closeHandle, processEntry.processId);
        }

        HANDLE previousThread = nullptr;
        for (;;) {
            HANDLE thread = nullptr;
            const NTSTATUS_T status = getNextThread(processEntry.process,
                                                    previousThread,
                                                    kThreadQueryFixAccess,
                                                    0,
                                                    0,
                                                    &thread);
            if (previousThread != nullptr) {
                closeHandle(previousThread);
            }

            if (status < 0 || thread == nullptr) {
                break;
            }

            previousThread = thread;
            THREAD_BASIC_INFORMATION_T basic{};
            if (queryThread(thread, ThreadBasicInformation, &basic, sizeof(basic), nullptr) < 0) {
                continue;
            }

            const DWORD processId = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(basic.ClientId.UniqueProcess));
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

            DWORD error = ERROR_SUCCESS;
            if (FixPriority16ThreadHandle(setThread, thread, error)) {
                ++stats.fixedPriority16;
                RememberThread(threadCache, processId, threadId, scanId, kCacheFixed);
            } else if (error == ERROR_ACCESS_DENIED || error == ERROR_INVALID_PARAMETER) {
                ++stats.openFailures;
                RememberThread(threadCache, processId, threadId, scanId, kCacheDenied);
            } else {
                ++stats.fixFailures;
                RememberThread(threadCache, processId, threadId, scanId, kCacheFailed);
            }
        }
    }

    return stats;
}

int wmain(int argc, wchar_t** argv) {
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) {
        std::fputs("ntdll.dll is unavailable\n", stderr);
        return 1;
    }

    const auto allocateHeap = reinterpret_cast<RtlAllocateHeapFn>(GetProcAddress(ntdll, "RtlAllocateHeap"));
    const auto freeHeap = reinterpret_cast<RtlFreeHeapFn>(GetProcAddress(ntdll, "RtlFreeHeap"));
    const auto createHeap = reinterpret_cast<RtlCreateHeapFn>(GetProcAddress(ntdll, "RtlCreateHeap"));
    const auto destroyHeap = reinterpret_cast<RtlDestroyHeapFn>(GetProcAddress(ntdll, "RtlDestroyHeap"));
    const auto openProcessToken = reinterpret_cast<NtOpenProcessTokenFn>(
        GetProcAddress(ntdll, "NtOpenProcessToken"));
    const auto queryToken = reinterpret_cast<NtQueryInformationTokenFn>(
        GetProcAddress(ntdll, "NtQueryInformationToken"));
    const auto adjustToken = reinterpret_cast<NtAdjustPrivilegesTokenFn>(
        GetProcAddress(ntdll, "NtAdjustPrivilegesToken"));
    const auto openProcess = reinterpret_cast<NtOpenProcessFn>(GetProcAddress(ntdll, "NtOpenProcess"));
    const auto setProcess = reinterpret_cast<NtSetInformationProcessFn>(
        GetProcAddress(ntdll, "NtSetInformationProcess"));
    const auto closeHandle = reinterpret_cast<NtCloseFn>(GetProcAddress(ntdll, "NtClose"));
    const auto delayExecution = reinterpret_cast<NtDelayExecutionFn>(GetProcAddress(ntdll, "NtDelayExecution"));
    if (allocateHeap == nullptr || freeHeap == nullptr || createHeap == nullptr || destroyHeap == nullptr ||
        openProcessToken == nullptr ||
        queryToken == nullptr || adjustToken == nullptr || openProcess == nullptr || setProcess == nullptr ||
        closeHandle == nullptr || delayExecution == nullptr) {
        std::fputs("required ntdll memory APIs are unavailable\n", stderr);
        return 1;
    }

    PVOID heap = createHeap(0, nullptr, 0, 0, nullptr, nullptr);
    if (heap == nullptr) {
        std::fputs("RtlCreateHeap failed\n", stderr);
        return 1;
    }

    EnableAllTokenPrivileges(allocateHeap, freeHeap, heap, openProcessToken, queryToken, adjustToken, closeHandle);

    const auto openThread = reinterpret_cast<NtOpenThreadFn>(GetProcAddress(ntdll, "NtOpenThread"));
    const auto query = reinterpret_cast<NtQuerySystemInformationFn>(
        GetProcAddress(ntdll, "NtQuerySystemInformation"));
    const auto queryThread = reinterpret_cast<NtQueryInformationThreadFn>(
        GetProcAddress(ntdll, "NtQueryInformationThread"));
    const auto setThread = reinterpret_cast<NtSetInformationThreadFn>(
        GetProcAddress(ntdll, "NtSetInformationThread"));
    const auto getNextThread = reinterpret_cast<NtGetNextThreadFn>(
        GetProcAddress(ntdll, "NtGetNextThread"));
    if (openThread == nullptr || query == nullptr || queryThread == nullptr || setThread == nullptr || getNextThread == nullptr) {
        std::fputs("required ntdll thread query APIs are unavailable\n", stderr);
        return 1;
    }

    ULONG capacity = 1024U * 1024U;
    PVOID buffer = allocateHeap(heap, 0, capacity);
    if (buffer == nullptr) {
        std::fputs("failed to allocate snapshot buffer\n", stderr);
        destroyHeap(heap);
        return 1;
    }
    ThreadCache threadCache{};
    ProcessCache processCache{};
    uint32_t scanId = 1;
    const uint32_t intervalMs = ReadIntervalMs(argc, argv);

    if (intervalMs != 0) {
        std::printf("monitoring priority 16 threads every %u ms; global refresh every %u scans; pass 0 for one scan\n",
                    intervalMs, kGlobalRefreshScans);
    }

    do {
        const bool globalRefresh = intervalMs == 0 || scanId == 1 || (scanId % kGlobalRefreshScans) == 0;
        const ScanStats stats = globalRefresh
            ? ScanAndFixPriority16(query, allocateHeap, freeHeap, heap, openThread, setThread, openProcess, setProcess, closeHandle, buffer, capacity, threadCache, processCache, scanId++)
            : ScanCachedPriority16Processes(getNextThread, queryThread, setThread, openProcess, setProcess, closeHandle, threadCache, processCache, scanId++);
        if (intervalMs == 0 || stats.fixedPriority16 != 0 || stats.openFailures != 0 || stats.fixFailures != 0) {
            std::printf("priority16_seen=%u priority16_fixed=%u cached_skipped=%u open_failures=%u fix_failures=%u\n",
                        stats.seenPriority16,
                        stats.fixedPriority16,
                        stats.cachedSkipped,
                        stats.openFailures,
                        stats.fixFailures);
        }

        if (intervalMs == 0) {
            break;
        }

        LARGE_INTEGER delay{};
        delay.QuadPart = -static_cast<LONGLONG>(intervalMs) * 10000LL;
        delayExecution(FALSE, &delay);
    } while (true);

    freeHeap(heap, 0, buffer);
    destroyHeap(heap);
    return 0;
}
