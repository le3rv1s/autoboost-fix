#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>

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
constexpr uint32_t kGlobalRefreshScans = 30;
constexpr uint32_t kRetryCooldownScans = 256;
constexpr size_t kThreadCacheSize = 512;
constexpr size_t kProcessCacheSize = 64;
constexpr uint8_t kCacheEmpty = 0;
constexpr uint8_t kCacheFixed = 1;
constexpr uint8_t kCacheDenied = 2;
constexpr uint8_t kCacheFailed = 3;

struct CLIENT_ID_T {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
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

using NtQuerySystemInformationFn = NTSTATUS_T(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
using NtQueryInformationThreadFn = NTSTATUS_T(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtGetNextThreadFn = NTSTATUS_T(NTAPI*)(HANDLE, HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);

struct THREAD_BASIC_INFORMATION_T {
    NTSTATUS_T ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID_T ClientId;
    ULONG_PTR AffinityMask;
    KPRIORITY Priority;
    LONG BasePriority;
};

constexpr ULONG ThreadBasicInformation = 0;

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


static void EnableDebugPrivilege() noexcept {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return;
    }

    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &privileges.Privileges[0].Luid)) {
        AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr);
    }

    CloseHandle(token);
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
                                 std::unique_ptr<BYTE[]>& buffer,
                                 ULONG& capacity) noexcept {
    ULONG required = 0;
    NTSTATUS_T status = query(SystemProcessInformation, buffer.get(), capacity, &required);
    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        const ULONG nextCapacity = required > capacity ? required + (64U * 1024U) : capacity * 2U;
        auto nextBuffer = std::make_unique<BYTE[]>(nextCapacity);
        status = query(SystemProcessInformation, nextBuffer.get(), nextCapacity, &required);
        if (status < 0) {
            return false;
        }

        buffer.swap(nextBuffer);
        capacity = nextCapacity;
        return true;
    }

    return status >= 0;
}

static bool FixPriority16ThreadHandle(HANDLE thread, DWORD& error) noexcept {
    error = ERROR_SUCCESS;
    const BOOL ok = SetThreadPriorityBoost(thread, TRUE);
    if (ok == FALSE) {
        error = GetLastError();
    }

    return ok != FALSE;
}

static bool FixPriority16Thread(DWORD threadId, DWORD& error) noexcept {
    error = ERROR_SUCCESS;
    HANDLE thread = OpenThread(THREAD_SET_INFORMATION, FALSE, threadId);
    if (thread == nullptr) {
        error = GetLastError();
        return false;
    }

    const bool ok = FixPriority16ThreadHandle(thread, error);
    CloseHandle(thread);
    return ok;
}

static HANDLE OpenCachedProcess(DWORD processId) noexcept {
    return OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION, FALSE, processId);
}

static void DisableProcessPriorityBoost(HANDLE process) noexcept {
    SetProcessPriorityBoost(process, TRUE);
}

static void RememberProcess(ProcessCache& cache, DWORD processId, uint32_t scanId) noexcept {
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
        CloseHandle(cache.entries[slot].process);
    }

    HANDLE process = OpenCachedProcess(processId);
    if (process != nullptr) {
        DisableProcessPriorityBoost(process);
    }

    cache.entries[slot] = ProcessCacheEntry{processId, process, scanId};
}

static ScanStats ScanAndFixPriority16(NtQuerySystemInformationFn query,
                                       std::unique_ptr<BYTE[]>& buffer,
                                       ULONG& capacity,
                                       ThreadCache& threadCache,
                                       ProcessCache& processCache,
                                       uint32_t scanId) noexcept {
    ScanStats stats{};
    if (!QueryProcessSnapshot(query, buffer, capacity)) {
        return stats;
    }

    const DWORD currentThreadId = GetCurrentThreadId();
    auto* process = reinterpret_cast<SYSTEM_PROCESS_INFORMATION_T*>(buffer.get());

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
            RememberProcess(processCache, processId, scanId);
            if (ShouldSkipCachedThread(threadCache, processId, threadId, scanId)) {
                ++stats.cachedSkipped;
                continue;
            }

            DWORD error = ERROR_SUCCESS;
            if (FixPriority16Thread(threadId, error)) {
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
            processEntry.process = OpenCachedProcess(processEntry.processId);
            if (processEntry.process == nullptr) {
                continue;
            }

            DisableProcessPriorityBoost(processEntry.process);
        }

        HANDLE previousThread = nullptr;
        for (;;) {
            HANDLE thread = nullptr;
            const NTSTATUS_T status = getNextThread(processEntry.process,
                                                    previousThread,
                                                    THREAD_QUERY_LIMITED_INFORMATION | THREAD_SET_INFORMATION,
                                                    0,
                                                    0,
                                                    &thread);
            if (previousThread != nullptr) {
                CloseHandle(previousThread);
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
            if (FixPriority16ThreadHandle(thread, error)) {
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

    EnableDebugPrivilege();

    const auto query = reinterpret_cast<NtQuerySystemInformationFn>(
        GetProcAddress(ntdll, "NtQuerySystemInformation"));
    const auto queryThread = reinterpret_cast<NtQueryInformationThreadFn>(
        GetProcAddress(ntdll, "NtQueryInformationThread"));
    const auto getNextThread = reinterpret_cast<NtGetNextThreadFn>(
        GetProcAddress(ntdll, "NtGetNextThread"));
    if (query == nullptr || queryThread == nullptr || getNextThread == nullptr) {
        std::fputs("required ntdll thread query APIs are unavailable\n", stderr);
        return 1;
    }

    ULONG capacity = 1024U * 1024U;
    auto buffer = std::make_unique<BYTE[]>(capacity);
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
            ? ScanAndFixPriority16(query, buffer, capacity, threadCache, processCache, scanId++)
            : ScanCachedPriority16Processes(getNextThread, queryThread, threadCache, processCache, scanId++);
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

        Sleep(intervalMs);
    } while (true);

    return 0;
}
