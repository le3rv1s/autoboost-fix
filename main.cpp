#define WIN32_LEAN_AND_MEAN
#include <windows.h>

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
constexpr uint32_t kDefaultIntervalMs = 30000;
constexpr uint32_t kRetryCooldownScans = 256;
constexpr size_t kThreadCacheSize = 512;
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

static bool FixPriority16Thread(DWORD threadId, DWORD& error) noexcept {
    error = ERROR_SUCCESS;
    HANDLE thread = OpenThread(THREAD_SET_INFORMATION, FALSE, threadId);
    if (thread == nullptr) {
        error = GetLastError();
        return false;
    }

    const BOOL ok = SetThreadPriorityBoost(thread, TRUE);
    if (ok == FALSE) {
        error = GetLastError();
    }

    CloseHandle(thread);
    return ok != FALSE;
}

static ScanStats ScanAndFixPriority16(NtQuerySystemInformationFn query,
                                       std::unique_ptr<BYTE[]>& buffer,
                                       ULONG& capacity,
                                       ThreadCache& threadCache,
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

int wmain(int argc, wchar_t** argv) {
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) {
        std::fputs("ntdll.dll is unavailable\n", stderr);
        return 1;
    }

    const auto query = reinterpret_cast<NtQuerySystemInformationFn>(
        GetProcAddress(ntdll, "NtQuerySystemInformation"));
    if (query == nullptr) {
        std::fputs("NtQuerySystemInformation is unavailable\n", stderr);
        return 1;
    }

    ULONG capacity = 1024U * 1024U;
    auto buffer = std::make_unique<BYTE[]>(capacity);
    ThreadCache threadCache{};
    uint32_t scanId = 1;
    const uint32_t intervalMs = ReadIntervalMs(argc, argv);

    if (intervalMs != 0) {
        std::printf("monitoring priority 16 threads every %u ms; cached retries every %u scans; pass 0 for one scan\n",
                    intervalMs, kRetryCooldownScans);
    }

    do {
        const ScanStats stats = ScanAndFixPriority16(query, buffer, capacity, threadCache, scanId++);
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
