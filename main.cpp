#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>

#ifndef THREAD_QUERY_LIMITED_INFORMATION
#define THREAD_QUERY_LIMITED_INFORMATION 0x0800
#endif

#ifndef THREAD_SET_LIMITED_INFORMATION
#define THREAD_SET_LIMITED_INFORMATION 0x0400
#endif

using NTSTATUS_T = LONG;
using KPRIORITY = LONG;

constexpr KPRIORITY kTargetPriority = 16;
constexpr uint32_t kDefaultIntervalMs = 1000;
constexpr uint32_t kRetryCooldownScans = 256;
constexpr size_t kThreadCacheSize = 1024;
constexpr uint8_t kCacheEmpty = 0;
constexpr uint8_t kCacheFixed = 1;
constexpr uint8_t kCacheDenied = 2;
constexpr uint8_t kCacheFailed = 3;
constexpr ACCESS_MASK kThreadFixAccess = THREAD_QUERY_LIMITED_INFORMATION | THREAD_SET_LIMITED_INFORMATION;

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

struct THREAD_BASIC_INFORMATION_T {
    NTSTATUS_T ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID_T ClientId;
    ULONG_PTR AffinityMask;
    KPRIORITY Priority;
    LONG BasePriority;
};

using NtOpenThreadFn = NTSTATUS_T(NTAPI*)(PHANDLE, ACCESS_MASK, OBJECT_ATTRIBUTES_T*, CLIENT_ID_T*);
using NtQueryInformationThreadFn = NTSTATUS_T(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtSetInformationThreadFn = NTSTATUS_T(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
using NtCloseFn = NTSTATUS_T(NTAPI*)(HANDLE);

constexpr ULONG ThreadBasicInformation = 0;
constexpr ULONG ThreadPriorityBoost = 14;

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

static void EnableAllTokenPrivileges() noexcept {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return;
    }

    DWORD required = 0;
    GetTokenInformation(token, TokenPrivileges, nullptr, 0, &required);
    if (required == 0) {
        CloseHandle(token);
        return;
    }

    auto privileges = std::make_unique<BYTE[]>(required);
    auto* tokenPrivileges = reinterpret_cast<TOKEN_PRIVILEGES*>(privileges.get());
    if (!GetTokenInformation(token, TokenPrivileges, tokenPrivileges, required, &required)) {
        CloseHandle(token);
        return;
    }

    for (DWORD i = 0; i < tokenPrivileges->PrivilegeCount; ++i) {
        tokenPrivileges->Privileges[i].Attributes |= SE_PRIVILEGE_ENABLED;
    }

    AdjustTokenPrivileges(token, FALSE, tokenPrivileges, required, nullptr, nullptr);
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

static bool FixPriorityBoost(NtSetInformationThreadFn setThread, HANDLE thread, DWORD& error) noexcept {
    error = ERROR_SUCCESS;

    ULONG disableBoost = TRUE;
    if (setThread(thread, ThreadPriorityBoost, &disableBoost, sizeof(disableBoost)) >= 0) {
        return true;
    }

    const BOOL ok = SetThreadPriorityBoost(thread, TRUE);
    if (ok == FALSE) {
        error = GetLastError();
    }

    return ok != FALSE;
}

static bool OpenThreadForFix(NtOpenThreadFn openThread, DWORD processId, DWORD threadId, HANDLE& thread) noexcept {
    thread = nullptr;
    CLIENT_ID_T clientId{reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(processId)),
                         reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(threadId))};
    OBJECT_ATTRIBUTES_T attributes{sizeof(attributes), nullptr, nullptr, 0, nullptr, nullptr};
    return openThread(&thread, kThreadFixAccess, &attributes, &clientId) >= 0 && thread != nullptr;
}

static ScanStats ScanToolhelpThreads(NtOpenThreadFn openThread,
                                     NtQueryInformationThreadFn queryThread,
                                     NtSetInformationThreadFn setThread,
                                     NtCloseFn closeHandle,
                                     ThreadCache& threadCache,
                                     uint32_t scanId) noexcept {
    ScanStats stats{};
    const DWORD currentThreadId = GetCurrentThreadId();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return stats;
    }

    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    if (!Thread32First(snapshot, &entry)) {
        CloseHandle(snapshot);
        return stats;
    }

    do {
        const DWORD processId = entry.th32OwnerProcessID;
        const DWORD threadId = entry.th32ThreadID;
        if (threadId == 0 || threadId == currentThreadId) {
            continue;
        }

        if (ShouldSkipCachedThread(threadCache, processId, threadId, scanId)) {
            ++stats.cachedSkipped;
            continue;
        }

        HANDLE thread = nullptr;
        if (!OpenThreadForFix(openThread, processId, threadId, thread)) {
            ++stats.openFailures;
            RememberThread(threadCache, processId, threadId, scanId, kCacheDenied);
            continue;
        }

        THREAD_BASIC_INFORMATION_T basic{};
        if (queryThread(thread, ThreadBasicInformation, &basic, sizeof(basic), nullptr) < 0) {
            ++stats.fixFailures;
            RememberThread(threadCache, processId, threadId, scanId, kCacheFailed);
            closeHandle(thread);
            continue;
        }

        if (basic.Priority != kTargetPriority) {
            closeHandle(thread);
            continue;
        }

        ++stats.seenPriority16;
        DWORD error = ERROR_SUCCESS;
        if (FixPriorityBoost(setThread, thread, error)) {
            ++stats.fixedPriority16;
            RememberThread(threadCache, processId, threadId, scanId, kCacheFixed);
        } else if (error == ERROR_ACCESS_DENIED || error == ERROR_INVALID_PARAMETER) {
            ++stats.openFailures;
            RememberThread(threadCache, processId, threadId, scanId, kCacheDenied);
        } else {
            ++stats.fixFailures;
            RememberThread(threadCache, processId, threadId, scanId, kCacheFailed);
        }

        closeHandle(thread);
    } while (Thread32Next(snapshot, &entry));

    CloseHandle(snapshot);
    return stats;
}

int wmain(int argc, wchar_t** argv) {
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) {
        std::fputs("ntdll.dll is unavailable\n", stderr);
        return 1;
    }

    EnableAllTokenPrivileges();

    const auto openThread = reinterpret_cast<NtOpenThreadFn>(GetProcAddress(ntdll, "NtOpenThread"));
    const auto queryThread = reinterpret_cast<NtQueryInformationThreadFn>(
        GetProcAddress(ntdll, "NtQueryInformationThread"));
    const auto setThread = reinterpret_cast<NtSetInformationThreadFn>(
        GetProcAddress(ntdll, "NtSetInformationThread"));
    const auto closeHandle = reinterpret_cast<NtCloseFn>(GetProcAddress(ntdll, "NtClose"));
    if (openThread == nullptr || queryThread == nullptr || setThread == nullptr || closeHandle == nullptr) {
        std::fputs("required ntdll thread APIs are unavailable\n", stderr);
        return 1;
    }

    ThreadCache threadCache{};
    uint32_t scanId = 1;
    const uint32_t intervalMs = ReadIntervalMs(argc, argv);

    if (intervalMs != 0) {
        std::printf("monitoring current priority 16 threads every %u ms via NtOpenThread/NtQueryInformationThread\n",
                    intervalMs);
    }

    do {
        const ScanStats stats = ScanToolhelpThreads(openThread, queryThread, setThread, closeHandle, threadCache, scanId++);
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
