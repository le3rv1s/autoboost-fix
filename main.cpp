#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>

using NTSTATUS = LONG;
using KPRIORITY = LONG;

constexpr NTSTATUS STATUS_INFO_LENGTH_MISMATCH = static_cast<NTSTATUS>(0xC0000004L);
constexpr ULONG SystemProcessInformation = 5;
constexpr KPRIORITY kTargetPriority = 16;

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
    BYTE Reserved1[48];
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved5[4];
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved6[6];
    SYSTEM_THREAD_INFORMATION_T Threads[1];
};

using NtQuerySystemInformationFn = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);

struct ScanStats {
    uint32_t seenPriority16 = 0;
    uint32_t fixedPriority16 = 0;
    uint32_t openFailures = 0;
    uint32_t fixFailures = 0;
};

static uint32_t ReadIntervalMs(int argc, wchar_t** argv) noexcept {
    if (argc < 2) {
        return 0;
    }

    wchar_t* end = nullptr;
    const unsigned long value = wcstoul(argv[1], &end, 10);
    if (end == argv[1] || *end != L'\0' || value > 60000UL) {
        return 0;
    }

    return static_cast<uint32_t>(value);
}

static bool QueryProcessSnapshot(NtQuerySystemInformationFn query,
                                 std::unique_ptr<BYTE[]>& buffer,
                                 ULONG& capacity) noexcept {
    ULONG required = 0;
    NTSTATUS status = query(SystemProcessInformation, buffer.get(), capacity, &required);
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

static bool FixPriority16Thread(DWORD threadId) noexcept {
    HANDLE thread = OpenThread(THREAD_SET_INFORMATION, FALSE, threadId);
    if (thread == nullptr) {
        return false;
    }

    const BOOL ok = SetThreadPriorityBoost(thread, TRUE);
    CloseHandle(thread);
    return ok != FALSE;
}

static ScanStats ScanAndFixPriority16(NtQuerySystemInformationFn query,
                                       std::unique_ptr<BYTE[]>& buffer,
                                       ULONG& capacity) noexcept {
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
            if (thread->Priority != kTargetPriority) {
                continue;
            }

            const DWORD threadId = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(thread->ClientId.UniqueThread));
            if (threadId == 0 || threadId == currentThreadId) {
                continue;
            }

            ++stats.seenPriority16;
            if (FixPriority16Thread(threadId)) {
                ++stats.fixedPriority16;
            } else {
                const DWORD error = GetLastError();
                if (error == ERROR_ACCESS_DENIED || error == ERROR_INVALID_PARAMETER) {
                    ++stats.openFailures;
                } else {
                    ++stats.fixFailures;
                }
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
    const uint32_t intervalMs = ReadIntervalMs(argc, argv);

    do {
        const ScanStats stats = ScanAndFixPriority16(query, buffer, capacity);
        std::printf("priority16_seen=%u priority16_fixed=%u open_failures=%u fix_failures=%u\n",
                    stats.seenPriority16,
                    stats.fixedPriority16,
                    stats.openFailures,
                    stats.fixFailures);

        if (intervalMs == 0) {
            break;
        }

        Sleep(intervalMs);
    } while (true);

    return 0;
}
