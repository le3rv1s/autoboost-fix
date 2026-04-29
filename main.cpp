#include <windows.h>
#include <winternl.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cwchar>
#include <memory>
#include <string>
#include <vector>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

constexpr ULONG kThreadInfoPriority = 2;
constexpr ULONG kThreadInfoBasePriority = 3;
constexpr ULONG kThreadInfoPriorityBoost = 14;

using NtQuerySystemInformation_t = NTSTATUS(NTAPI*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
using NtOpenThread_t = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, CLIENT_ID*);
using NtSetInformationThread_t = NTSTATUS(NTAPI*)(HANDLE, THREADINFOCLASS, PVOID, ULONG);

struct UNDOC_SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
};

struct UNDOC_SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2[2];
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4[2];
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved5[6];
    UNDOC_SYSTEM_THREAD_INFORMATION Threads[1];
};

struct NtApi {
    NtQuerySystemInformation_t querySystemInformation = nullptr;
    NtOpenThread_t openThread = nullptr;
    NtSetInformationThread_t setInformationThread = nullptr;
};

struct ThreadFixStats {
    ULONG visited = 0;
    ULONG candidates = 0;
    ULONG fixed = 0;
    ULONG ntSetPriorityOk = 0;
    ULONG ntSetBaseOk = 0;
    ULONG win32FallbackOk = 0;
    ULONG openFailed = 0;
    ULONG setFailed = 0;
};

static DWORD ParsePidOrDefault(int argc, wchar_t** argv, DWORD defaultPid) {
    if (argc < 2) {
        return defaultPid;
    }

    const wchar_t* s = argv[1];
    if (!s || !*s) {
        return defaultPid;
    }

    wchar_t* end = nullptr;
    const unsigned long long value = _wcstoui64(s, &end, 10);
    if (!end || *end != L'\0' || value == 0 || value > 0xFFFFFFFFull) {
        return 0;
    }

    return static_cast<DWORD>(value);
}

static LONG ClampLong(LONG v, LONG lo, LONG hi) {
    return (v < lo) ? lo : ((v > hi) ? hi : v);
}

static int ClampWin32RelativePriorityFromBase(KPRIORITY processBase, KPRIORITY threadBase) {
    LONG relative = static_cast<LONG>(threadBase) - static_cast<LONG>(processBase);
    relative = ClampLong(relative, THREAD_PRIORITY_LOWEST, THREAD_PRIORITY_HIGHEST);
    return static_cast<int>(relative);
}

static bool IsAutoboostStuckRange(KPRIORITY dynamicPriority) {
    return dynamicPriority >= 16 && dynamicPriority <= 31;
}

static LONG ComputeRelativeBaseForNt(KPRIORITY processBase, KPRIORITY threadBase) {
    LONG relative = static_cast<LONG>(threadBase) - static_cast<LONG>(processBase);
    return ClampLong(relative, -2, 2);
}

static std::wstring ProcessNameOrUnknown(const UNICODE_STRING& name) {
    if (!name.Buffer || name.Length == 0) {
        return L"<unknown>";
    }

    const size_t count = static_cast<size_t>(name.Length / sizeof(wchar_t));
    return std::wstring(name.Buffer, name.Buffer + count);
}

static bool LoadNtApi(NtApi& nt) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        return false;
    }

    nt.querySystemInformation = reinterpret_cast<NtQuerySystemInformation_t>(
        GetProcAddress(ntdll, "NtQuerySystemInformation"));
    nt.openThread = reinterpret_cast<NtOpenThread_t>(GetProcAddress(ntdll, "NtOpenThread"));
    nt.setInformationThread = reinterpret_cast<NtSetInformationThread_t>(
        GetProcAddress(ntdll, "NtSetInformationThread"));

    return nt.querySystemInformation && nt.openThread && nt.setInformationThread;
}

static std::unique_ptr<std::byte[]> QuerySystemProcessBuffer(const NtApi& nt, ULONG& outSize) {
    ULONG size = 1 << 20;
    std::unique_ptr<std::byte[]> buffer;
    NTSTATUS status;
    ULONG needed = 0;

    do {
        buffer.reset(new std::byte[size]);
        status = nt.querySystemInformation(SystemProcessInformation, buffer.get(), size, &needed);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            size = std::max(size + (1 << 20), needed + (1 << 16));
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status)) {
        outSize = 0;
        return nullptr;
    }

    outSize = size;
    return buffer;
}

static UNDOC_SYSTEM_PROCESS_INFORMATION* FindProcessByPid(std::byte* raw, DWORD pid) {
    auto* spi = reinterpret_cast<UNDOC_SYSTEM_PROCESS_INFORMATION*>(raw);
    while (spi) {
        const DWORD currentPid = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(spi->UniqueProcessId));
        if (currentPid == pid) {
            return spi;
        }

        if (spi->NextEntryOffset == 0) {
            break;
        }

        spi = reinterpret_cast<UNDOC_SYSTEM_PROCESS_INFORMATION*>(reinterpret_cast<std::byte*>(spi) + spi->NextEntryOffset);
    }

    return nullptr;
}

static bool ApplyPriorityFix(const NtApi& nt,
                             HANDLE threadHandle,
                             KPRIORITY processBase,
                             KPRIORITY threadBase,
                             ThreadFixStats& stats) {
    ULONG disableBoost = 0;
    nt.setInformationThread(threadHandle, static_cast<THREADINFOCLASS>(kThreadInfoPriorityBoost), reinterpret_cast<PVOID>(&disableBoost), sizeof(disableBoost));

    bool anySetWorked = false;

    LONG relativeNtBase = ComputeRelativeBaseForNt(processBase, threadBase);
    if (NT_SUCCESS(nt.setInformationThread(threadHandle, static_cast<THREADINFOCLASS>(kThreadInfoBasePriority), reinterpret_cast<PVOID>(&relativeNtBase), sizeof(relativeNtBase)))) {
        anySetWorked = true;
        ++stats.ntSetBaseOk;
    }

    KPRIORITY absoluteTarget = static_cast<KPRIORITY>(ClampLong(threadBase, 1, 15));
    if (NT_SUCCESS(nt.setInformationThread(threadHandle, static_cast<THREADINFOCLASS>(kThreadInfoPriority), reinterpret_cast<PVOID>(&absoluteTarget), sizeof(absoluteTarget)))) {
        anySetWorked = true;
        ++stats.ntSetPriorityOk;
    }

    if (!anySetWorked) {
        int relativeWin32 = ClampWin32RelativePriorityFromBase(processBase, threadBase);
        if (SetThreadPriority(threadHandle, relativeWin32) != 0) {
            anySetWorked = true;
            ++stats.win32FallbackOk;
        }
    }

    if (!anySetWorked) {
        ++stats.setFailed;
    }

    return anySetWorked;
}

static void PrintBanner() {
    std::wprintf(L"autoboost_fix_nt - stuck dynamic priority recovery\n");
    std::wprintf(L"Policy: detect dynamic priority in [16..31], restore base class priority\n");
}

static void PrintProcessInfo(DWORD pid,
                             const UNDOC_SYSTEM_PROCESS_INFORMATION* proc) {
    const std::wstring name = ProcessNameOrUnknown(proc->ImageName);
    std::wprintf(L"Target PID: %lu\n", pid);
    std::wprintf(L"Process: %ls\n", name.c_str());
    std::wprintf(L"Process base priority class: %ld\n", static_cast<LONG>(proc->BasePriority));
}

static void PrintThreadLine(DWORD tid,
                            KPRIORITY oldPrio,
                            KPRIORITY basePrio,
                            KPRIORITY processBase,
                            bool fixed) {
    std::wprintf(L"TID=%-6lu dyn=%-2ld base=%-2ld pbase=%-2ld => %ls\n",
                 tid,
                 static_cast<LONG>(oldPrio),
                 static_cast<LONG>(basePrio),
                 static_cast<LONG>(processBase),
                 fixed ? L"fixed" : L"failed");
}

static ThreadFixStats FixProcessThreads(const NtApi& nt,
                                        UNDOC_SYSTEM_PROCESS_INFORMATION* proc) {
    ThreadFixStats stats{};
    const KPRIORITY processBase = proc->BasePriority;

    for (ULONG i = 0; i < proc->NumberOfThreads; ++i) {
        const auto& t = proc->Threads[i];
        ++stats.visited;

        if (!IsAutoboostStuckRange(t.Priority)) {
            continue;
        }

        if (t.Priority <= t.BasePriority) {
            continue;
        }

        ++stats.candidates;

        HANDLE threadHandle = nullptr;
        CLIENT_ID cid{t.ClientId.UniqueProcess, t.ClientId.UniqueThread};
        OBJECT_ATTRIBUTES oa{};
        InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);

        const NTSTATUS openStatus = nt.openThread(&threadHandle,
                                                  THREAD_SET_INFORMATION | THREAD_QUERY_INFORMATION,
                                                  &oa,
                                                  &cid);
        if (!NT_SUCCESS(openStatus) || !threadHandle) {
            ++stats.openFailed;
            PrintThreadLine(static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(t.ClientId.UniqueThread)),
                            t.Priority,
                            t.BasePriority,
                            processBase,
                            false);
            continue;
        }

        const bool fixed = ApplyPriorityFix(nt, threadHandle, processBase, t.BasePriority, stats);
        if (fixed) {
            ++stats.fixed;
        }

        PrintThreadLine(static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(t.ClientId.UniqueThread)),
                        t.Priority,
                        t.BasePriority,
                        processBase,
                        fixed);

        CloseHandle(threadHandle);
    }

    return stats;
}

static void PrintSummary(const ThreadFixStats& s) {
    std::wprintf(L"\nSummary\n");
    std::wprintf(L"  threads visited      : %lu\n", s.visited);
    std::wprintf(L"  candidates [16..31]  : %lu\n", s.candidates);
    std::wprintf(L"  fixed                : %lu\n", s.fixed);
    std::wprintf(L"  NtSet static_cast<THREADINFOCLASS>(kThreadInfoPriority) : %lu\n", s.ntSetPriorityOk);
    std::wprintf(L"  NtSet BasePriority   : %lu\n", s.ntSetBaseOk);
    std::wprintf(L"  Win32 fallback       : %lu\n", s.win32FallbackOk);
    std::wprintf(L"  open failures        : %lu\n", s.openFailed);
    std::wprintf(L"  set failures         : %lu\n", s.setFailed);
}

int wmain(int argc, wchar_t** argv) {
    constexpr DWORD kDefaultPid = 11692;

    PrintBanner();

    const DWORD pid = ParsePidOrDefault(argc, argv, kDefaultPid);
    if (pid == 0) {
        std::wprintf(L"Invalid PID argument.\n");
        std::wprintf(L"Usage: autoboost_fix_nt.exe [pid]\n");
        return 1;
    }

    NtApi nt{};
    if (!LoadNtApi(nt)) {
        std::wprintf(L"Failed to resolve NT API from ntdll.dll\n");
        return 1;
    }

    ULONG queriedSize = 0;
    auto buffer = QuerySystemProcessBuffer(nt, queriedSize);
    if (!buffer) {
        std::wprintf(L"NtQuerySystemInformation(SystemProcessInformation) failed\n");
        return 1;
    }

    auto* proc = FindProcessByPid(buffer.get(), pid);
    if (!proc) {
        std::wprintf(L"Target process PID %lu was not found in system snapshot.\n", pid);
        return 2;
    }

    PrintProcessInfo(pid, proc);
    const ThreadFixStats stats = FixProcessThreads(nt, proc);
    PrintSummary(stats);

    if (stats.candidates == 0) {
        std::wprintf(L"No stuck dynamic-priority threads [16..31] were detected for this process.\n");
    }

    return 0;
}
