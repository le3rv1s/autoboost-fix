#define NOMINMAX
#include <windows.h>
#include <winternl.h>

#include <cstdint>
#include <cstdio>
#include <memory>
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
constexpr THREADINFOCLASS kThreadBasicInformationClass = static_cast<THREADINFOCLASS>(0);

using NtOpenThread_t = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, CLIENT_ID*);
using NtSetInformationThread_t = NTSTATUS(NTAPI*)(HANDLE, THREADINFOCLASS, PVOID, ULONG);
using NtQueryInformationThread_t = NTSTATUS(NTAPI*)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
using NtQuerySystemInformation_t = NTSTATUS(NTAPI*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

typedef struct _LOCAL_THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
} LOCAL_THREAD_BASIC_INFORMATION;

struct NtApi {
    NtOpenThread_t openThread = nullptr;
    NtSetInformationThread_t setInformationThread = nullptr;
    NtQueryInformationThread_t queryInformationThread = nullptr;
    NtQuerySystemInformation_t querySystemInformation = nullptr;
};

struct Stats {
    ULONG visited = 0;
    ULONG openFailed = 0;
    ULONG candidates = 0;
    ULONG fixed = 0;
};

static bool LoadNtApi(NtApi& nt) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;

    nt.openThread = reinterpret_cast<NtOpenThread_t>(GetProcAddress(ntdll, "NtOpenThread"));
    nt.setInformationThread = reinterpret_cast<NtSetInformationThread_t>(GetProcAddress(ntdll, "NtSetInformationThread"));
    nt.queryInformationThread = reinterpret_cast<NtQueryInformationThread_t>(GetProcAddress(ntdll, "NtQueryInformationThread"));
    nt.querySystemInformation = reinterpret_cast<NtQuerySystemInformation_t>(GetProcAddress(ntdll, "NtQuerySystemInformation"));
    return nt.openThread && nt.setInformationThread && nt.queryInformationThread && nt.querySystemInformation;
}

static std::unique_ptr<std::byte[]> QuerySystemProcessBuffer(const NtApi& nt) {
    ULONG size = 1 << 20;
    ULONG retLen = 0;
    NTSTATUS st;
    std::unique_ptr<std::byte[]> buffer;

    do {
        buffer.reset(new std::byte[size]);
        st = nt.querySystemInformation(SystemProcessInformation, buffer.get(), size, &retLen);
        if (st == STATUS_INFO_LENGTH_MISMATCH) {
            ULONG grown = size + (1 << 20);
            ULONG required = retLen + (1 << 16);
            size = (grown > required) ? grown : required;
        }
    } while (st == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(st)) return nullptr;
    return buffer;
}

static SYSTEM_PROCESS_INFORMATION* FindProcessByPid(std::byte* raw, DWORD pid) {
    auto* spi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(raw);
    while (spi) {
        DWORD currentPid = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(spi->UniqueProcessId));
        if (currentPid == pid) return spi;
        if (spi->NextEntryOffset == 0) break;
        spi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(reinterpret_cast<std::byte*>(spi) + spi->NextEntryOffset);
    }
    return nullptr;
}

static std::vector<DWORD> CollectThreadIds(const SYSTEM_PROCESS_INFORMATION* spi) {
    std::vector<DWORD> tids;
    if (!spi) return tids;

    tids.reserve(spi->NumberOfThreads);

    const auto* threads = reinterpret_cast<const SYSTEM_THREAD_INFORMATION*>(
        reinterpret_cast<const std::byte*>(spi) + sizeof(SYSTEM_PROCESS_INFORMATION));

    for (ULONG i = 0; i < spi->NumberOfThreads; ++i) {
        DWORD threadId = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(threads[i].ClientId.UniqueThread));
        if (threadId != 0) {
            tids.push_back(threadId);
        }
    }

    return tids;
}

static bool QueryLive(const NtApi& nt, HANDLE hThread, KPRIORITY& prio, KPRIORITY& base) {
    LOCAL_THREAD_BASIC_INFORMATION tbi{};
    NTSTATUS st = nt.queryInformationThread(hThread,
                                            kThreadBasicInformationClass,
                                            reinterpret_cast<PVOID>(&tbi),
                                            static_cast<ULONG>(sizeof(tbi)),
                                            nullptr);
    if (!NT_SUCCESS(st)) return false;
    prio = tbi.Priority;
    base = tbi.BasePriority;
    return true;
}

static bool IsCandidate(KPRIORITY prio, KPRIORITY base) {
    return prio >= 16 && prio <= 31 && prio > base;
}

static bool FixThread(const NtApi& nt, HANDLE hThread, KPRIORITY processBase, KPRIORITY threadBase) {
    ULONG disableBoost = 0;
    nt.setInformationThread(hThread,
                            static_cast<THREADINFOCLASS>(kThreadInfoPriorityBoost),
                            reinterpret_cast<PVOID>(&disableBoost),
                            sizeof(disableBoost));

    LONG relativeBase = static_cast<LONG>(threadBase) - static_cast<LONG>(processBase);
    if (relativeBase < -2) relativeBase = -2;
    if (relativeBase > 2) relativeBase = 2;

    bool ok = false;
    if (NT_SUCCESS(nt.setInformationThread(hThread,
                                           static_cast<THREADINFOCLASS>(kThreadInfoBasePriority),
                                           reinterpret_cast<PVOID>(&relativeBase),
                                           sizeof(relativeBase)))) {
        ok = true;
    }

    KPRIORITY absTarget = threadBase;
    if (absTarget < 1) absTarget = 1;
    if (absTarget > 15) absTarget = 15;
    if (NT_SUCCESS(nt.setInformationThread(hThread,
                                           static_cast<THREADINFOCLASS>(kThreadInfoPriority),
                                           reinterpret_cast<PVOID>(&absTarget),
                                           sizeof(absTarget)))) {
        ok = true;
    }

    if (!ok) {
        int rel = static_cast<int>(threadBase) - static_cast<int>(processBase);
        if (rel < THREAD_PRIORITY_LOWEST) rel = THREAD_PRIORITY_LOWEST;
        if (rel > THREAD_PRIORITY_HIGHEST) rel = THREAD_PRIORITY_HIGHEST;
        ok = SetThreadPriority(hThread, rel) != 0;
    }

    return ok;
}

int wmain(int argc, wchar_t** argv) {
    DWORD pid = 11692;
    if (argc >= 2) pid = static_cast<DWORD>(_wtoi(argv[1]));

    std::wprintf(L"autoboost_fix_nt (NT-only enumeration mode)\n");
    std::wprintf(L"Target PID: %lu\n", pid);

    NtApi nt{};
    if (!LoadNtApi(nt)) {
        std::wprintf(L"Failed to resolve NT functions\n");
        return 1;
    }

    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) {
        std::wprintf(L"OpenProcess failed for PID %lu\n", pid);
        return 1;
    }

    DWORD prioClass = GetPriorityClass(process);
    CloseHandle(process);

    KPRIORITY processBase = 8;
    if (prioClass == IDLE_PRIORITY_CLASS) processBase = 4;
    if (prioClass == BELOW_NORMAL_PRIORITY_CLASS) processBase = 6;
    if (prioClass == NORMAL_PRIORITY_CLASS) processBase = 8;
    if (prioClass == ABOVE_NORMAL_PRIORITY_CLASS) processBase = 10;
    if (prioClass == HIGH_PRIORITY_CLASS) processBase = 13;
    if (prioClass == REALTIME_PRIORITY_CLASS) processBase = 24;

    auto buffer = QuerySystemProcessBuffer(nt);
    if (!buffer) {
        std::wprintf(L"NtQuerySystemInformation(SystemProcessInformation) failed\n");
        return 2;
    }

    SYSTEM_PROCESS_INFORMATION* spi = FindProcessByPid(buffer.get(), pid);
    if (!spi) {
        std::wprintf(L"PID %lu not found in NT snapshot\n", pid);
        return 2;
    }

    std::vector<DWORD> tids = CollectThreadIds(spi);
    if (tids.empty()) {
        std::wprintf(L"No threads found in NT snapshot for PID %lu\n", pid);
        return 2;
    }

    Stats stats{};
    for (DWORD tid : tids) {
        ++stats.visited;
        HANDLE hThread = nullptr;

        CLIENT_ID cid{};
        cid.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid));
        cid.UniqueThread = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(tid));
        OBJECT_ATTRIBUTES oa{};
        InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);

        NTSTATUS openSt = nt.openThread(&hThread,
                                        THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION,
                                        &oa,
                                        &cid);
        if (!NT_SUCCESS(openSt) || !hThread) {
            ++stats.openFailed;
            std::wprintf(L"TID=%lu open failed NTSTATUS=0x%08X\n", tid, static_cast<unsigned>(openSt));
            continue;
        }

        KPRIORITY dyn = 0;
        KPRIORITY base = 0;
        if (!QueryLive(nt, hThread, dyn, base)) {
            std::wprintf(L"TID=%lu query failed\n", tid);
            CloseHandle(hThread);
            continue;
        }

        if (IsCandidate(dyn, base)) {
            ++stats.candidates;
            bool ok = FixThread(nt, hThread, processBase, base);
            if (ok) ++stats.fixed;
            std::wprintf(L"TID=%-6lu dyn=%-2ld base=%-2ld => %ls\n", tid, static_cast<LONG>(dyn), static_cast<LONG>(base), ok ? L"fixed" : L"failed");
        }

        CloseHandle(hThread);
    }

    std::wprintf(L"\nSummary\n");
    std::wprintf(L"  threads visited      : %lu\n", stats.visited);
    std::wprintf(L"  candidates [16..31]  : %lu\n", stats.candidates);
    std::wprintf(L"  fixed                : %lu\n", stats.fixed);
    std::wprintf(L"  open failures        : %lu\n", stats.openFailed);
    return 0;
}
