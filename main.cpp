#define NOMINMAX
#include <windows.h>
#include <winternl.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>

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
using NtDelayExecution_t = NTSTATUS(NTAPI*)(BOOLEAN, PLARGE_INTEGER);

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
    NtDelayExecution_t delayExecution = nullptr;
};

static bool LoadNtApi(NtApi& nt) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;
    nt.openThread = reinterpret_cast<NtOpenThread_t>(GetProcAddress(ntdll, "NtOpenThread"));
    nt.setInformationThread = reinterpret_cast<NtSetInformationThread_t>(GetProcAddress(ntdll, "NtSetInformationThread"));
    nt.queryInformationThread = reinterpret_cast<NtQueryInformationThread_t>(GetProcAddress(ntdll, "NtQueryInformationThread"));
    nt.querySystemInformation = reinterpret_cast<NtQuerySystemInformation_t>(GetProcAddress(ntdll, "NtQuerySystemInformation"));
    nt.delayExecution = reinterpret_cast<NtDelayExecution_t>(GetProcAddress(ntdll, "NtDelayExecution"));
    return nt.openThread && nt.setInformationThread && nt.queryInformationThread && nt.querySystemInformation && nt.delayExecution;
}

static std::unique_ptr<std::byte[]> QuerySnapshot(const NtApi& nt) {
    ULONG size = 4 << 20;
    ULONG ret = 0;
    NTSTATUS st;
    std::unique_ptr<std::byte[]> buf;
    do {
        buf.reset(new std::byte[size]);
        st = nt.querySystemInformation(SystemProcessInformation, buf.get(), size, &ret);
        if (st == STATUS_INFO_LENGTH_MISMATCH) size = (ret + (1 << 20));
    } while (st == STATUS_INFO_LENGTH_MISMATCH);
    if (!NT_SUCCESS(st)) return nullptr;
    return buf;
}

static bool QueryLive(const NtApi& nt, HANDLE hThread, KPRIORITY& prio, KPRIORITY& base) {
    LOCAL_THREAD_BASIC_INFORMATION tbi{};
    NTSTATUS st = nt.queryInformationThread(hThread,
                                            kThreadBasicInformationClass,
                                            &tbi,
                                            sizeof(tbi),
                                            nullptr);
    if (!NT_SUCCESS(st)) return false;
    prio = tbi.Priority;
    base = tbi.BasePriority;
    return true;
}

static bool IsCandidate(KPRIORITY dyn, KPRIORITY base) {
    return dyn >= 16 && dyn <= 31 && dyn > base;
}

static bool FixOne(const NtApi& nt, DWORD pid, DWORD tid, KPRIORITY processBase, KPRIORITY threadBase) {
    HANDLE hThread = nullptr;
    CLIENT_ID cid{};
    cid.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid));
    cid.UniqueThread = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(tid));
    OBJECT_ATTRIBUTES oa{};
    InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);

    NTSTATUS openSt = nt.openThread(&hThread, THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION, &oa, &cid);
    if (!NT_SUCCESS(openSt) || !hThread) return false;

    KPRIORITY dyn = 0;
    KPRIORITY base = 0;
    if (!QueryLive(nt, hThread, dyn, base)) {
        CloseHandle(hThread);
        return false;
    }

    if (!IsCandidate(dyn, base)) {
        CloseHandle(hThread);
        return false;
    }

    ULONG disableBoost = 0;
    nt.setInformationThread(hThread, static_cast<THREADINFOCLASS>(kThreadInfoPriorityBoost), &disableBoost, sizeof(disableBoost));

    LONG relativeBase = static_cast<LONG>(threadBase) - static_cast<LONG>(processBase);
    if (relativeBase < -2) relativeBase = -2;
    if (relativeBase > 2) relativeBase = 2;

    bool ok = false;
    ok |= NT_SUCCESS(nt.setInformationThread(hThread, static_cast<THREADINFOCLASS>(kThreadInfoBasePriority), &relativeBase, sizeof(relativeBase)));

    KPRIORITY absTarget = threadBase;
    if (absTarget < 1) absTarget = 1;
    if (absTarget > 15) absTarget = 15;
    ok |= NT_SUCCESS(nt.setInformationThread(hThread, static_cast<THREADINFOCLASS>(kThreadInfoPriority), &absTarget, sizeof(absTarget)));

    CloseHandle(hThread);
    if (ok) {
        std::wprintf(L"FIX pid=%lu tid=%lu dyn=%ld base=%ld\n", pid, tid, static_cast<LONG>(dyn), static_cast<LONG>(base));
    }
    return ok;
}

int wmain() {
    NtApi nt{};
    if (!LoadNtApi(nt)) {
        std::wprintf(L"NT API load failed\n");
        return 1;
    }

    std::wprintf(L"monitor mode: full system scan every 1000ms (NT-only)\n");

    while (true) {
        ULONG scannedThreads = 0;
        ULONG candidates = 0;
        ULONG fixed = 0;

        auto snap = QuerySnapshot(nt);
        if (snap) {
            auto* spi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(snap.get());
            while (spi) {
                KPRIORITY processBase = spi->BasePriority;
                const auto* threads = reinterpret_cast<const SYSTEM_THREAD_INFORMATION*>(
                    reinterpret_cast<const std::byte*>(spi) + sizeof(SYSTEM_PROCESS_INFORMATION));

                DWORD pid = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(spi->UniqueProcessId));
                for (ULONG i = 0; i < spi->NumberOfThreads; ++i) {
                    ++scannedThreads;
                    KPRIORITY dyn = threads[i].Priority;
                    KPRIORITY base = threads[i].BasePriority;
                    if (!IsCandidate(dyn, base)) continue;

                    ++candidates;
                    DWORD tid = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(threads[i].ClientId.UniqueThread));
                    if (tid == 0 || pid == 0) continue;
                    if (FixOne(nt, pid, tid, processBase, base)) ++fixed;
                }

                if (spi->NextEntryOffset == 0) break;
                spi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(reinterpret_cast<std::byte*>(spi) + spi->NextEntryOffset);
            }
        }

        std::wprintf(L"tick scanned=%lu candidates=%lu fixed=%lu\n", scannedThreads, candidates, fixed);

        LARGE_INTEGER interval{};
        interval.QuadPart = -10'000'000LL; // 1s
        nt.delayExecution(FALSE, &interval);
    }
}
