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

static bool FixOne(const NtApi& nt, DWORD pid, DWORD tid, KPRIORITY processBase, KPRIORITY snapshotBase) {
    HANDLE hThread = nullptr;
    CLIENT_ID cid{};
    cid.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid));
    cid.UniqueThread = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(tid));
    OBJECT_ATTRIBUTES oa{};
    InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);

    NTSTATUS openSt = nt.openThread(&hThread, THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION, &oa, &cid);
    if (!NT_SUCCESS(openSt) || !hThread) return false;


    ULONG disableBoost = 0;
    nt.setInformationThread(hThread, static_cast<THREADINFOCLASS>(kThreadInfoPriorityBoost), &disableBoost, sizeof(disableBoost));

    LONG relativeBase = static_cast<LONG>(snapshotBase) - static_cast<LONG>(processBase);
    if (relativeBase < -2) relativeBase = -2;
    if (relativeBase > 2) relativeBase = 2;

    bool ok = false;
    ok |= NT_SUCCESS(nt.setInformationThread(hThread, static_cast<THREADINFOCLASS>(kThreadInfoBasePriority), &relativeBase, sizeof(relativeBase)));

    KPRIORITY absTarget = snapshotBase;
    if (absTarget < 1) absTarget = 1;
    if (absTarget > 15) absTarget = 15;
    ok |= NT_SUCCESS(nt.setInformationThread(hThread, static_cast<THREADINFOCLASS>(kThreadInfoPriority), &absTarget, sizeof(absTarget)));

    CloseHandle(hThread);
    if (ok) {
    }
    return ok;
}


static std::vector<ThreadSnapshotEntry> BuildThreadCache(const NtApi& nt) {
    std::vector<ThreadSnapshotEntry> out;
    auto snap = QuerySnapshot(nt);
    if (!snap) return out;

    auto* spi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(snap.get());
    while (spi) {
        KPRIORITY processBase = spi->BasePriority;
        DWORD pid = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(spi->UniqueProcessId));
        const auto* threads = reinterpret_cast<const SYSTEM_THREAD_INFORMATION*>(
            reinterpret_cast<const std::byte*>(spi) + sizeof(SYSTEM_PROCESS_INFORMATION));

        for (ULONG i = 0; i < spi->NumberOfThreads; ++i) {
            ThreadSnapshotEntry e{};
            e.pid = pid;
            e.tid = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(threads[i].ClientId.UniqueThread));
            e.processBase = processBase;
            e.dyn = threads[i].Priority;
            e.base = threads[i].BasePriority;
            if (e.pid != 0 && e.tid != 0) out.push_back(e);
        }

        if (spi->NextEntryOffset == 0) break;
        spi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(reinterpret_cast<std::byte*>(spi) + spi->NextEntryOffset);
    }

    return out;
}

int wmain() {
    NtApi nt{};
    if (!LoadNtApi(nt)) {
        std::wprintf(L"NT API load failed\n");
        return 1;
    }

    std::wprintf(L"monitor mode: low-overhead NT scan (1000..5000ms)\n");

    ULONG idleTicks = 0;
    LONGLONG interval100ns = -10'000'000LL;

    std::vector<ThreadSnapshotEntry> cache;
    size_t cursor = 0;
    ULONG ticksFromRefresh = 1000;

    while (true) {
        static ULONG tick = 0;
        ++tick;
        if (ticksFromRefresh >= 10 || cache.empty()) {
            cache = BuildThreadCache(nt); // refresh ~every 10 ticks
            cursor = 0;
            ticksFromRefresh = 0;
        }
        ++ticksFromRefresh;

        ULONG scannedThreads = 0;
        ULONG candidates = 0;
        ULONG fixed = 0;

        const size_t kBudgetPerTick = 256;
        size_t processed = 0;
        while (!cache.empty() && processed < kBudgetPerTick) {
            if (cursor >= cache.size()) cursor = 0;
            const auto& e = cache[cursor++];
            ++processed;
            ++scannedThreads;
            if (!IsCandidate(e.dyn, e.base)) continue;
            ++candidates;
            if (FixOne(nt, e.pid, e.tid, e.processBase, e.base)) ++fixed;
        }

        if (candidates > 0 || fixed > 0) {
            idleTicks = 0;
            interval100ns = -10'000'000LL; // 1s active
        } else {
            ++idleTicks;
            if (idleTicks > 30) interval100ns = -50'000'000LL; // 5s
            else interval100ns = -20'000'000LL; // 2s
        }

        if ((tick % 20) == 0) {
            std::wprintf(L"status cache=%zu scanned=%lu candidates=%lu fixed=%lu idleTicks=%lu\n",
                         cache.size(), scannedThreads, candidates, fixed, idleTicks);
        }

        LARGE_INTEGER interval{};
        interval.QuadPart = interval100ns;
        nt.delayExecution(FALSE, &interval);
    }
}
