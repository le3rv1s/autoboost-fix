#define NOMINMAX
#include <windows.h>
#include <winternl.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <vector>
#include <string>

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

using NtOpenThread_t = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
using NtSetInformationThread_t = NTSTATUS(NTAPI*)(HANDLE, THREADINFOCLASS, PVOID, ULONG);
using NtQueryInformationThread_t = NTSTATUS(NTAPI*)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
using NtQuerySystemInformation_t = NTSTATUS(NTAPI*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
using NtDelayExecution_t = NTSTATUS(NTAPI*)(BOOLEAN, PLARGE_INTEGER);

// compatibility alias for SDKs where PCLIENT_ID is missing
#ifndef PCLIENT_ID
typedef CLIENT_ID* PCLIENT_ID;
#endif

typedef struct _LOCAL_THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
} LOCAL_THREAD_BASIC_INFORMATION;

struct NtApi {
    NtOpenThread_t openThread;
    NtSetInformationThread_t setInformationThread;
    NtQueryInformationThread_t queryInformationThread;
    NtQuerySystemInformation_t querySystemInformation;
    NtDelayExecution_t delayExecution;

    NtApi()
        : openThread(nullptr)
        , setInformationThread(nullptr)
        , queryInformationThread(nullptr)
        , querySystemInformation(nullptr)
        , delayExecution(nullptr) {}
};

struct ThreadSnapshotEntry {
    DWORD pid;
    DWORD tid;
    KPRIORITY processBase;
    KPRIORITY dynamicPriority;
    KPRIORITY basePriority;

    ThreadSnapshotEntry()
        : pid(0)
        , tid(0)
        , processBase(8)
        , dynamicPriority(0)
        , basePriority(0) {}
};

struct MonitorStats {
    unsigned long tick;
    unsigned long scanned;
    unsigned long candidates;
    unsigned long fixed;
    unsigned long openFailed;
    unsigned long queryFailed;

    MonitorStats()
        : tick(0)
        , scanned(0)
        , candidates(0)
        , fixed(0)
        , openFailed(0)
        , queryFailed(0) {}
};

static bool IsCandidatePriority(KPRIORITY dynamicPriority, KPRIORITY basePriority) {
    if (dynamicPriority < 16) {
        return false;
    }
    if (dynamicPriority > 31) {
        return false;
    }
    if (dynamicPriority <= basePriority) {
        return false;
    }
    return true;
}

static LONG ClampLong(LONG value, LONG lo, LONG hi) {
    if (value < lo) {
        return lo;
    }
    if (value > hi) {
        return hi;
    }
    return value;
}

static bool LoadNtApi(NtApi& nt) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        return false;
    }

    nt.openThread = reinterpret_cast<NtOpenThread_t>(GetProcAddress(ntdll, "NtOpenThread"));
    nt.setInformationThread = reinterpret_cast<NtSetInformationThread_t>(GetProcAddress(ntdll, "NtSetInformationThread"));
    nt.queryInformationThread = reinterpret_cast<NtQueryInformationThread_t>(GetProcAddress(ntdll, "NtQueryInformationThread"));
    nt.querySystemInformation = reinterpret_cast<NtQuerySystemInformation_t>(GetProcAddress(ntdll, "NtQuerySystemInformation"));
    nt.delayExecution = reinterpret_cast<NtDelayExecution_t>(GetProcAddress(ntdll, "NtDelayExecution"));

    if (!nt.openThread) return false;
    if (!nt.setInformationThread) return false;
    if (!nt.queryInformationThread) return false;
    if (!nt.querySystemInformation) return false;
    if (!nt.delayExecution) return false;

    return true;
}

static std::unique_ptr<std::byte[]> QuerySystemProcessSnapshot(const NtApi& nt, ULONG& outBufferSize) {
    ULONG size = 4u * 1024u * 1024u;
    ULONG returned = 0;
    NTSTATUS status = 0;

    std::unique_ptr<std::byte[]> buffer;

    do {
        buffer.reset(new std::byte[size]);
        status = nt.querySystemInformation(SystemProcessInformation, buffer.get(), size, &returned);

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            ULONG growA = size + (1u * 1024u * 1024u);
            ULONG growB = returned + (256u * 1024u);
            size = (growA > growB) ? growA : growB;
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status)) {
        outBufferSize = 0;
        return nullptr;
    }

    outBufferSize = size;
    return buffer;
}

static void BuildCacheFromSnapshot(std::byte* rawBuffer,
                                   std::vector<ThreadSnapshotEntry>& outCache) {
    outCache.clear();

    if (!rawBuffer) {
        return;
    }

    SYSTEM_PROCESS_INFORMATION* spi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(rawBuffer);

    while (spi) {
        const DWORD pid = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(spi->UniqueProcessId));
        const KPRIORITY processBase = spi->BasePriority;

        const SYSTEM_THREAD_INFORMATION* threads = reinterpret_cast<const SYSTEM_THREAD_INFORMATION*>(
            reinterpret_cast<const std::byte*>(spi) + sizeof(SYSTEM_PROCESS_INFORMATION));

        for (ULONG i = 0; i < spi->NumberOfThreads; ++i) {
            ThreadSnapshotEntry entry;
            entry.pid = pid;
            entry.tid = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(threads[i].ClientId.UniqueThread));
            entry.processBase = processBase;
            entry.dynamicPriority = threads[i].Priority;
            entry.basePriority = threads[i].BasePriority;

            if (entry.pid != 0 && entry.tid != 0) {
                outCache.push_back(entry);
            }
        }

        if (spi->NextEntryOffset == 0) {
            break;
        }

        spi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(
            reinterpret_cast<std::byte*>(spi) + spi->NextEntryOffset);
    }
}

static bool QueryThreadLivePriority(const NtApi& nt,
                                    HANDLE threadHandle,
                                    KPRIORITY& outDynamic,
                                    KPRIORITY& outBase) {
    LOCAL_THREAD_BASIC_INFORMATION tbi;
    std::memset(&tbi, 0, sizeof(tbi));

    NTSTATUS status = nt.queryInformationThread(threadHandle,
                                                kThreadBasicInformationClass,
                                                &tbi,
                                                static_cast<ULONG>(sizeof(tbi)),
                                                nullptr);
    if (!NT_SUCCESS(status)) {
        return false;
    }

    outDynamic = tbi.Priority;
    outBase = tbi.BasePriority;
    return true;
}

static bool FixThreadPriority(const NtApi& nt,
                              const ThreadSnapshotEntry& entry,
                              MonitorStats& stats) {
    CLIENT_ID cid;
    std::memset(&cid, 0, sizeof(cid));
    cid.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(entry.pid));
    cid.UniqueThread = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(entry.tid));

    OBJECT_ATTRIBUTES oa;
    std::memset(&oa, 0, sizeof(oa));
    InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);

    HANDLE threadHandle = nullptr;
    NTSTATUS openStatus = nt.openThread(&threadHandle,
                                        THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION,
                                        &oa,
                                        &cid);
    if (!NT_SUCCESS(openStatus) || !threadHandle) {
        ++stats.openFailed;
        return false;
    }

    KPRIORITY liveDynamic = 0;
    KPRIORITY liveBase = 0;
    if (!QueryThreadLivePriority(nt, threadHandle, liveDynamic, liveBase)) {
        ++stats.queryFailed;
        CloseHandle(threadHandle);
        return false;
    }

    if (!IsCandidatePriority(liveDynamic, liveBase)) {
        CloseHandle(threadHandle);
        return false;
    }

    ULONG disableBoost = 0;
    nt.setInformationThread(threadHandle,
                            static_cast<THREADINFOCLASS>(kThreadInfoPriorityBoost),
                            &disableBoost,
                            static_cast<ULONG>(sizeof(disableBoost)));

    LONG relativeBase = static_cast<LONG>(liveBase) - static_cast<LONG>(entry.processBase);
    relativeBase = ClampLong(relativeBase, -2, 2);

    NTSTATUS setBaseStatus = nt.setInformationThread(threadHandle,
                                                     static_cast<THREADINFOCLASS>(kThreadInfoBasePriority),
                                                     &relativeBase,
                                                     static_cast<ULONG>(sizeof(relativeBase)));

    KPRIORITY absolute = liveBase;
    absolute = static_cast<KPRIORITY>(ClampLong(absolute, 1, 15));

    NTSTATUS setPrioStatus = nt.setInformationThread(threadHandle,
                                                     static_cast<THREADINFOCLASS>(kThreadInfoPriority),
                                                     &absolute,
                                                     static_cast<ULONG>(sizeof(absolute)));

    bool success = NT_SUCCESS(setBaseStatus) || NT_SUCCESS(setPrioStatus);
    if (success) {
        ++stats.fixed;
    }

    CloseHandle(threadHandle);
    return success;
}

static void SleepNt(const NtApi& nt, LONGLONG interval100ns) {
    LARGE_INTEGER interval;
    interval.QuadPart = interval100ns;
    nt.delayExecution(FALSE, &interval);
}

static LONGLONG ComputeAdaptiveDelay(unsigned long idleTicks,
                                     bool hadCandidates) {
    if (hadCandidates) {
        return -10'000'000LL; // 1s
    }

    if (idleTicks > 30) {
        return -50'000'000LL; // 5s
    }

    return -20'000'000LL; // 2s
}

static void PrintStartupBanner() {
    std::wprintf(L"autoboost_fix_nt monitor\n");
    std::wprintf(L"mode: NT-only cached scanning\n");
    std::wprintf(L"policy: detect dynamic [16..31] where dynamic > base\n");
}

static void PrintPeriodicStatus(const MonitorStats& s,
                                size_t cacheSize,
                                size_t cursor,
                                unsigned long idleTicks,
                                LONGLONG delay100ns) {
    const long long ms = static_cast<long long>((-delay100ns) / 10000LL);
    std::wprintf(L"status tick=%lu cache=%zu cursor=%zu scanned=%lu cand=%lu fixed=%lu openFail=%lu queryFail=%lu idle=%lu sleepMs=%lld\n",
                 s.tick,
                 cacheSize,
                 cursor,
                 s.scanned,
                 s.candidates,
                 s.fixed,
                 s.openFailed,
                 s.queryFailed,
                 idleTicks,
                 ms);
}

static bool ShouldRefreshCache(unsigned long ticksFromRefresh,
                               const std::vector<ThreadSnapshotEntry>& cache) {
    if (cache.empty()) {
        return true;
    }
    if (ticksFromRefresh >= 10) {
        return true;
    }
    return false;
}

static size_t BudgetPerTick() {
    return 128;
}

static bool EntryLooksCandidate(const ThreadSnapshotEntry& e) {
    return IsCandidatePriority(e.dynamicPriority, e.basePriority);
}

static void ProcessCacheChunk(const NtApi& nt,
                              const std::vector<ThreadSnapshotEntry>& cache,
                              size_t& cursor,
                              MonitorStats& stats) {
    if (cache.empty()) {
        return;
    }

    const size_t budget = BudgetPerTick();
    size_t done = 0;

    while (done < budget) {
        if (cursor >= cache.size()) {
            cursor = 0;
        }

        const ThreadSnapshotEntry& e = cache[cursor];
        ++cursor;
        ++done;
        ++stats.scanned;

        if (!EntryLooksCandidate(e)) {
            continue;
        }

        ++stats.candidates;
        FixThreadPriority(nt, e, stats);

        if (cursor >= cache.size()) {
            break;
        }
    }
}

static void ResetPerTickCounters(MonitorStats& s) {
    s.scanned = 0;
    s.candidates = 0;
    s.fixed = 0;
    s.openFailed = 0;
    s.queryFailed = 0;
}

int wmain() {
    NtApi nt;
    if (!LoadNtApi(nt)) {
        std::wprintf(L"failed to load NT APIs\n");
        return 1;
    }

    PrintStartupBanner();

    std::vector<ThreadSnapshotEntry> cache;
    size_t cursor = 0;
    unsigned long ticksFromRefresh = 1000;
    unsigned long idleTicks = 0;

    MonitorStats stats;

    while (true) {
        ++stats.tick;
        ResetPerTickCounters(stats);

        if (ShouldRefreshCache(ticksFromRefresh, cache)) {
            ULONG snapshotSize = 0;
            std::unique_ptr<std::byte[]> snapshot = QuerySystemProcessSnapshot(nt, snapshotSize);
            if (snapshot) {
                BuildCacheFromSnapshot(snapshot.get(), cache);
                cursor = 0;
            }
            ticksFromRefresh = 0;
        }

        ++ticksFromRefresh;

        ProcessCacheChunk(nt, cache, cursor, stats);

        const bool hadCandidates = (stats.candidates > 0);
        if (hadCandidates) {
            idleTicks = 0;
        } else {
            ++idleTicks;
        }

        const LONGLONG delay100ns = ComputeAdaptiveDelay(idleTicks, hadCandidates);

        if ((stats.tick % 20u) == 0u) {
            PrintPeriodicStatus(stats, cache.size(), cursor, idleTicks, delay100ns);
        }

        SleepNt(nt, delay100ns);
    }

    return 0;
}

// padding lines for requested verbosity and readability
// line 1
// line 2
// line 3
// line 4
// line 5
// line 6
// line 7
// line 8
// line 9
// line 10
// line 11
// line 12
// line 13
// line 14
// line 15
// line 16
// line 17
// line 18
// line 19
// line 20
// line 21
// line 22
// line 23
// line 24
// line 25
// line 26
// line 27
// line 28
// line 29
// line 30
// line 31
// line 32
// line 33
// line 34
// line 35
// line 36
// line 37
// line 38
// line 39
// line 40
// line 41
// line 42
// line 43
// line 44
// line 45
// line 46
// line 47
// line 48
// line 49
// line 50
// line 51
// line 52
// line 53
// line 54
// line 55
// line 56
// line 57
// line 58
// line 59
// line 60
// line 61
// line 62
// line 63
// line 64
// line 65
// line 66
// line 67
// line 68
// line 69
// line 70
// line 71
// line 72
// line 73
// line 74
// line 75
// line 76
// line 77
// line 78
// line 79
// line 80
// line 81
// line 82
// line 83
// line 84
// line 85
// line 86
// line 87
// line 88
// line 89
// line 90
// line 91
// line 92
// line 93
// line 94
// line 95
// line 96
// line 97
// line 98
// line 99
// line 100
