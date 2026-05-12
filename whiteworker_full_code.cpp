#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <winternl.h>
#include <shlobj.h>
#include <tlhelp32.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cwctype>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#pragma comment(lib, "Shell32.lib")

using NtQuerySystemInformation_t =
NTSTATUS(NTAPI*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

static constexpr NTSTATUS STATUS_INFO_LENGTH_MISMATCH =
(NTSTATUS)0xC0000004L;

static constexpr double WHITE_THRESHOLD = 30.0;
static constexpr auto SAMPLE_INTERVAL = std::chrono::seconds(1);

static NtQuerySystemInformation_t g_NtQuerySystemInformation = nullptr;

typedef struct _MY_SYSTEM_THREAD_INFORMATION {
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
} MY_SYSTEM_THREAD_INFORMATION, * PMY_SYSTEM_THREAD_INFORMATION;

typedef struct _MY_SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
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

    MY_SYSTEM_THREAD_INFORMATION Threads[1];
} MY_SYSTEM_PROCESS_INFORMATION, * PMY_SYSTEM_PROCESS_INFORMATION;

struct Snapshot {
    ULONGLONG cpu100ns = 0;
    ULONGLONG user100ns = 0;
    ULONGLONG cycles = 0;
};

struct ThreadCache {
    HANDLE handle = nullptr;
    bool resolvedName = false;
    std::wstring name;
};

struct Row {
    DWORD tid = 0;

    std::wstring name;
    std::wstring module;

    double cpuRel = 0.0;
    double userRel = 0.0;
    double cyclesRel = 0.0;

    double score = 0.0;

    bool whiteWorker = false;
};

static std::unordered_map<DWORD, Snapshot> g_previous;
static std::unordered_map<DWORD, ThreadCache> g_threadCache;

std::wstring ToLower(std::wstring s) {
    for (auto& c : s) {
        c = static_cast<wchar_t>(towlower(c));
    }
    return s;
}

bool ContainsI(const std::wstring& text, const std::wstring& needle) {
    return ToLower(text).find(ToLower(needle)) != std::wstring::npos;
}

std::wstring SafeText(const std::wstring& s) {
    return s.empty() ? L"-" : s;
}

std::wstring TimeNow() {
    SYSTEMTIME st{};
    GetLocalTime(&st);

    wchar_t buf[64]{};

    swprintf_s(
        buf,
        L"%04u-%02u-%02u %02u:%02u:%02u",
        st.wYear,
        st.wMonth,
        st.wDay,
        st.wHour,
        st.wMinute,
        st.wSecond
    );

    return buf;
}

std::wstring GetDesktopLogPath() {
    wchar_t path[MAX_PATH]{};

    if (FAILED(SHGetFolderPathW(
        nullptr,
        CSIDL_DESKTOPDIRECTORY,
        nullptr,
        0,
        path
    ))) {
        return L"whiteworker_log.txt";
    }

    return std::wstring(path) + L"\\whiteworker_log.txt";
}

bool InitNt() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        return false;
    }

    g_NtQuerySystemInformation =
        reinterpret_cast<NtQuerySystemInformation_t>(
            GetProcAddress(ntdll, "NtQuerySystemInformation")
            );

    return g_NtQuerySystemInformation != nullptr;
}

bool QueryProcesses(std::vector<BYTE>& buffer) {
    ULONG size = 1024 * 1024;

    while (true) {
        buffer.resize(size);

        ULONG needed = 0;

        NTSTATUS status =
            g_NtQuerySystemInformation(
                SystemProcessInformation,
                buffer.data(),
                size,
                &needed
            );

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            size *= 2;
            continue;
        }

        if (status < 0) {
            return false;
        }

        return true;
    }
}

PMY_SYSTEM_PROCESS_INFORMATION FindCS2(
    std::vector<BYTE>& buffer,
    DWORD& pidOut
) {
    auto* proc =
        reinterpret_cast<PMY_SYSTEM_PROCESS_INFORMATION>(
            buffer.data()
            );

    while (true) {
        std::wstring name;

        if (proc->ImageName.Buffer && proc->ImageName.Length > 0) {
            name.assign(
                proc->ImageName.Buffer,
                proc->ImageName.Length / sizeof(WCHAR)
            );
        }

        if (!name.empty() && ContainsI(name, L"cs2.exe")) {
            pidOut =
                static_cast<DWORD>(
                    reinterpret_cast<uintptr_t>(proc->UniqueProcessId)
                    );

            return proc;
        }

        if (proc->NextEntryOffset == 0) {
            break;
        }

        proc =
            reinterpret_cast<PMY_SYSTEM_PROCESS_INFORMATION>(
                reinterpret_cast<BYTE*>(proc) +
                proc->NextEntryOffset
                );
    }

    return nullptr;
}

HANDLE GetCachedThreadHandle(DWORD tid) {
    auto& entry = g_threadCache[tid];

    if (entry.handle) {
        return entry.handle;
    }

    entry.handle =
        OpenThread(
            THREAD_QUERY_LIMITED_INFORMATION,
            FALSE,
            tid
        );

    return entry.handle;
}

std::wstring GetThreadNameCached(DWORD tid) {
    auto& entry = g_threadCache[tid];

    if (entry.resolvedName) {
        return entry.name;
    }

    entry.resolvedName = true;

    HANDLE hThread = GetCachedThreadHandle(tid);

    if (!hThread) {
        entry.name = L"-";
        return entry.name;
    }

    PWSTR rawName = nullptr;

    HRESULT hr =
        GetThreadDescription(
            hThread,
            &rawName
        );

    if (FAILED(hr) || !rawName) {
        entry.name = L"-";
        return entry.name;
    }

    entry.name = rawName;

    LocalFree(rawName);

    return entry.name;
}

ULONGLONG GetThreadCycles(DWORD tid) {
    HANDLE hThread = GetCachedThreadHandle(tid);

    if (!hThread) {
        return 0;
    }

    ULONG64 cycles = 0;

    if (!QueryThreadCycleTime(hThread, &cycles)) {
        return 0;
    }

    return static_cast<ULONGLONG>(cycles);
}

std::wstring GetModuleFromAddress(
    DWORD pid,
    uintptr_t address
) {
    HANDLE snapshot =
        CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
            pid
        );

    if (snapshot == INVALID_HANDLE_VALUE) {
        return L"-";
    }

    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);

    std::wstring result = L"-";

    if (Module32FirstW(snapshot, &me)) {
        do {
            uintptr_t base =
                reinterpret_cast<uintptr_t>(me.modBaseAddr);

            uintptr_t size =
                static_cast<uintptr_t>(me.modBaseSize);

            if (address >= base &&
                address < (base + size))
            {
                result = me.szModule;
                break;
            }

        } while (Module32NextW(snapshot, &me));
    }

    CloseHandle(snapshot);

    return result;
}

double Clamp100(double v) {
    if (v < 0.0) return 0.0;
    if (v > 100.0) return 100.0;
    return v;
}

int wmain() {
    if (!InitNt()) {
        std::wcerr << L"NT init failed\n";
        return 1;
    }

    std::wofstream log(
        GetDesktopLogPath(),
        std::ios::app
    );

    if (!log.is_open()) {
        std::wcerr << L"log open failed\n";
        return 1;
    }

    bool haveBaseline = false;

    log << L"=== Started " << TimeNow() << L" ===\n";
    log.flush();

    auto lastSample =
        std::chrono::steady_clock::now();

    while (true) {
        std::this_thread::sleep_for(SAMPLE_INTERVAL);

        auto now =
            std::chrono::steady_clock::now();

        auto elapsed =
            now - lastSample;

        lastSample = now;

        double elapsed100ns =
            std::chrono::duration_cast<
            std::chrono::nanoseconds
            >(elapsed).count() / 100.0;

        if (elapsed100ns <= 0.0) {
            elapsed100ns = 1.0;
        }

        std::vector<BYTE> buffer;

        if (!QueryProcesses(buffer)) {
            continue;
        }

        DWORD pid = 0;

        auto* proc =
            FindCS2(buffer, pid);

        if (!proc) {
            g_previous.clear();
            haveBaseline = false;
            continue;
        }

        if (!haveBaseline) {
            g_previous.clear();

            for (ULONG i = 0; i < proc->NumberOfThreads; ++i) {
                auto& t = proc->Threads[i];

                DWORD tid =
                    static_cast<DWORD>(
                        reinterpret_cast<uintptr_t>(
                            t.ClientId.UniqueThread
                            )
                        );

                ULONGLONG cpuNow =
                    static_cast<ULONGLONG>(
                        t.KernelTime.QuadPart
                        ) +
                    static_cast<ULONGLONG>(
                        t.UserTime.QuadPart
                        );

                ULONGLONG userNow =
                    static_cast<ULONGLONG>(
                        t.UserTime.QuadPart
                        );

                ULONGLONG cyclesNow =
                    GetThreadCycles(tid);

                g_previous[tid] = {
                    cpuNow,
                    userNow,
                    cyclesNow
                };
            }

            haveBaseline = true;
            continue;
        }

        struct Temp {
            DWORD tid = 0;

            double cpuRel = 0.0;
            double userRel = 0.0;

            ULONGLONG cycles = 0;

            std::wstring name;
            std::wstring module;
        };

        std::vector<Temp> tempRows;

        ULONGLONG totalCycles = 0;

        for (ULONG i = 0; i < proc->NumberOfThreads; ++i) {
            auto& t = proc->Threads[i];

            DWORD tid =
                static_cast<DWORD>(
                    reinterpret_cast<uintptr_t>(
                        t.ClientId.UniqueThread
                        )
                    );

            ULONGLONG cpuNow =
                static_cast<ULONGLONG>(
                    t.KernelTime.QuadPart
                    ) +
                static_cast<ULONGLONG>(
                    t.UserTime.QuadPart
                    );

            ULONGLONG userNow =
                static_cast<ULONGLONG>(
                    t.UserTime.QuadPart
                    );

            ULONGLONG cyclesNow =
                GetThreadCycles(tid);

            ULONGLONG cpuDelta = 0;
            ULONGLONG userDelta = 0;

            auto it =
                g_previous.find(tid);

            if (it != g_previous.end()) {
                if (cpuNow >= it->second.cpu100ns) {
                    cpuDelta =
                        cpuNow -
                        it->second.cpu100ns;
                }

                if (userNow >= it->second.user100ns) {
                    userDelta =
                        userNow -
                        it->second.user100ns;
                }
            }

            g_previous[tid] = {
                cpuNow,
                userNow,
                cyclesNow
            };

            double cpuRel =
                Clamp100(
                    (double)cpuDelta /
                    elapsed100ns *
                    100.0
                );

            double userRel =
                Clamp100(
                    (double)userDelta /
                    elapsed100ns *
                    100.0
                );

            totalCycles += cyclesNow;

            tempRows.push_back({
                tid,
                cpuRel,
                userRel,
                cyclesNow,
                SafeText(GetThreadNameCached(tid)),
                SafeText(
                    GetModuleFromAddress(
                        pid,
                        reinterpret_cast<uintptr_t>(
                            t.StartAddress
                        )
                    )
                )
                });
        }

        std::vector<Row> rows;

        double maxCpuRel = 0.0;
        double maxUserRel = 0.0;
        double maxCyclesRel = 0.0;

        for (const auto& t : tempRows) {
            const double cyclesRel =
                (totalCycles > 0)
                ? Clamp100((double)t.cycles / (double)totalCycles * 100.0)
                : 0.0;

            maxCpuRel = std::max(maxCpuRel, t.cpuRel);
            maxUserRel = std::max(maxUserRel, t.userRel);
            maxCyclesRel = std::max(maxCyclesRel, cyclesRel);
        }

        for (auto& t : tempRows) {
            Row r{};

            r.tid = t.tid;
            r.name = t.name;
            r.module = t.module;

            r.cpuRel = t.cpuRel;
            r.userRel = t.userRel;

            if (totalCycles > 0) {
                r.cyclesRel =
                    Clamp100(
                        (double)t.cycles /
                        (double)totalCycles *
                        100.0
                    );
            }

            const double cpuNorm =
                (maxCpuRel > 0.0) ? (r.cpuRel / maxCpuRel * 100.0) : 0.0;

            const double userNorm =
                (maxUserRel > 0.0) ? (r.userRel / maxUserRel * 100.0) : 0.0;

            const double cyclesNorm =
                (maxCyclesRel > 0.0) ? (r.cyclesRel / maxCyclesRel * 100.0) : 0.0;

            r.score =
                Clamp100((cpuNorm + userNorm + cyclesNorm) / 3.0);

            r.whiteWorker =
                (r.score >= WHITE_THRESHOLD);

            rows.push_back(std::move(r));
        }

        std::sort(
            rows.begin(),
            rows.end(),
            [](const Row& a, const Row& b) {
                return a.score > b.score;
            }
        );

        log
            << L"\n["
            << TimeNow()
            << L"] PID="
            << pid
            << L"\n";

        for (const auto& r : rows) {
            log
                << L"TID=" << r.tid
                << L" Name=" << r.name
                << L" Module=" << r.module

                << L" CPU(Relative)="
                << std::fixed
                << std::setprecision(2)
                << r.cpuRel
                << L"%"

                << L" UserTime(Relative)="
                << r.userRel
                << L"%"

                << L" Cycles(Relative)="
                << r.cyclesRel
                << L"%"

                << L" Score="
                << r.score

                << L" WhiteWorker="
                << (r.whiteWorker ? L"YES" : L"NO")

                << L"\n";
        }

        log.flush();
    }

    return 0;
}
