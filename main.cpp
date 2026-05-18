#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <shlobj.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cwchar>
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

using NTSTATUS_T = LONG;
using KPRIORITY_T = LONG;

using NtQuerySystemInformation_t = NTSTATUS_T(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
using NtQueryVirtualMemory_t = NTSTATUS_T(NTAPI*)(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);
using NtQueryInformationThread_t = NTSTATUS_T(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using SetThreadDescription_t = HRESULT(WINAPI*)(HANDLE, PCWSTR);
using GetThreadDescription_t = HRESULT(WINAPI*)(HANDLE, PWSTR*);

static constexpr NTSTATUS_T STATUS_INFO_LENGTH_MISMATCH_VALUE = static_cast<NTSTATUS_T>(0xC0000004L);
static constexpr ULONG SYSTEM_PROCESS_INFORMATION_CLASS = 5;
static constexpr ULONG MEMORY_SECTION_NAME_CLASS = 2;
static constexpr ULONG THREAD_QUERY_SET_WIN32_START_ADDRESS_CLASS = 9;
static constexpr double TOPG_THRESHOLD = 15.0;
static constexpr size_t MIN_THREADS_PER_GROUP = 3;
static constexpr size_t MAX_THREADS_PER_GROUP = 5;
static constexpr auto SAMPLE_INTERVAL = std::chrono::seconds(1);
static constexpr wchar_t TARGET_GAME[] = L"SNB.exe";

#ifndef THREAD_QUERY_LIMITED_INFORMATION
#define THREAD_QUERY_LIMITED_INFORMATION 0x0800
#endif

#ifndef THREAD_SET_LIMITED_INFORMATION
#define THREAD_SET_LIMITED_INFORMATION 0x0400
#endif

#ifndef THREAD_QUERY_INFORMATION
#define THREAD_QUERY_INFORMATION 0x0040
#endif

// =========================================================
// NT STRUCTS
// =========================================================
struct NativeUnicodeString {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
};

struct NativeClientId {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
};

struct NativeSystemThreadInformation {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    NativeClientId ClientId;
    KPRIORITY_T Priority;
    KPRIORITY_T BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
};

struct NativeSystemProcessInformation {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    NativeUnicodeString ImageName;
    KPRIORITY_T BasePriority;
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
    NativeSystemThreadInformation Threads[1];
};

// =========================================================
// DATA
// =========================================================
struct Snapshot {
    ULONGLONG cycles = 0;
};

struct ThreadCacheEntry {
    HANDLE handle = nullptr;
    bool symbolResolved = false;
    std::wstring originalSymbol;
};

struct ThreadRow {
    DWORD tid = 0;
    std::wstring symbol;
    std::wstring module;
    ULONGLONG cyclesDelta = 0;
    double cyclesShare = 0.0;
    bool white = false;
    std::wstring label;
};

struct GroupBucket {
    std::wstring symbol;
    std::wstring module;
    std::vector<size_t> members;
};

struct GroupChunk {
    std::wstring symbol;
    std::wstring module;
    std::vector<size_t> members;
    ULONGLONG cyclesDeltaSum = 0;
    double share = 0.0;
    size_t groupNo = 0;
    bool white = false;
    std::wstring label;
};

static NtQuerySystemInformation_t g_NtQuerySystemInformation = nullptr;
static NtQueryVirtualMemory_t g_NtQueryVirtualMemory = nullptr;
static NtQueryInformationThread_t g_NtQueryInformationThread = nullptr;
static SetThreadDescription_t g_SetThreadDescription = nullptr;
static GetThreadDescription_t g_GetThreadDescription = nullptr;

static std::unordered_map<DWORD, Snapshot> g_previous;
static std::unordered_map<DWORD, ThreadCacheEntry> g_threadCache;
static std::unordered_map<uintptr_t, std::wstring> g_moduleCache;

// =========================================================
// HELPERS
// =========================================================
std::wstring TimeNow() {
    SYSTEMTIME st{};
    GetLocalTime(&st);

    wchar_t buffer[64]{};
    swprintf_s(buffer,
        L"%04u-%02u-%02u %02u:%02u:%02u",
        st.wYear,
        st.wMonth,
        st.wDay,
        st.wHour,
        st.wMinute,
        st.wSecond);

    return buffer;
}


std::wstring GetDesktopPath() {
    wchar_t path[MAX_PATH]{};
    HRESULT hr = SHGetFolderPathW(
        nullptr,
        CSIDL_DESKTOPDIRECTORY | CSIDL_FLAG_CREATE,
        nullptr,
        SHGFP_TYPE_CURRENT,
        path);

    if (SUCCEEDED(hr) && path[0] != L'\0') {
        return path;
    }

    wchar_t currentDir[MAX_PATH]{};
    DWORD len = GetCurrentDirectoryW(MAX_PATH, currentDir);
    if (len > 0 && len < MAX_PATH) {
        return currentDir;
    }

    return L".";
}

std::wstring JoinPath(const std::wstring& dir, const std::wstring& file) {
    if (dir.empty()) {
        return file;
    }

    wchar_t last = dir.back();
    if (last == L'\\' || last == L'/') {
        return dir + file;
    }

    return dir + L"\\" + file;
}

std::wstring Trim(const std::wstring& s) {
    size_t start = 0;
    while (start < s.size() && iswspace(s[start])) {
        ++start;
    }

    size_t end = s.size();
    while (end > start && iswspace(s[end - 1])) {
        --end;
    }

    return s.substr(start, end - start);
}

double Clamp100(double v) {
    if (v < 0.0) {
        return 0.0;
    }
    if (v > 100.0) {
        return 100.0;
    }
    return v;
}

bool StartsWithI(const std::wstring& text, const std::wstring& prefix) {
    if (text.size() < prefix.size()) {
        return false;
    }

    for (size_t i = 0; i < prefix.size(); ++i) {
        if (towlower(text[i]) != towlower(prefix[i])) {
            return false;
        }
    }

    return true;
}

std::wstring NormalizeSymbol(const std::wstring& s) {
    std::wstring out = Trim(s);

    if (out.empty()) {
        return L"-";
    }

    if (StartsWithI(out, L"TopGWhiteWorker/") || StartsWithI(out, L"TopGBlackWorker/")) {
        return out;
    }

    while (!out.empty() && iswdigit(out.back())) {
        out.pop_back();
    }

    while (!out.empty() &&
        (out.back() == L'/' || out.back() == L'_' || out.back() == L'-' || iswspace(out.back()))) {
        out.pop_back();
    }

    out = Trim(out);
    return out.empty() ? L"-" : out;
}

bool InitNt() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        return false;
    }

    g_NtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformation_t>(
        GetProcAddress(ntdll, "NtQuerySystemInformation"));
    g_NtQueryVirtualMemory = reinterpret_cast<NtQueryVirtualMemory_t>(
        GetProcAddress(ntdll, "NtQueryVirtualMemory"));
    g_NtQueryInformationThread = reinterpret_cast<NtQueryInformationThread_t>(
        GetProcAddress(ntdll, "NtQueryInformationThread"));

    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (kernel32) {
        g_SetThreadDescription = reinterpret_cast<SetThreadDescription_t>(
            GetProcAddress(kernel32, "SetThreadDescription"));
        g_GetThreadDescription = reinterpret_cast<GetThreadDescription_t>(
            GetProcAddress(kernel32, "GetThreadDescription"));
    }

    return g_NtQuerySystemInformation != nullptr &&
        g_NtQueryVirtualMemory != nullptr &&
        g_NtQueryInformationThread != nullptr;
}

bool QueryProcesses(std::vector<BYTE>& buffer) {
    ULONG size = 1024 * 1024;

    while (true) {
        buffer.resize(size);
        ULONG needed = 0;
        NTSTATUS_T status = g_NtQuerySystemInformation(
            SYSTEM_PROCESS_INFORMATION_CLASS,
            buffer.data(),
            size,
            &needed);

        if (status == STATUS_INFO_LENGTH_MISMATCH_VALUE) {
            size = (needed > size) ? needed + 1024 * 256 : size * 2;
            continue;
        }

        return status >= 0;
    }
}

NativeSystemProcessInformation* FindGame(std::vector<BYTE>& buffer, DWORD& pidOut) {
    auto* proc = reinterpret_cast<NativeSystemProcessInformation*>(buffer.data());

    while (true) {
        std::wstring name;
        if (proc->ImageName.Buffer && proc->ImageName.Length > 0) {
            name.assign(proc->ImageName.Buffer, proc->ImageName.Length / sizeof(WCHAR));
        }

        if (_wcsicmp(name.c_str(), TARGET_GAME) == 0) {
            pidOut = static_cast<DWORD>(reinterpret_cast<uintptr_t>(proc->UniqueProcessId));
            return proc;
        }

        if (proc->NextEntryOffset == 0) {
            break;
        }

        proc = reinterpret_cast<NativeSystemProcessInformation*>(
            reinterpret_cast<BYTE*>(proc) + proc->NextEntryOffset);
    }

    return nullptr;
}

std::wstring GetProcessName(NativeSystemProcessInformation* proc) {
    if (proc && proc->ImageName.Buffer && proc->ImageName.Length > 0) {
        return std::wstring(proc->ImageName.Buffer, proc->ImageName.Length / sizeof(WCHAR));
    }
    return L"-";
}

HANDLE GetCachedThreadHandle(DWORD tid) {
    auto& entry = g_threadCache[tid];
    if (entry.handle) {
        return entry.handle;
    }

    entry.handle = OpenThread(THREAD_QUERY_LIMITED_INFORMATION | THREAD_SET_LIMITED_INFORMATION, FALSE, tid);
    return entry.handle;
}

void CloseThreadCacheEntry(DWORD tid) {
    auto it = g_threadCache.find(tid);
    if (it != g_threadCache.end()) {
        if (it->second.handle) {
            CloseHandle(it->second.handle);
        }
        g_threadCache.erase(it);
    }
}

std::wstring GetThreadOriginalSymbolCached(DWORD tid) {
    auto& entry = g_threadCache[tid];

    if (entry.symbolResolved) {
        return entry.originalSymbol;
    }

    entry.symbolResolved = true;

    HANDLE hThread = GetCachedThreadHandle(tid);
    if (!hThread || !g_GetThreadDescription) {
        entry.originalSymbol = L"-";
        return entry.originalSymbol;
    }

    PWSTR rawName = nullptr;
    HRESULT hr = g_GetThreadDescription(hThread, &rawName);
    if (FAILED(hr) || !rawName) {
        entry.originalSymbol = L"-";
        return entry.originalSymbol;
    }

    std::wstring resolved = NormalizeSymbol(rawName);
    LocalFree(rawName);

    entry.originalSymbol = resolved;
    return entry.originalSymbol;
}

bool SetThreadName(DWORD tid, const std::wstring& newName) {
    if (!g_SetThreadDescription) {
        return false;
    }

    HANDLE hThread = GetCachedThreadHandle(tid);
    if (!hThread) {
        return false;
    }

    HRESULT hr = g_SetThreadDescription(hThread, newName.c_str());
    return SUCCEEDED(hr);
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

uintptr_t GetThreadWin32StartAddress(DWORD tid, uintptr_t fallbackAddress) {
    if (!g_NtQueryInformationThread) {
        return fallbackAddress;
    }

    PVOID startAddress = nullptr;
    HANDLE hThread = GetCachedThreadHandle(tid);
    if (hThread) {
        NTSTATUS_T status = g_NtQueryInformationThread(
            hThread,
            THREAD_QUERY_SET_WIN32_START_ADDRESS_CLASS,
            &startAddress,
            sizeof(startAddress),
            nullptr);
        if (status >= 0 && startAddress) {
            return reinterpret_cast<uintptr_t>(startAddress);
        }
    }

    HANDLE queryThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
    if (queryThread) {
        NTSTATUS_T status = g_NtQueryInformationThread(
            queryThread,
            THREAD_QUERY_SET_WIN32_START_ADDRESS_CLASS,
            &startAddress,
            sizeof(startAddress),
            nullptr);
        CloseHandle(queryThread);
        if (status >= 0 && startAddress) {
            return reinterpret_cast<uintptr_t>(startAddress);
        }
    }

    return fallbackAddress;
}

std::wstring FormatHex(uintptr_t value) {
    wchar_t buffer[32]{};
    swprintf_s(buffer, L"0x%llx", static_cast<unsigned long long>(value));
    return buffer;
}

std::wstring QuerySectionName(HANDLE hProcess, uintptr_t address) {
    auto it = g_moduleCache.find(address);
    if (it != g_moduleCache.end()) {
        return it->second;
    }

    if (!g_NtQueryVirtualMemory || !hProcess) {
        g_moduleCache[address] = L"-";
        return L"-";
    }

    std::vector<BYTE> buffer(1024);
    while (true) {
        SIZE_T retLen = 0;
        NTSTATUS_T status = g_NtQueryVirtualMemory(
            hProcess,
            reinterpret_cast<PVOID>(address),
            MEMORY_SECTION_NAME_CLASS,
            buffer.data(),
            buffer.size(),
            &retLen);

        if (status == STATUS_INFO_LENGTH_MISMATCH_VALUE) {
            buffer.resize(buffer.size() * 2);
            continue;
        }

        if (status < 0) {
            g_moduleCache[address] = L"-";
            return L"-";
        }

        break;
    }

    auto* u = reinterpret_cast<NativeUnicodeString*>(buffer.data());
    if (!u || !u->Buffer || u->Length == 0) {
        g_moduleCache[address] = L"-";
        return L"-";
    }

    std::wstring fullPath(u->Buffer, u->Length / sizeof(WCHAR));
    fullPath = Trim(fullPath);

    size_t slash = fullPath.find_last_of(L"\\/");
    std::wstring module = (slash == std::wstring::npos) ? fullPath : fullPath.substr(slash + 1);
    if (module.empty()) {
        module = L"-";
    }

    g_moduleCache[address] = module;
    return module;
}

std::wstring BuildStartAddressSymbol(HANDLE hProcess, const std::wstring& module, uintptr_t address) {
    if (module.empty() || module == L"-" || address == 0) {
        return L"-";
    }

    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == 0 ||
        mbi.AllocationBase == nullptr) {
        return module + L"!" + FormatHex(address);
    }

    const uintptr_t moduleBase = reinterpret_cast<uintptr_t>(mbi.AllocationBase);
    if (address < moduleBase) {
        return module + L"!" + FormatHex(address);
    }

    return module + L"!+" + FormatHex(address - moduleBase);
}

void ClearCaches() {
    for (auto& kv : g_threadCache) {
        if (kv.second.handle) {
            CloseHandle(kv.second.handle);
        }
    }

    g_threadCache.clear();
    g_moduleCache.clear();
    g_previous.clear();
}

DWORD GetForegroundPid() {
    HWND hwnd = GetForegroundWindow();
    if (!hwnd) {
        return 0;
    }

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    return pid;
}

std::vector<size_t> BuildGroupFromBucket(
    const GroupBucket& bucket,
    const std::vector<ThreadRow>& rows,
    ULONGLONG totalCyclesDelta,
    std::vector<GroupChunk>& outChunks) {
    std::vector<size_t> ordered = bucket.members;

    // Prefer the hottest threads for the active group; TID is only a deterministic tie-breaker.
    std::sort(ordered.begin(), ordered.end(), [&](size_t a, size_t b) {
        if (rows[a].cyclesDelta != rows[b].cyclesDelta) {
            return rows[a].cyclesDelta > rows[b].cyclesDelta;
        }
        return rows[a].tid < rows[b].tid;
    });

    if (ordered.size() < MIN_THREADS_PER_GROUP) {
        return {};
    }

    const size_t groupSize = std::min(ordered.size(), MAX_THREADS_PER_GROUP);

    GroupChunk chunk;
    chunk.symbol = bucket.symbol;
    chunk.module = bucket.module;
    chunk.members.reserve(groupSize);

    for (size_t i = 0; i < groupSize; ++i) {
        chunk.members.push_back(ordered[i]);
        chunk.cyclesDeltaSum += rows[ordered[i]].cyclesDelta;
    }

    if (totalCyclesDelta > 0) {
        chunk.share = Clamp100(static_cast<double>(chunk.cyclesDeltaSum) /
            static_cast<double>(totalCyclesDelta) * 100.0);
    }

    chunk.white = chunk.share >= TOPG_THRESHOLD;
    outChunks.push_back(std::move(chunk));

    if (ordered.size() <= MAX_THREADS_PER_GROUP) {
        return {};
    }

    return std::vector<size_t>(ordered.begin() + MAX_THREADS_PER_GROUP, ordered.end());
}

int wmain() {
    if (!InitNt()) {
        std::wcerr << L"NT init failed\n";
        return 1;
    }

    const std::wstring desktopPath = GetDesktopPath();
    const std::wstring logPath = JoinPath(desktopPath, L"topg_log.txt");
    const std::wstring overflowLogPath = JoinPath(desktopPath, L"topg_overflow_log.txt");

    std::wofstream log(logPath, std::ios::app);
    if (!log.is_open()) {
        std::wcerr << L"log open failed: " << logPath << L"\n";
        return 1;
    }

    std::wofstream overflowLog(overflowLogPath, std::ios::app);
    if (!overflowLog.is_open()) {
        std::wcerr << L"overflow log open failed: " << overflowLogPath << L"\n";
        return 1;
    }

    bool baseline = false;
    DWORD lastForegroundPid = 0;

    log << L"=== TopG detector started " << TimeNow() << L" target=" << TARGET_GAME
        << L" log=" << logPath << L" overflow_log=" << overflowLogPath << L" ===\n";
    overflowLog << L"=== TopG overflow log started " << TimeNow() << L" target=" << TARGET_GAME << L" ===\n";
    log.flush();
    overflowLog.flush();

    std::wcout << L"TopG log: " << logPath << L"\n";
    std::wcout << L"TopG overflow log: " << overflowLogPath << L"\n";

    while (true) {
        std::this_thread::sleep_for(SAMPLE_INTERVAL);

        DWORD foregroundPid = GetForegroundPid();
        if (!foregroundPid) {
            continue;
        }

        if (lastForegroundPid != 0 && foregroundPid != lastForegroundPid) {
            ClearCaches();
            baseline = false;
        }
        lastForegroundPid = foregroundPid;

        std::vector<BYTE> buffer;
        if (!QueryProcesses(buffer)) {
            continue;
        }

        DWORD pid = 0;
        auto* proc = FindGame(buffer, pid);
        if (!proc) {
            continue;
        }

        std::wstring processName = GetProcessName(proc);

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) {
            continue;
        }

        if (!baseline) {
            ClearCaches();

            for (ULONG i = 0; i < proc->NumberOfThreads; ++i) {
                const auto& t = proc->Threads[i];
                DWORD tid = static_cast<DWORD>(reinterpret_cast<uintptr_t>(t.ClientId.UniqueThread));
                g_previous[tid] = { GetThreadCycles(tid) };
            }

            baseline = true;
            CloseHandle(hProcess);
            continue;
        }

        std::vector<ThreadRow> rows;
        rows.reserve(proc->NumberOfThreads);

        std::unordered_set<DWORD> seen;
        ULONGLONG totalCyclesDelta = 0;

        for (ULONG i = 0; i < proc->NumberOfThreads; ++i) {
            const auto& t = proc->Threads[i];
            DWORD tid = static_cast<DWORD>(reinterpret_cast<uintptr_t>(t.ClientId.UniqueThread));
            seen.insert(tid);

            ULONGLONG cyclesNow = GetThreadCycles(tid);
            ULONGLONG cyclesDelta = 0;
            auto it = g_previous.find(tid);
            if (it != g_previous.end() && cyclesNow >= it->second.cycles) {
                cyclesDelta = cyclesNow - it->second.cycles;
            }

            g_previous[tid] = { cyclesNow };
            totalCyclesDelta += cyclesDelta;

            const uintptr_t systemStartAddress = reinterpret_cast<uintptr_t>(t.StartAddress);
            const uintptr_t startAddress = GetThreadWin32StartAddress(tid, systemStartAddress);
            std::wstring module = Trim(QuerySectionName(hProcess, startAddress));
            std::wstring symbol = BuildStartAddressSymbol(hProcess, module, startAddress);

            rows.push_back({ tid, symbol, module, cyclesDelta, 0.0, false, L"" });
        }

        for (auto& r : rows) {
            if (totalCyclesDelta > 0) {
                r.cyclesShare = Clamp100(static_cast<double>(r.cyclesDelta) /
                    static_cast<double>(totalCyclesDelta) * 100.0);
            }
        }

        // Exact grouping by SAME start-address symbol + SAME module only. Thread names/descriptions are not used for grouping.
        std::unordered_map<std::wstring, GroupBucket> buckets;
        buckets.reserve(rows.size());

        for (size_t i = 0; i < rows.size(); ++i) {
            const auto& r = rows[i];

            std::wstring key;
            if (r.symbol == L"-" || r.module == L"-") {
                key = L"__UNRESOLVED__" + std::to_wstring(r.tid);
            }
            else {
                key = r.symbol;
                key.push_back(L'\x1f');
                key += r.module;
            }

            auto& b = buckets[key];
            if (b.members.empty()) {
                b.symbol = r.symbol;
                b.module = r.module;
            }

            b.members.push_back(i);
        }

        std::vector<GroupChunk> chunks;
        chunks.reserve(rows.size());

        std::vector<size_t> overflowMembers;
        for (const auto& kv : buckets) {
            std::vector<size_t> extras = BuildGroupFromBucket(kv.second, rows, totalCyclesDelta, chunks);
            overflowMembers.insert(overflowMembers.end(), extras.begin(), extras.end());
        }

        std::sort(chunks.begin(), chunks.end(), [](const GroupChunk& a, const GroupChunk& b) {
            if (a.white != b.white) {
                return a.white > b.white;
            }
            if (a.share != b.share) {
                return a.share > b.share;
            }
            if (a.symbol != b.symbol) {
                return a.symbol < b.symbol;
            }
            if (a.module != b.module) {
                return a.module < b.module;
            }
            return a.members < b.members;
        });

        size_t groupNo = 1;

        for (auto& chunk : chunks) {
            chunk.groupNo = groupNo++;
            if (chunk.white) {
                chunk.label = L"TopGWhiteWorker/" + std::to_wstring(chunk.groupNo);
                for (size_t idx : chunk.members) {
                    rows[idx].white = true;
                    rows[idx].label = chunk.label;
                    SetThreadName(rows[idx].tid, chunk.label);
                }
            }
            else {
                chunk.label = L"TopGBlackWorker/" + std::to_wstring(chunk.groupNo);
                for (size_t idx : chunk.members) {
                    rows[idx].white = false;
                    rows[idx].label = chunk.label;
                    SetThreadName(rows[idx].tid, chunk.label);
                }
            }
        }

        for (size_t idx : overflowMembers) {
            rows[idx].white = false;
            rows[idx].label = L"TopGBlackWorker/Overflow";
            SetThreadName(rows[idx].tid, rows[idx].label);
        }

        for (auto& row : rows) {
            if (row.label.empty()) {
                row.label = L"TopGBlackWorker/Ungrouped";
                SetThreadName(row.tid, row.label);
            }
        }

        for (auto it = g_previous.begin(); it != g_previous.end();) {
            if (seen.find(it->first) == seen.end()) {
                CloseThreadCacheEntry(it->first);
                it = g_previous.erase(it);
            }
            else {
                ++it;
            }
        }

        std::sort(rows.begin(), rows.end(), [](const ThreadRow& a, const ThreadRow& b) {
            return a.cyclesShare > b.cyclesShare;
        });

        log << L"\n[" << TimeNow() << L"] PID=" << pid << L" Process=" << processName << L"\n";

        log << L"Groups (" << MIN_THREADS_PER_GROUP << L".." << MAX_THREADS_PER_GROUP
            << L" threads per group, same start-address symbol+module):\n";
        for (const auto& c : chunks) {
            log << L"  "
                << (c.white ? L"TopGWhiteWorker" : L"TopGBlackWorker")
                << L" GroupNo=" << c.groupNo
                << L" Label=" << c.label
                << L" Symbol=" << c.symbol
                << L" Module=" << c.module
                << L" CyclesSum=" << c.cyclesDeltaSum
                << L" Share=" << std::fixed << std::setprecision(2) << c.share << L"%"
                << L" Members=" << c.members.size()
                << L"\n";
        }

        if (!overflowMembers.empty()) {
            overflowLog << L"\n[" << TimeNow() << L"] PID=" << pid << L" Process=" << processName
                << L" OverflowThreads=" << overflowMembers.size()
                << L" Reason=more_than_" << MAX_THREADS_PER_GROUP << L"_with_same_symbol_module_not_in_active_group\n";
            for (size_t idx : overflowMembers) {
                const auto& r = rows[idx];
                overflowLog << L"  TID=" << r.tid
                    << L" Symbol=" << r.symbol
                    << L" Module=" << r.module
                    << L" CyclesDelta=" << r.cyclesDelta
                    << L" Share=" << std::fixed << std::setprecision(2) << r.cyclesShare << L"%\n";
            }
            overflowLog.flush();
        }

        log << L"Threads:\n";
        for (const auto& r : rows) {
            log << L"  TID=" << r.tid
                << L" Name=" << (!r.label.empty() ? r.label : r.symbol)
                << L" Symbol=" << r.symbol
                << L" Module=" << r.module
                << L" CyclesDelta=" << r.cyclesDelta
                << L" Share=" << std::fixed << std::setprecision(2) << r.cyclesShare << L"%"
                << L" White=" << (r.white ? L"YES" : L"NO")
                << L"\n";
        }

        log.flush();
        CloseHandle(hProcess);
    }

    return 0;
}
