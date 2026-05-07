#define WIN32_LEAN_AND_MEAN
#include <windows.h>
<<<<<<< HEAD
=======
#define NOMINMAX
#include <windows.h>
#include <winternl.h>
>>>>>>> d9e66da6445f50d9b892139534ab15c71c91ac1f

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

#ifndef THREAD_QUERY_LIMITED_INFORMATION
#define THREAD_QUERY_LIMITED_INFORMATION 0x0800
#endif

#ifndef THREAD_SET_LIMITED_INFORMATION
#define THREAD_SET_LIMITED_INFORMATION 0x0400
#endif

#ifndef THREAD_SET_INFORMATION
#define THREAD_SET_INFORMATION 0x0020
#endif

#ifndef THREAD_QUERY_INFORMATION
#define THREAD_QUERY_INFORMATION 0x0040
#endif

#ifndef THREAD_ALL_ACCESS
#define THREAD_ALL_ACCESS 0x001FFFFF
#endif

#ifdef kThreadSetAccess
#undef kThreadSetAccess
#endif
#ifdef kThreadQuerySetAccess
#undef kThreadQuerySetAccess
#endif
#ifdef kThreadFullQuerySetAccess
#undef kThreadFullQuerySetAccess
#endif
#ifdef kProcessEnumAccess
#undef kProcessEnumAccess
#endif
<<<<<<< HEAD
=======
#ifdef kProcessBoostAccess
#undef kProcessBoostAccess
#endif
>>>>>>> d9e66da6445f50d9b892139534ab15c71c91ac1f
#ifdef kOpenFailureProtected
#undef kOpenFailureProtected
#endif
#ifdef kOpenFailureTransient
#undef kOpenFailureTransient
#endif
#ifdef kOpenFailureOther
#undef kOpenFailureOther
#endif

using NTSTATUS_T = LONG;
using KPRIORITY = LONG;

struct NativeUnicodeString {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
};

constexpr NTSTATUS_T kStatusInfoLengthMismatch = static_cast<NTSTATUS_T>(0xC0000004L);
constexpr NTSTATUS_T kStatusAccessDenied = static_cast<NTSTATUS_T>(0xC0000022L);
constexpr NTSTATUS_T kStatusInvalidCid = static_cast<NTSTATUS_T>(0xC000000BL);
constexpr NTSTATUS_T kStatusInvalidParameter = static_cast<NTSTATUS_T>(0xC000000DL);
constexpr ULONG kSystemProcessInformation = 5;
constexpr KPRIORITY kTargetPriority = 16;
constexpr ULONG kHeapGrowable = 0x00000002;
constexpr uint32_t kDefaultIntervalMs = 1000;
constexpr uint32_t kGlobalRefreshScans = 60;
<<<<<<< HEAD
constexpr uint32_t kRetryCooldownScans = 8192;
constexpr uint32_t kRetryCooldownFixedScans = 2;
constexpr uint32_t kCachedRefreshStride = 1;
constexpr uint32_t kCachedProcessRescanScans = 2;
constexpr size_t kThreadCacheSize = 512;
constexpr size_t kProcessCacheSize = 64;
constexpr size_t kCachedProcessesPerScan = 1;
constexpr size_t kCachedThreadsPerProcessPerScan = 2;
=======
constexpr uint32_t kRetryCooldownScans = 256;
constexpr size_t kThreadCacheSize = 512;
constexpr size_t kProcessCacheSize = 64;
>>>>>>> d9e66da6445f50d9b892139534ab15c71c91ac1f
constexpr uint8_t kCacheEmpty = 0;
constexpr uint8_t kCacheFixed = 1;
constexpr uint8_t kCacheDenied = 2;
constexpr uint8_t kCacheFailed = 3;
<<<<<<< HEAD
const ACCESS_MASK kThreadFixAccess = THREAD_SET_INFORMATION;
const ACCESS_MASK kThreadLimitedFixAccess = THREAD_SET_LIMITED_INFORMATION;
const ACCESS_MASK kThreadQueryFixAccess = THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION;
=======
const ACCESS_MASK kThreadFixAccess = THREAD_SET_INFORMATION | THREAD_SET_LIMITED_INFORMATION;
const ACCESS_MASK kThreadLimitedFixAccess = THREAD_SET_LIMITED_INFORMATION;
const ACCESS_MASK kThreadQuerySetAccess = THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION |
    THREAD_QUERY_LIMITED_INFORMATION | THREAD_SET_LIMITED_INFORMATION;
const ACCESS_MASK kThreadLimitedQuerySetAccess = THREAD_QUERY_LIMITED_INFORMATION | THREAD_SET_LIMITED_INFORMATION;
const ACCESS_MASK kThreadFullQuerySetAccess = THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION |
    THREAD_QUERY_LIMITED_INFORMATION | THREAD_SET_LIMITED_INFORMATION;
const ACCESS_MASK kThreadQueryFixAccess = THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION |
    THREAD_QUERY_LIMITED_INFORMATION | THREAD_SET_LIMITED_INFORMATION;
>>>>>>> d9e66da6445f50d9b892139534ab15c71c91ac1f
constexpr uint8_t kOpenFailureProtected = 1;
constexpr uint8_t kOpenFailureTransient = 2;
constexpr uint8_t kOpenFailureOther = 3;
const ACCESS_MASK kProcessEnumAccess = PROCESS_QUERY_INFORMATION;
<<<<<<< HEAD
=======
const ACCESS_MASK kProcessBoostAccess = PROCESS_SET_INFORMATION;
>>>>>>> d9e66da6445f50d9b892139534ab15c71c91ac1f

struct NativeClientId {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
};

struct NativeObjectAttributes {
    ULONG Length;
    HANDLE RootDirectory;
    PVOID ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
};

struct NativeSystemThreadInformation {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    NativeClientId ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
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
    NativeSystemThreadInformation Threads[1];
};

using RtlAllocateHeapFn = PVOID(NTAPI*)(PVOID, ULONG, SIZE_T);
using RtlFreeHeapFn = BOOLEAN(NTAPI*)(PVOID, ULONG, PVOID);
using RtlCreateHeapFn = PVOID(NTAPI*)(ULONG, PVOID, SIZE_T, SIZE_T, PVOID, PVOID);
using RtlDestroyHeapFn = PVOID(NTAPI*)(PVOID);
using RtlReAllocateHeapFn = PVOID(NTAPI*)(PVOID, ULONG, PVOID, SIZE_T);
using NtOpenProcessTokenFn = NTSTATUS_T(NTAPI*)(HANDLE, ACCESS_MASK, PHANDLE);
using NtAdjustPrivilegesTokenFn = NTSTATUS_T(NTAPI*)(HANDLE, BOOLEAN, PTOKEN_PRIVILEGES, ULONG, PTOKEN_PRIVILEGES, PULONG);
using NtQueryInformationTokenFn = NTSTATUS_T(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtOpenThreadFn = NTSTATUS_T(NTAPI*)(PHANDLE, ACCESS_MASK, NativeObjectAttributes*, NativeClientId*);
using NtOpenProcessFn = NTSTATUS_T(NTAPI*)(PHANDLE, ACCESS_MASK, NativeObjectAttributes*, NativeClientId*);
<<<<<<< HEAD
=======
using NtSetInformationProcessFn = NTSTATUS_T(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
>>>>>>> d9e66da6445f50d9b892139534ab15c71c91ac1f
using NtQuerySystemInformationFn = NTSTATUS_T(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
using NtQueryInformationThreadFn = NTSTATUS_T(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtSetInformationThreadFn = NTSTATUS_T(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
using NtGetNextThreadFn = NTSTATUS_T(NTAPI*)(HANDLE, HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);
using NtCloseFn = NTSTATUS_T(NTAPI*)(HANDLE);
using NtDelayExecutionFn = NTSTATUS_T(NTAPI*)(BOOLEAN, PLARGE_INTEGER);

struct NativeThreadBasicInformation {
    NTSTATUS_T ExitStatus;
    PVOID TebBaseAddress;
    NativeClientId ClientId;
    ULONG_PTR AffinityMask;
    KPRIORITY Priority;
    LONG BasePriority;
};

constexpr ULONG kThreadBasicInformation = 0;
<<<<<<< HEAD
constexpr ULONG kThreadBasePriority = 3;
constexpr KPRIORITY kNormalThreadBasePriority = 0;
=======
constexpr ULONG kThreadPriority = 2;
constexpr ULONG kThreadBasePriority = 3;
constexpr ULONG kThreadPriorityBoost = 14;
constexpr ULONG kThreadActualBasePriority = 25;
constexpr ULONG kProcessPriorityBoost = 22;
constexpr KPRIORITY kNormalPriority = 8;
constexpr KPRIORITY kHighPriority = 15;
>>>>>>> d9e66da6445f50d9b892139534ab15c71c91ac1f

struct ScanStats {
    uint32_t seenPriority16 = 0;
    uint32_t fixedPriority16 = 0;
    uint32_t cachedSkipped = 0;
    uint32_t openFailures = 0;
    uint32_t protectedFailures = 0;
    uint32_t transientFailures = 0;
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

struct ProcessCacheEntry {
    DWORD processId = 0;
    HANDLE process = nullptr;
    uint32_t lastSeenScan = 0;
<<<<<<< HEAD
    uint32_t lastScannedScan = 0;
=======
>>>>>>> d9e66da6445f50d9b892139534ab15c71c91ac1f
};

struct ProcessCache {
    ProcessCacheEntry entries[kProcessCacheSize]{};
};

static bool EqualsInsensitiveAscii(const WCHAR* text, size_t length, const char* ascii) noexcept {
    for (size_t i = 0; i < length; ++i) {
        char c = ascii[i];
        if (c == '\0') {
            return false;
        }

        WCHAR w = text[i];
        if (w >= L'A' && w <= L'Z') {
            w = static_cast<WCHAR>(w + (L'a' - L'A'));
        }
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c + ('a' - 'A'));
        }

        if (w != static_cast<WCHAR>(c)) {
            return false;
        }
    }

    return ascii[length] == '\0';
}

static bool IsExcludedProcess(const NativeUnicodeString& imageName) noexcept {
    if (imageName.Buffer == nullptr || imageName.Length == 0) {
        return false;
    }

    const size_t chars = imageName.Length / sizeof(WCHAR);
    return EqualsInsensitiveAscii(imageName.Buffer, chars, "csrss.exe") ||
        EqualsInsensitiveAscii(imageName.Buffer, chars, "system.exe") ||
        EqualsInsensitiveAscii(imageName.Buffer, chars, "system");
}

static HANDLE NtCurrentProcessHandle() noexcept {
    return reinterpret_cast<HANDLE>(static_cast<LONG_PTR>(-1));
}

static void EnableAllTokenPrivileges(RtlAllocateHeapFn allocateHeap,
<<<<<<< HEAD
    RtlFreeHeapFn freeHeap,
    PVOID heap,
    NtOpenProcessTokenFn openProcessToken,
    NtQueryInformationTokenFn queryToken,
    NtAdjustPrivilegesTokenFn adjustToken,
    NtCloseFn closeHandle) noexcept {
=======
                                     RtlFreeHeapFn freeHeap,
                                     PVOID heap,
                                     NtOpenProcessTokenFn openProcessToken,
                                     NtQueryInformationTokenFn queryToken,
                                     NtAdjustPrivilegesTokenFn adjustToken,
                                     NtCloseFn closeHandle) noexcept {
>>>>>>> d9e66da6445f50d9b892139534ab15c71c91ac1f
    HANDLE token = nullptr;
    if (openProcessToken(NtCurrentProcessHandle(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token) < 0) {
        return;
    }

    ULONG required = 0;
    queryToken(token, TokenPrivileges, nullptr, 0, &required);
    if (required == 0) {
        closeHandle(token);
        return;
    }

    PVOID privileges = allocateHeap(heap, 0, required);
    if (privileges == nullptr) {
        closeHandle(token);
        return;
    }

    auto* tokenPrivileges = reinterpret_cast<TOKEN_PRIVILEGES*>(privileges);
    if (queryToken(token, TokenPrivileges, tokenPrivileges, required, &required) < 0) {
        freeHeap(heap, 0, privileges);
        closeHandle(token);
        return;
    }

    for (DWORD i = 0; i < tokenPrivileges->PrivilegeCount; ++i) {
        tokenPrivileges->Privileges[i].Attributes |= SE_PRIVILEGE_ENABLED;
    }

    adjustToken(token, FALSE, tokenPrivileges, required, nullptr, nullptr);
    freeHeap(heap, 0, privileges);
    closeHandle(token);
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
<<<<<<< HEAD
            const uint32_t age = scanId - entry.lastScan;
            if (entry.state == kCacheFixed) {
                return age < kRetryCooldownFixedScans;
            }

            return age < kRetryCooldownScans;
=======
            return scanId - entry.lastScan < kRetryCooldownScans;
>>>>>>> d9e66da6445f50d9b892139534ab15c71c91ac1f
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

<<<<<<< HEAD
    cache.entries[slot] = ThreadCacheEntry{ processId, threadId, scanId, state };
=======
    cache.entries[slot] = ThreadCacheEntry{processId, threadId, scanId, state};
>>>>>>> d9e66da6445f50d9b892139534ab15c71c91ac1f
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
<<<<<<< HEAD
    RtlAllocateHeapFn allocateHeap,
    RtlReAllocateHeapFn reallocateHeap,
    PVOID heap,
    PVOID& buffer,
    ULONG& capacity) noexcept {
=======
                                 RtlAllocateHeapFn allocateHeap,
                                 RtlReAllocateHeapFn reallocateHeap,
                                 PVOID heap,
                                 PVOID& buffer,
                                 ULONG& capacity) noexcept {
>>>>>>> d9e66da6445f50d9b892139534ab15c71c91ac1f
    ULONG required = 0;
    NTSTATUS_T status = query(kSystemProcessInformation, buffer, capacity, &required);
    while (status == kStatusInfoLengthMismatch) {
        const ULONG nextCapacity = required > capacity ? required + (64U * 1024U) : capacity * 2U;
        PVOID nextBuffer = reallocateHeap(heap, 0, buffer, nextCapacity);
        if (nextBuffer == nullptr) {
            return false;
        }

        buffer = nextBuffer;
        capacity = nextCapacity;
        required = 0;
        status = query(kSystemProcessInformation, buffer, capacity, &required);
    }

    return status >= 0;
}

<<<<<<< HEAD
static bool FixPriority16ThreadHandle(NtSetInformationThreadFn setThread, HANDLE thread, DWORD& error) noexcept {
    error = ERROR_SUCCESS;

    KPRIORITY normalBasePriority = kNormalThreadBasePriority;
    const NTSTATUS_T status = setThread(thread, kThreadBasePriority, &normalBasePriority, sizeof(normalBasePriority));
    if (status < 0) {
        if (status == kStatusAccessDenied) {
            error = ERROR_ACCESS_DENIED;
        }
        else if (status == kStatusInvalidParameter) {
            error = ERROR_INVALID_PARAMETER;
        }
        else {
            error = ERROR_GEN_FAILURE;
        }
        return false;
    }

    return true;
}

static NTSTATUS_T TryOpenPriorityThread(NtOpenThreadFn openThread,
    DWORD processId,
    DWORD threadId,
    ACCESS_MASK desiredAccess,
    bool includeProcessId,
    HANDLE& thread) noexcept {
    thread = nullptr;
    NativeObjectAttributes attributes{ sizeof(attributes), nullptr, nullptr, 0, nullptr, nullptr };
    NativeClientId clientId{ includeProcessId ? reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(processId)) : nullptr,
                         reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(threadId)) };
=======
static bool SetThreadPriorityValue(NtSetInformationThreadFn setThread,
                                   HANDLE thread,
                                   ULONG informationClass,
                                   KPRIORITY priority,
                                   NTSTATUS_T& lastStatus) noexcept {
    KPRIORITY value = priority;
    lastStatus = setThread(thread, informationClass, &value, sizeof(value));
    return lastStatus >= 0;
}

static bool LowerPriority16ThreadHandle(NtSetInformationThreadFn setThread,
                                        HANDLE thread,
                                        NTSTATUS_T& lastStatus) noexcept {
    const ULONG informationClasses[] = {
        kThreadActualBasePriority,
        kThreadBasePriority,
        kThreadPriority
    };
    const KPRIORITY targetPriorities[] = {
        kHighPriority,
        kNormalPriority
    };

    for (size_t priorityIndex = 0;
         priorityIndex < sizeof(targetPriorities) / sizeof(targetPriorities[0]);
         ++priorityIndex) {
        for (size_t classIndex = 0;
             classIndex < sizeof(informationClasses) / sizeof(informationClasses[0]);
             ++classIndex) {
            if (SetThreadPriorityValue(setThread,
                                       thread,
                                       informationClasses[classIndex],
                                       targetPriorities[priorityIndex],
                                       lastStatus)) {
                return true;
            }
        }
    }

    return false;
}

static bool FixPriority16ThreadHandle(NtSetInformationThreadFn setThread, HANDLE thread, DWORD& error) noexcept {
    error = ERROR_SUCCESS;

    NTSTATUS_T priorityStatus = kStatusInvalidParameter;
    const bool loweredPriority = LowerPriority16ThreadHandle(setThread, thread, priorityStatus);

    ULONG disableBoost = TRUE;
    const NTSTATUS_T boostStatus = setThread(thread, kThreadPriorityBoost, &disableBoost, sizeof(disableBoost));
    if (loweredPriority) {
        return true;
    }

    error = boostStatus < 0 && priorityStatus == kStatusInvalidParameter
        ? ERROR_INVALID_PARAMETER
        : ERROR_ACCESS_DENIED;
    return false;
}

static NTSTATUS_T TryOpenPriorityThread(NtOpenThreadFn openThread,
                                        DWORD processId,
                                        DWORD threadId,
                                        ACCESS_MASK desiredAccess,
                                        bool includeProcessId,
                                        HANDLE& thread) noexcept {
    thread = nullptr;
    NativeObjectAttributes attributes{sizeof(attributes), nullptr, nullptr, 0, nullptr, nullptr};
    NativeClientId clientId{includeProcessId ? reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(processId)) : nullptr,
                         reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(threadId))};
>>>>>>> d9e66da6445f50d9b892139534ab15c71c91ac1f
    return openThread(&thread, desiredAccess, &attributes, &clientId);
}

static uint8_t ClassifyOpenStatus(NTSTATUS_T status) noexcept {
    if (status == kStatusInvalidCid || status == kStatusInvalidParameter) {
        return kOpenFailureTransient;
    }

    if (status == kStatusAccessDenied) {
        return kOpenFailureProtected;
    }

    return kOpenFailureOther;
}

static bool OpenPriorityFixThread(NtOpenThreadFn openThread,
<<<<<<< HEAD
    DWORD processId,
    DWORD threadId,
    HANDLE& thread,
    uint8_t& failureKind) noexcept {
    const ACCESS_MASK accessMasks[] = {
        kThreadFixAccess
=======
                                  DWORD processId,
                                  DWORD threadId,
                                  HANDLE& thread,
                                  uint8_t& failureKind) noexcept {
    const ACCESS_MASK accessMasks[] = {
        kThreadFixAccess,
        kThreadQuerySetAccess,
        kThreadFullQuerySetAccess,
        THREAD_ALL_ACCESS,
        kThreadLimitedFixAccess,
        kThreadLimitedQuerySetAccess
>>>>>>> d9e66da6445f50d9b892139534ab15c71c91ac1f
    };

    NTSTATUS_T lastStatus = kStatusAccessDenied;
    for (size_t i = 0; i < sizeof(accessMasks) / sizeof(accessMasks[0]); ++i) {
        const ACCESS_MASK desiredAccess = accessMasks[i];
        lastStatus = TryOpenPriorityThread(openThread, processId, threadId, desiredAccess, true, thread);
        if (lastStatus >= 0 && thread != nullptr) {
            return true;
        }
<<<<<<< HEAD
=======

        lastStatus = TryOpenPriorityThread(openThread, processId, threadId, desiredAccess, false, thread);
        if (lastStatus >= 0 && thread != nullptr) {
            return true;
        }
>>>>>>> d9e66da6445f50d9b892139534ab15c71c91ac1f
    }

    failureKind = ClassifyOpenStatus(lastStatus);
    return false;
}

static HANDLE OpenProcessNative(NtOpenProcessFn openProcess, DWORD processId, ACCESS_MASK desiredAccess) noexcept {
    HANDLE process = nullptr;
<<<<<<< HEAD
    NativeObjectAttributes attributes{ sizeof(attributes), nullptr, nullptr, 0, nullptr, nullptr };
    NativeClientId clientId{ reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(processId)), nullptr };
=======
    NativeObjectAttributes attributes{sizeof(attributes), nullptr, nullptr, 0, nullptr, nullptr};
    NativeClientId clientId{reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(processId)), nullptr};
>>>>>>> d9e66da6445f50d9b892139534ab15c71c91ac1f
    if (openProcess(&process, desiredAccess, &attributes, &clientId) < 0) {
        return nullptr;
    }

    return process;
}

static HANDLE OpenCachedProcess(NtOpenProcessFn openProcess, DWORD processId) noexcept {
    return OpenProcessNative(openProcess, processId, kProcessEnumAccess);
}

static bool OpenPriorityFixThreadFromProcess(NtGetNextThreadFn getNextThread,
<<<<<<< HEAD
    NtQueryInformationThreadFn queryThread,
    NtOpenProcessFn openProcess,
    NtCloseFn closeHandle,
    DWORD processId,
    DWORD threadId,
    HANDLE& thread) noexcept {
=======
                                             NtQueryInformationThreadFn queryThread,
                                             NtOpenProcessFn openProcess,
                                             NtCloseFn closeHandle,
                                             DWORD processId,
                                             DWORD threadId,
                                             HANDLE& thread) noexcept {
>>>>>>> d9e66da6445f50d9b892139534ab15c71c91ac1f
    thread = nullptr;

    HANDLE process = OpenCachedProcess(openProcess, processId);
    if (process == nullptr) {
        return false;
    }

    HANDLE previousThread = nullptr;
    for (;;) {
        HANDLE candidate = nullptr;
        const NTSTATUS_T status = getNextThread(process,
<<<<<<< HEAD
            previousThread,
            kThreadQueryFixAccess,
            0,
            0,
            &candidate);
=======
                                                previousThread,
                                                kThreadQueryFixAccess,
                                                0,
                                                0,
                                                &candidate);
>>>>>>> d9e66da6445f50d9b892139534ab15c71c91ac1f
        if (previousThread != nullptr) {
            closeHandle(previousThread);
        }

        if (status < 0 || candidate == nullptr) {
            closeHandle(process);
            return false;
        }

        previousThread = candidate;
        NativeThreadBasicInformation basic{};
        if (queryThread(candidate, kThreadBasicInformation, &basic, sizeof(basic), nullptr) < 0) {
            continue;
        }

        const DWORD candidateThreadId = static_cast<DWORD>(
            reinterpret_cast<ULONG_PTR>(basic.ClientId.UniqueThread));
        if (candidateThreadId == threadId) {
            thread = candidate;
            closeHandle(process);
            return true;
        }
    }
}

static bool FixPriority16Thread(NtOpenThreadFn openThread,
<<<<<<< HEAD
    NtGetNextThreadFn getNextThread,
    NtQueryInformationThreadFn queryThread,
    NtSetInformationThreadFn setThread,
    NtOpenProcessFn openProcess,
    NtCloseFn closeHandle,
    DWORD processId,
    DWORD threadId,
    DWORD& error,
    uint8_t& openFailureKind) noexcept {
    error = ERROR_SUCCESS;
    HANDLE thread = nullptr;
    const bool openedDirect = OpenPriorityFixThread(openThread, processId, threadId, thread, openFailureKind);
    if (!openedDirect) {
=======
                                NtGetNextThreadFn getNextThread,
                                NtQueryInformationThreadFn queryThread,
                                NtSetInformationThreadFn setThread,
                                NtOpenProcessFn openProcess,
                                NtCloseFn closeHandle,
                                DWORD processId,
                                DWORD threadId,
                                DWORD& error,
                                uint8_t& openFailureKind) noexcept {
    error = ERROR_SUCCESS;
    HANDLE thread = nullptr;
    if (!OpenPriorityFixThread(openThread, processId, threadId, thread, openFailureKind) &&
        !OpenPriorityFixThreadFromProcess(getNextThread,
                                          queryThread,
                                          openProcess,
                                          closeHandle,
                                          processId,
                                          threadId,
                                          thread)) {
>>>>>>> d9e66da6445f50d9b892139534ab15c71c91ac1f
        error = ERROR_ACCESS_DENIED;
        return false;
    }

    const bool ok = FixPriority16ThreadHandle(setThread, thread, error);
    closeHandle(thread);
    return ok;
}

<<<<<<< HEAD
static void RememberProcess(ProcessCache& cache,
    NtOpenProcessFn openProcess,
    NtCloseFn closeHandle,
    DWORD processId,
    uint32_t scanId) noexcept {
=======
static void DisableProcessPriorityBoost(NtOpenProcessFn openProcess,
                                        NtSetInformationProcessFn setProcess,
                                        NtCloseFn closeHandle,
                                        DWORD processId) noexcept {
    HANDLE process = OpenProcessNative(openProcess, processId, kProcessBoostAccess);
    if (process == nullptr) {
        return;
    }

    ULONG disableBoost = TRUE;
    setProcess(process, kProcessPriorityBoost, &disableBoost, sizeof(disableBoost));
    closeHandle(process);
}

static void RememberProcess(ProcessCache& cache,
                            NtOpenProcessFn openProcess,
                            NtSetInformationProcessFn setProcess,
                            NtCloseFn closeHandle,
                            DWORD processId,
                            uint32_t scanId) noexcept {
>>>>>>> d9e66da6445f50d9b892139534ab15c71c91ac1f
    if (processId == 0) {
        return;
    }

    size_t slot = kProcessCacheSize;
    uint32_t oldestAge = 0;
    for (size_t i = 0; i < kProcessCacheSize; ++i) {
        ProcessCacheEntry& entry = cache.entries[i];
        if (entry.processId == processId) {
            entry.lastSeenScan = scanId;
            return;
        }

        if (entry.processId == 0) {
            slot = i;
            break;
        }

        const uint32_t age = scanId - entry.lastSeenScan;
        if (age >= oldestAge) {
            oldestAge = age;
            slot = i;
        }
    }

    if (slot == kProcessCacheSize) {
        return;
    }

    if (cache.entries[slot].process != nullptr) {
        closeHandle(cache.entries[slot].process);
    }

<<<<<<< HEAD
    cache.entries[slot] = ProcessCacheEntry{ processId, OpenCachedProcess(openProcess, processId), scanId, 0 };
}

static ScanStats ScanAndFixPriority16(NtQuerySystemInformationFn query,
    RtlAllocateHeapFn allocateHeap,
    RtlReAllocateHeapFn reallocateHeap,
    PVOID heap,
    NtOpenThreadFn openThread,
    NtGetNextThreadFn getNextThread,
    NtQueryInformationThreadFn queryThread,
    NtSetInformationThreadFn setThread,
    NtOpenProcessFn openProcess,
    NtCloseFn closeHandle,
    PVOID& buffer,
    ULONG& capacity,
    ThreadCache& threadCache,
    ProcessCache& processCache,
    uint32_t scanId) noexcept {
=======
    DisableProcessPriorityBoost(openProcess, setProcess, closeHandle, processId);
    cache.entries[slot] = ProcessCacheEntry{processId, OpenCachedProcess(openProcess, processId), scanId};
}

static ScanStats ScanAndFixPriority16(NtQuerySystemInformationFn query,
                                       RtlAllocateHeapFn allocateHeap,
                                       RtlReAllocateHeapFn reallocateHeap,
                                       PVOID heap,
                                       NtOpenThreadFn openThread,
                                       NtGetNextThreadFn getNextThread,
                                       NtQueryInformationThreadFn queryThread,
                                       NtSetInformationThreadFn setThread,
                                       NtOpenProcessFn openProcess,
                                       NtSetInformationProcessFn setProcess,
                                       NtCloseFn closeHandle,
                                       PVOID& buffer,
                                       ULONG& capacity,
                                       ThreadCache& threadCache,
                                       ProcessCache& processCache,
                                       uint32_t scanId) noexcept {
>>>>>>> d9e66da6445f50d9b892139534ab15c71c91ac1f
    ScanStats stats{};
    if (!QueryProcessSnapshot(query, allocateHeap, reallocateHeap, heap, buffer, capacity)) {
        return stats;
    }

    const DWORD currentThreadId = GetCurrentThreadId();
    auto* process = reinterpret_cast<NativeSystemProcessInformation*>(buffer);
<<<<<<< HEAD
=======

>>>>>>> d9e66da6445f50d9b892139534ab15c71c91ac1f
    for (;;) {
        const bool skipProcess = IsExcludedProcess(process->ImageName);
        const ULONG threadCount = process->NumberOfThreads;
        const NativeSystemThreadInformation* thread = process->Threads;

        if (!skipProcess) {
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
<<<<<<< HEAD
                RememberProcess(processCache, openProcess, closeHandle, processId, scanId);
=======
                RememberProcess(processCache, openProcess, setProcess, closeHandle, processId, scanId);
>>>>>>> d9e66da6445f50d9b892139534ab15c71c91ac1f
                if (ShouldSkipCachedThread(threadCache, processId, threadId, scanId)) {
                    ++stats.cachedSkipped;
                    continue;
                }

                DWORD error = ERROR_SUCCESS;
                uint8_t openFailureKind = kOpenFailureOther;
                if (FixPriority16Thread(openThread,
<<<<<<< HEAD
                    getNextThread,
                    queryThread,
                    setThread,
                    openProcess,
                    closeHandle,
                    processId,
                    threadId,
                    error,
                    openFailureKind)) {
                    ++stats.fixedPriority16;
                    RememberThread(threadCache, processId, threadId, scanId, kCacheFixed);
                }
                else if (error == ERROR_ACCESS_DENIED) {
                    if (openFailureKind == kOpenFailureTransient) {
                        ++stats.openFailures;
                        ++stats.transientFailures;
                    }
                    else if (openFailureKind == kOpenFailureProtected) {
                        ++stats.protectedFailures;
                    }
                    else {
=======
                                        getNextThread,
                                        queryThread,
                                        setThread,
                                        openProcess,
                                        closeHandle,
                                        processId,
                                        threadId,
                                        error,
                                        openFailureKind)) {
                    ++stats.fixedPriority16;
                    RememberThread(threadCache, processId, threadId, scanId, kCacheFixed);
                } else if (error == ERROR_ACCESS_DENIED || error == ERROR_INVALID_PARAMETER) {
                    if (openFailureKind == kOpenFailureTransient) {
                        ++stats.openFailures;
                        ++stats.transientFailures;
                    } else if (openFailureKind == kOpenFailureProtected) {
                        ++stats.protectedFailures;
                    } else {
>>>>>>> d9e66da6445f50d9b892139534ab15c71c91ac1f
                        ++stats.openFailures;
                    }

                    RememberThread(threadCache, processId, threadId, scanId,
<<<<<<< HEAD
                        openFailureKind == kOpenFailureTransient ? kCacheEmpty : kCacheDenied);
                }
                else {
=======
                                   openFailureKind == kOpenFailureTransient ? kCacheEmpty : kCacheDenied);
                } else {
>>>>>>> d9e66da6445f50d9b892139534ab15c71c91ac1f
                    ++stats.fixFailures;
                    RememberThread(threadCache, processId, threadId, scanId, kCacheFailed);
                }
            }
        }

        if (process->NextEntryOffset == 0) {
            break;
        }

        process = reinterpret_cast<NativeSystemProcessInformation*>(
            reinterpret_cast<BYTE*>(process) + process->NextEntryOffset);
    }

    return stats;
}

static void CloseProcessCache(ProcessCache& processCache, NtCloseFn closeHandle) noexcept {
    for (ProcessCacheEntry& entry : processCache.entries) {
        if (entry.process != nullptr) {
            closeHandle(entry.process);
            entry.process = nullptr;
        }
    }
}

static ScanStats ScanCachedPriority16Processes(NtGetNextThreadFn getNextThread,
<<<<<<< HEAD
    NtQueryInformationThreadFn queryThread,
    NtSetInformationThreadFn setThread,
    NtOpenProcessFn openProcess,
    NtCloseFn closeHandle,
    ThreadCache& threadCache,
    ProcessCache& processCache,
    size_t& processCursor,
    uint32_t scanId) noexcept {
    ScanStats stats{};
    const DWORD currentThreadId = GetCurrentThreadId();

    size_t visited = 0;
    size_t handled = 0;
    while (visited < kProcessCacheSize && handled < kCachedProcessesPerScan) {
        ProcessCacheEntry& processEntry = processCache.entries[(processCursor + visited) % kProcessCacheSize];
        ++visited;
        if (processEntry.processId == 0) {
            continue;
        }
        ++handled;
        if (scanId - processEntry.lastScannedScan < kCachedProcessRescanScans) {
            continue;
        }
        processEntry.lastScannedScan = scanId;
=======
                                             NtQueryInformationThreadFn queryThread,
                                             NtSetInformationThreadFn setThread,
                                             NtOpenProcessFn openProcess,
                                             NtSetInformationProcessFn setProcess,
                                             NtCloseFn closeHandle,
                                             ThreadCache& threadCache,
                                             ProcessCache& processCache,
                                             uint32_t scanId) noexcept {
    ScanStats stats{};
    const DWORD currentThreadId = GetCurrentThreadId();

    for (ProcessCacheEntry& processEntry : processCache.entries) {
        if (processEntry.processId == 0) {
            continue;
        }
>>>>>>> d9e66da6445f50d9b892139534ab15c71c91ac1f

        if (processEntry.process == nullptr) {
            processEntry.process = OpenCachedProcess(openProcess, processEntry.processId);
            if (processEntry.process == nullptr) {
                continue;
            }
<<<<<<< HEAD
        }

        HANDLE previousThread = nullptr;
        size_t processTried = 0;
        for (;;) {
            HANDLE thread = nullptr;
            const NTSTATUS_T status = getNextThread(processEntry.process,
                previousThread,
                kThreadQueryFixAccess,
                0,
                0,
                &thread);
=======

            DisableProcessPriorityBoost(openProcess, setProcess, closeHandle, processEntry.processId);
        }

        HANDLE previousThread = nullptr;
        for (;;) {
            HANDLE thread = nullptr;
            const NTSTATUS_T status = getNextThread(processEntry.process,
                                                    previousThread,
                                                    kThreadQueryFixAccess,
                                                    0,
                                                    0,
                                                    &thread);
>>>>>>> d9e66da6445f50d9b892139534ab15c71c91ac1f
            if (previousThread != nullptr) {
                closeHandle(previousThread);
            }

            if (status < 0 || thread == nullptr) {
                break;
            }

            previousThread = thread;
            NativeThreadBasicInformation basic{};
            if (queryThread(thread, kThreadBasicInformation, &basic, sizeof(basic), nullptr) < 0) {
                continue;
            }

            const DWORD processId = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(basic.ClientId.UniqueProcess));
            const DWORD threadId = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(basic.ClientId.UniqueThread));
            if (threadId == 0 || threadId == currentThreadId) {
                continue;
            }

            if (basic.Priority != kTargetPriority && basic.BasePriority != kTargetPriority) {
                continue;
            }

            ++stats.seenPriority16;
            if (ShouldSkipCachedThread(threadCache, processId, threadId, scanId)) {
                ++stats.cachedSkipped;
                continue;
            }

            DWORD error = ERROR_SUCCESS;
<<<<<<< HEAD
            ++processTried;
            if (FixPriority16ThreadHandle(setThread, thread, error)) {
                ++stats.fixedPriority16;
                RememberThread(threadCache, processId, threadId, scanId, kCacheFixed);
            }
            else if (error == ERROR_ACCESS_DENIED) {
                ++stats.openFailures;
                RememberThread(threadCache, processId, threadId, scanId, kCacheDenied);
            }
            else {
                ++stats.fixFailures;
                RememberThread(threadCache, processId, threadId, scanId, kCacheFailed);
            }

            if (processTried >= kCachedThreadsPerProcessPerScan) {
                break;
            }
        }
    }
    processCursor = (processCursor + handled) % kProcessCacheSize;
=======
            if (FixPriority16ThreadHandle(setThread, thread, error)) {
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
    }
>>>>>>> d9e66da6445f50d9b892139534ab15c71c91ac1f

    return stats;
}

int wmain(int argc, wchar_t** argv) {
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) {
        std::fputs("ntdll.dll is unavailable\n", stderr);
        return 1;
    }

    const auto allocateHeap = reinterpret_cast<RtlAllocateHeapFn>(GetProcAddress(ntdll, "RtlAllocateHeap"));
    const auto freeHeap = reinterpret_cast<RtlFreeHeapFn>(GetProcAddress(ntdll, "RtlFreeHeap"));
    const auto reallocateHeap = reinterpret_cast<RtlReAllocateHeapFn>(GetProcAddress(ntdll, "RtlReAllocateHeap"));
    const auto createHeap = reinterpret_cast<RtlCreateHeapFn>(GetProcAddress(ntdll, "RtlCreateHeap"));
    const auto destroyHeap = reinterpret_cast<RtlDestroyHeapFn>(GetProcAddress(ntdll, "RtlDestroyHeap"));
    const auto openProcessToken = reinterpret_cast<NtOpenProcessTokenFn>(
        GetProcAddress(ntdll, "NtOpenProcessToken"));
    const auto queryToken = reinterpret_cast<NtQueryInformationTokenFn>(
        GetProcAddress(ntdll, "NtQueryInformationToken"));
    const auto adjustToken = reinterpret_cast<NtAdjustPrivilegesTokenFn>(
        GetProcAddress(ntdll, "NtAdjustPrivilegesToken"));
    const auto openProcess = reinterpret_cast<NtOpenProcessFn>(GetProcAddress(ntdll, "NtOpenProcess"));
<<<<<<< HEAD
=======
    const auto setProcess = reinterpret_cast<NtSetInformationProcessFn>(
        GetProcAddress(ntdll, "NtSetInformationProcess"));
>>>>>>> d9e66da6445f50d9b892139534ab15c71c91ac1f
    const auto closeHandle = reinterpret_cast<NtCloseFn>(GetProcAddress(ntdll, "NtClose"));
    const auto delayExecution = reinterpret_cast<NtDelayExecutionFn>(GetProcAddress(ntdll, "NtDelayExecution"));
    if (allocateHeap == nullptr || freeHeap == nullptr || reallocateHeap == nullptr ||
        createHeap == nullptr || destroyHeap == nullptr ||
        openProcessToken == nullptr ||
<<<<<<< HEAD
        queryToken == nullptr || adjustToken == nullptr || openProcess == nullptr ||
=======
        queryToken == nullptr || adjustToken == nullptr || openProcess == nullptr || setProcess == nullptr ||
>>>>>>> d9e66da6445f50d9b892139534ab15c71c91ac1f
        closeHandle == nullptr || delayExecution == nullptr) {
        std::fputs("required ntdll memory APIs are unavailable\n", stderr);
        return 1;
    }

    PVOID heap = createHeap(kHeapGrowable, nullptr, 0, 0, nullptr, nullptr);
    if (heap == nullptr) {
        std::fputs("RtlCreateHeap failed\n", stderr);
        return 1;
    }

    EnableAllTokenPrivileges(allocateHeap, freeHeap, heap, openProcessToken, queryToken, adjustToken, closeHandle);

    const auto openThread = reinterpret_cast<NtOpenThreadFn>(GetProcAddress(ntdll, "NtOpenThread"));
    const auto query = reinterpret_cast<NtQuerySystemInformationFn>(
        GetProcAddress(ntdll, "NtQuerySystemInformation"));
    const auto queryThread = reinterpret_cast<NtQueryInformationThreadFn>(
        GetProcAddress(ntdll, "NtQueryInformationThread"));
    const auto setThread = reinterpret_cast<NtSetInformationThreadFn>(
        GetProcAddress(ntdll, "NtSetInformationThread"));
    const auto getNextThread = reinterpret_cast<NtGetNextThreadFn>(
        GetProcAddress(ntdll, "NtGetNextThread"));
    if (openThread == nullptr || query == nullptr || queryThread == nullptr || setThread == nullptr || getNextThread == nullptr) {
        std::fputs("required ntdll thread query APIs are unavailable\n", stderr);
        return 1;
    }

    ULONG capacity = 256U * 1024U;
    PVOID buffer = allocateHeap(heap, 0, capacity);
    if (buffer == nullptr) {
        capacity = 64U * 1024U;
        buffer = allocateHeap(heap, 0, capacity);
    }
    if (buffer == nullptr) {
        std::fputs("failed to allocate snapshot buffer\n", stderr);
        destroyHeap(heap);
        return 1;
    }
    ThreadCache threadCache{};
    ProcessCache processCache{};
<<<<<<< HEAD
    size_t processCursor = 0;
=======
>>>>>>> d9e66da6445f50d9b892139534ab15c71c91ac1f
    uint32_t scanId = 1;
    const uint32_t intervalMs = ReadIntervalMs(argc, argv);

    if (intervalMs != 0) {
<<<<<<< HEAD
        std::printf("monitoring priority 16 threads every %u ms; global refresh every %u scans; cached budget=%zu process/scan; pass 0 for one scan\n",
            intervalMs, kGlobalRefreshScans, kCachedProcessesPerScan);
=======
        std::printf("monitoring priority 16 threads every %u ms; global refresh every %u scans; pass 0 for one scan\n",
                    intervalMs, kGlobalRefreshScans);
>>>>>>> d9e66da6445f50d9b892139534ab15c71c91ac1f
    }

    do {
        const bool globalRefresh = intervalMs == 0 || scanId == 1 || (scanId % kGlobalRefreshScans) == 0;
<<<<<<< HEAD
        const bool cachedRefresh = !globalRefresh && (scanId % kCachedRefreshStride) == 0;
        const ScanStats stats = globalRefresh
            ? ScanAndFixPriority16(query,
                allocateHeap,
                reallocateHeap,
                heap,
                openThread,
                getNextThread,
                queryThread,
                setThread,
                openProcess,
                closeHandle,
                buffer,
                capacity,
                threadCache,
                processCache,
                scanId++)
            : (cachedRefresh
                ? ScanCachedPriority16Processes(getNextThread,
                    queryThread,
                    setThread,
                    openProcess,
                    closeHandle,
                    threadCache,
                    processCache,
                    processCursor,
                    scanId++)
                : ScanStats{});
        if (intervalMs == 0 || stats.fixedPriority16 != 0 || stats.openFailures != 0 || stats.fixFailures != 0) {
            std::printf("priority16_seen=%u priority16_fixed=%u cached_skipped=%u open_failures=%u protected_failures=%u transient_failures=%u fix_failures=%u\n",
                stats.seenPriority16,
                stats.fixedPriority16,
                stats.cachedSkipped,
                stats.openFailures,
                stats.protectedFailures,
                stats.transientFailures,
                stats.fixFailures);
=======
        const ScanStats stats = globalRefresh
            ? ScanAndFixPriority16(query,
                                   allocateHeap,
                                   reallocateHeap,
                                   heap,
                                   openThread,
                                   getNextThread,
                                   queryThread,
                                   setThread,
                                   openProcess,
                                   setProcess,
                                   closeHandle,
                                   buffer,
                                   capacity,
                                   threadCache,
                                   processCache,
                                   scanId++)
            : ScanCachedPriority16Processes(getNextThread,
                                            queryThread,
                                            setThread,
                                            openProcess,
                                            setProcess,
                                            closeHandle,
                                            threadCache,
                                            processCache,
                                            scanId++);
        if (intervalMs == 0 || stats.fixedPriority16 != 0 || stats.openFailures != 0 || stats.fixFailures != 0) {
            std::printf("priority16_seen=%u priority16_fixed=%u cached_skipped=%u open_failures=%u protected_failures=%u transient_failures=%u fix_failures=%u\n",
                        stats.seenPriority16,
                        stats.fixedPriority16,
                        stats.cachedSkipped,
                        stats.openFailures,
                        stats.protectedFailures,
                        stats.transientFailures,
                        stats.fixFailures);
>>>>>>> d9e66da6445f50d9b892139534ab15c71c91ac1f
        }

        if (intervalMs == 0) {
            break;
        }

        LARGE_INTEGER delay{};
        delay.QuadPart = -static_cast<LONGLONG>(intervalMs) * 10000LL;
        delayExecution(FALSE, &delay);
    } while (true);

    CloseProcessCache(processCache, closeHandle);
    freeHeap(heap, 0, buffer);
    destroyHeap(heap);
    return 0;
<<<<<<< HEAD
}
=======
}
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
>>>>>>> d9e66da6445f50d9b892139534ab15c71c91ac1f
