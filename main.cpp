#include <windows.h>
#include <winternl.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

using NtQuerySystemInformation_t = NTSTATUS(NTAPI*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
using NtOpenThread_t = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
using NtSetInformationThread_t = NTSTATUS(NTAPI*)(HANDLE, THREADINFOCLASS, PVOID, ULONG);
using NtQueryInformationThread_t = NTSTATUS(NTAPI*)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);

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

static std::wstring ToWide(const char* arg) {
    const int len = MultiByteToWideChar(CP_UTF8, 0, arg, -1, nullptr, 0);
    if (len <= 0) return L"";
    std::wstring result(static_cast<size_t>(len - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, arg, -1, result.data(), len);
    return result;
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) {
        std::wprintf(L"Usage: autoboost_fix_nt.exe <pid>\n");
        return 1;
    }

    const DWORD pid = static_cast<DWORD>(_wtoi(argv[1]));
    if (pid == 0) {
        std::wprintf(L"Invalid PID.\n");
        return 1;
    }

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        std::wprintf(L"Failed to load ntdll.\n");
        return 1;
    }

    auto NtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformation_t>(GetProcAddress(ntdll, "NtQuerySystemInformation"));
    auto NtOpenThread = reinterpret_cast<NtOpenThread_t>(GetProcAddress(ntdll, "NtOpenThread"));
    auto NtSetInformationThread = reinterpret_cast<NtSetInformationThread_t>(GetProcAddress(ntdll, "NtSetInformationThread"));
    auto NtQueryInformationThread = reinterpret_cast<NtQueryInformationThread_t>(GetProcAddress(ntdll, "NtQueryInformationThread"));

    if (!NtQuerySystemInformation || !NtOpenThread || !NtSetInformationThread || !NtQueryInformationThread) {
        std::wprintf(L"Failed to resolve NT functions.\n");
        return 1;
    }

    ULONG size = 1 << 20;
    std::unique_ptr<std::byte[]> buffer;
    NTSTATUS status;
    ULONG needed = 0;

    do {
        buffer.reset(new std::byte[size]);
        status = NtQuerySystemInformation(SystemProcessInformation, buffer.get(), size, &needed);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            size = needed + (1 << 16);
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status)) {
        std::wprintf(L"NtQuerySystemInformation failed: 0x%08X\n", static_cast<unsigned>(status));
        return 1;
    }

    ULONG fixed = 0;
    auto* spi = reinterpret_cast<UNDOC_SYSTEM_PROCESS_INFORMATION*>(buffer.get());
    while (true) {
        if (static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(spi->UniqueProcessId)) == pid) {
            for (ULONG i = 0; i < spi->NumberOfThreads; ++i) {
                const auto& t = spi->Threads[i];
                if (t.Priority <= 15 || t.BasePriority >= t.Priority) {
                    continue;
                }

                HANDLE threadHandle = nullptr;
                CLIENT_ID cid{t.ClientId.UniqueProcess, t.ClientId.UniqueThread};
                OBJECT_ATTRIBUTES oa{};
                InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);

                if (!NT_SUCCESS(NtOpenThread(&threadHandle, THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION, &oa, &cid))) {
                    continue;
                }

                ULONG boostDisabled = 1;
                NtSetInformationThread(threadHandle, static_cast<THREADINFOCLASS>(ThreadPriorityBoost), &boostDisabled, sizeof(boostDisabled));

                KPRIORITY targetPrio = t.BasePriority;
                if (targetPrio < 1) targetPrio = 1;
                if (targetPrio > 15) targetPrio = 15;

                if (NT_SUCCESS(NtSetInformationThread(threadHandle, ThreadPriority, &targetPrio, sizeof(targetPrio)))) {
                    ++fixed;
                    std::wprintf(L"TID %5lu: %2ld -> %2ld\n", static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(t.ClientId.UniqueThread)), t.Priority, targetPrio);
                }

                CloseHandle(threadHandle);
            }
            break;
        }

        if (spi->NextEntryOffset == 0) break;
        spi = reinterpret_cast<UNDOC_SYSTEM_PROCESS_INFORMATION*>(reinterpret_cast<std::byte*>(spi) + spi->NextEntryOffset);
    }

    std::wprintf(L"Done. Fixed threads: %lu\n", fixed);
    return 0;
}
