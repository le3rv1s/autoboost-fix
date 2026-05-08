#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

using NTSTATUS_T = LONG;
using KPRIORITY = LONG;

struct NativeUnicodeString { USHORT Length; USHORT MaximumLength; PWSTR Buffer; };
struct NativeClientId { HANDLE UniqueProcess; HANDLE UniqueThread; };
struct NativeObjectAttributes { ULONG Length; HANDLE RootDirectory; PVOID ObjectName; ULONG Attributes; PVOID SecurityDescriptor; PVOID SecurityQualityOfService; };
struct NativeSystemThreadInformation {
    LARGE_INTEGER KernelTime; LARGE_INTEGER UserTime; LARGE_INTEGER CreateTime; ULONG WaitTime; PVOID StartAddress;
    NativeClientId ClientId; KPRIORITY Priority; LONG BasePriority; ULONG ContextSwitches; ULONG ThreadState; ULONG WaitReason;
};
struct NativeSystemProcessInformation {
    ULONG NextEntryOffset; ULONG NumberOfThreads; LARGE_INTEGER WorkingSetPrivateSize; ULONG HardFaultCount; ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime; LARGE_INTEGER CreateTime; LARGE_INTEGER UserTime; LARGE_INTEGER KernelTime; NativeUnicodeString ImageName;
    KPRIORITY BasePriority; HANDLE UniqueProcessId; HANDLE InheritedFromUniqueProcessId; ULONG HandleCount; ULONG SessionId; ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize; SIZE_T VirtualSize; ULONG PageFaultCount; SIZE_T PeakWorkingSetSize; SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage; SIZE_T QuotaPagedPoolUsage; SIZE_T QuotaPeakNonPagedPoolUsage; SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage; SIZE_T PeakPagefileUsage; SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount; LARGE_INTEGER WriteOperationCount; LARGE_INTEGER OtherOperationCount; LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount; LARGE_INTEGER OtherTransferCount; NativeSystemThreadInformation Threads[1];
};
struct NativeThreadBasicInformation { NTSTATUS_T ExitStatus; PVOID TebBaseAddress; NativeClientId ClientId; ULONG_PTR AffinityMask; KPRIORITY Priority; LONG BasePriority; };

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
using NtQuerySystemInformationFn = NTSTATUS_T(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
using NtQueryInformationThreadFn = NTSTATUS_T(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtSetInformationThreadFn = NTSTATUS_T(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
using NtGetNextThreadFn = NTSTATUS_T(NTAPI*)(HANDLE, HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);
using NtCloseFn = NTSTATUS_T(NTAPI*)(HANDLE);
using NtDelayExecutionFn = NTSTATUS_T(NTAPI*)(BOOLEAN, PLARGE_INTEGER);

constexpr NTSTATUS_T kStatusInfoLengthMismatch = static_cast<NTSTATUS_T>(0xC0000004L);
constexpr NTSTATUS_T kStatusAccessDenied = static_cast<NTSTATUS_T>(0xC0000022L);
constexpr NTSTATUS_T kStatusInvalidCid = static_cast<NTSTATUS_T>(0xC000000BL);
constexpr NTSTATUS_T kStatusInvalidParameter = static_cast<NTSTATUS_T>(0xC000000DL);
constexpr ULONG kSystemProcessInformation = 5;
constexpr ULONG kThreadBasicInformation = 0;
constexpr ULONG kThreadBasePriority = 3;
constexpr KPRIORITY kTargetPriority = 16;
constexpr KPRIORITY kNormalThreadBasePriority = 0;
constexpr ULONG kHeapGrowable = 2;
constexpr uint32_t kDefaultIntervalMs = 1000;
constexpr uint32_t kFullScanPeriodMs = 120000;
constexpr uint32_t kRetryCooldownScans = 4096;
constexpr uint32_t kRetryCooldownFixedScans = 1;
constexpr size_t kThreadCacheSize = 1024;
constexpr size_t kProcessCacheSize = 128;
constexpr size_t kProcessesPerIncrementalScan = 2;

struct ScanStats { uint32_t seenPriority16=0,fixedPriority16=0,cachedSkipped=0,openFailures=0,protectedFailures=0,transientFailures=0,fixFailures=0; };
struct ThreadCacheEntry { DWORD processId=0, threadId=0; uint32_t lastScan=0; uint8_t state=0; };
struct ThreadCache { ThreadCacheEntry entries[kThreadCacheSize]{}; };
struct ProcessCache { DWORD pids[kProcessCacheSize]{}; size_t cursor=0; };

static uint32_t HashThreadKey(DWORD processId, DWORD threadId) noexcept { uint32_t x=processId*16777619u^threadId; x^=x>>16; x*=0x7feb352dU; x^=x>>15; return x; }
static bool ShouldSkipCachedThread(ThreadCache& c,DWORD p,DWORD t,uint32_t s) noexcept { size_t st=HashThreadKey(p,t)&(kThreadCacheSize-1); for(size_t i=0;i<4;++i){ auto &e=c.entries[(st+i)&(kThreadCacheSize-1)]; if(e.state==0) return false; if(e.processId==p&&e.threadId==t){ uint32_t age=s-e.lastScan; return e.state==1?age<kRetryCooldownFixedScans:age<kRetryCooldownScans; }} return false; }
static void RememberThread(ThreadCache& c,DWORD p,DWORD t,uint32_t s,uint8_t stt) noexcept { size_t st=HashThreadKey(p,t)&(kThreadCacheSize-1),slot=st; uint32_t old=0; for(size_t i=0;i<4;++i){ auto &e=c.entries[(st+i)&(kThreadCacheSize-1)]; if(e.state==0||(e.processId==p&&e.threadId==t)){slot=(st+i)&(kThreadCacheSize-1);break;} uint32_t age=s-e.lastScan; if(age>=old){old=age;slot=(st+i)&(kThreadCacheSize-1);} } c.entries[slot]={p,t,s,stt}; }
static uint32_t ReadIntervalMs(int argc, wchar_t** argv) noexcept { if(argc<2) return kDefaultIntervalMs; wchar_t* end=nullptr; unsigned long v=wcstoul(argv[1],&end,10); return (end==argv[1]||*end!=L'\0'||v>60000UL)?kDefaultIntervalMs:(uint32_t)v; }

static bool QueryProcessSnapshot(NtQuerySystemInformationFn query, RtlReAllocateHeapFn reallocateHeap, PVOID heap, PVOID& buffer, ULONG& capacity) noexcept {
    ULONG required=0; NTSTATUS_T status=query(kSystemProcessInformation, buffer, capacity, &required);
    while(status==kStatusInfoLengthMismatch){ ULONG next= required>capacity? required+65536U : capacity*2U; PVOID nb=reallocateHeap(heap,0,buffer,next); if(!nb) return false; buffer=nb; capacity=next; required=0; status=query(kSystemProcessInformation,buffer,capacity,&required);} return status>=0;
}
static HANDLE NtCurrentProcessHandle() noexcept { return reinterpret_cast<HANDLE>(static_cast<LONG_PTR>(-1)); }
static void EnableAllTokenPrivileges(RtlAllocateHeapFn alloc,RtlFreeHeapFn freeHeap,PVOID heap,NtOpenProcessTokenFn openTok,NtQueryInformationTokenFn qTok,NtAdjustPrivilegesTokenFn adjTok,NtCloseFn closeHandle) noexcept {
    HANDLE token=nullptr; if(openTok(NtCurrentProcessHandle(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&token)<0) return; ULONG req=0; qTok(token,TokenPrivileges,nullptr,0,&req); if(!req){closeHandle(token); return;} PVOID mem=alloc(heap,0,req); if(!mem){closeHandle(token); return;} auto* tp=(TOKEN_PRIVILEGES*)mem; if(qTok(token,TokenPrivileges,tp,req,&req)<0){freeHeap(heap,0,mem); closeHandle(token); return;} for(DWORD i=0;i<tp->PrivilegeCount;++i) tp->Privileges[i].Attributes|=SE_PRIVILEGE_ENABLED; adjTok(token,FALSE,tp,req,nullptr,nullptr); freeHeap(heap,0,mem); closeHandle(token);
}
static bool FixThread(NtOpenThreadFn openThread,NtSetInformationThreadFn setThread,NtCloseFn closeHandle,DWORD pid,DWORD tid,DWORD& error,uint8_t& fk) noexcept {
    NativeObjectAttributes a{sizeof(a),nullptr,nullptr,0,nullptr,nullptr}; NativeClientId cid{(HANDLE)(ULONG_PTR)pid,(HANDLE)(ULONG_PTR)tid}; HANDLE th=nullptr; NTSTATUS_T st=openThread(&th,THREAD_SET_INFORMATION,&a,&cid); if(st<0||!th){ error=ERROR_ACCESS_DENIED; fk=(st==kStatusInvalidCid||st==kStatusInvalidParameter)?2:(st==kStatusAccessDenied?1:3); return false; }
    KPRIORITY base=kNormalThreadBasePriority; st=setThread(th,kThreadBasePriority,&base,sizeof(base)); closeHandle(th); if(st<0){ error=(st==kStatusAccessDenied)?ERROR_ACCESS_DENIED:ERROR_GEN_FAILURE; return false; } error=0; return true;
}
static void RememberProcess(ProcessCache& pc, DWORD pid) noexcept { if(!pid) return; for(size_t i=0;i<kProcessCacheSize;++i){ if(pc.pids[i]==pid) return; if(pc.pids[i]==0){ pc.pids[i]=pid; return; } } pc.pids[pc.cursor++%kProcessCacheSize]=pid; }

static ScanStats FullScan(NtQuerySystemInformationFn query,RtlReAllocateHeapFn reallocateHeap,PVOID heap,PVOID& buffer,ULONG& capacity,NtOpenThreadFn openThread,NtSetInformationThreadFn setThread,NtCloseFn closeHandle,ThreadCache& tc,ProcessCache& pc,uint32_t scanId) noexcept {
    ScanStats st{}; if(!QueryProcessSnapshot(query,reallocateHeap,heap,buffer,capacity)) return st; DWORD self=GetCurrentThreadId(); auto* p=(NativeSystemProcessInformation*)buffer; for(;;){ auto* t=p->Threads; for(ULONG i=0;i<p->NumberOfThreads;++i,++t){ if(t->Priority!=kTargetPriority&&t->BasePriority!=kTargetPriority) continue; DWORD pid=(DWORD)(ULONG_PTR)t->ClientId.UniqueProcess, tid=(DWORD)(ULONG_PTR)t->ClientId.UniqueThread; if(!tid||tid==self) continue; ++st.seenPriority16; RememberProcess(pc,pid); if(ShouldSkipCachedThread(tc,pid,tid,scanId)){++st.cachedSkipped; continue;} DWORD e=0; uint8_t fk=3; if(FixThread(openThread,setThread,closeHandle,pid,tid,e,fk)){++st.fixedPriority16; RememberThread(tc,pid,tid,scanId,1);} else if(e==ERROR_ACCESS_DENIED){ if(fk==2){++st.openFailures;++st.transientFailures; RememberThread(tc,pid,tid,scanId,0);} else if(fk==1){++st.protectedFailures; RememberThread(tc,pid,tid,scanId,2);} else {++st.openFailures; RememberThread(tc,pid,tid,scanId,2);} } else {++st.fixFailures; RememberThread(tc,pid,tid,scanId,3);} }
        if(!p->NextEntryOffset) break; p=(NativeSystemProcessInformation*)((BYTE*)p+p->NextEntryOffset);
    } return st;
}

static HANDLE OpenProcessNative(NtOpenProcessFn openProcess,DWORD pid) noexcept { HANDLE proc=nullptr; NativeObjectAttributes a{sizeof(a),nullptr,nullptr,0,nullptr,nullptr}; NativeClientId c{(HANDLE)(ULONG_PTR)pid,nullptr}; return openProcess(&proc,PROCESS_QUERY_INFORMATION,&a,&c)>=0?proc:nullptr; }
static ScanStats IncrementalScan(NtOpenProcessFn openProcess,NtGetNextThreadFn getNextThread,NtQueryInformationThreadFn queryThread,NtSetInformationThreadFn setThread,NtCloseFn closeHandle,ThreadCache& tc,ProcessCache& pc,uint32_t scanId) noexcept {
    ScanStats st{}; DWORD self=GetCurrentThreadId();
    for(size_t i=0;i<kProcessesPerIncrementalScan;++i){ DWORD pid=pc.pids[(pc.cursor+i)%kProcessCacheSize]; if(!pid) continue; HANDLE proc=OpenProcessNative(openProcess,pid); if(!proc) continue; HANDLE prev=nullptr;
        for(;;){ HANDLE th=nullptr; NTSTATUS_T ns=getNextThread(proc,prev,THREAD_QUERY_INFORMATION|THREAD_SET_INFORMATION,0,0,&th); if(prev) closeHandle(prev); prev=th; if(ns<0||!th) break; NativeThreadBasicInformation b{}; if(queryThread(th,kThreadBasicInformation,&b,sizeof(b),nullptr)<0) continue; DWORD tid=(DWORD)(ULONG_PTR)b.ClientId.UniqueThread; if(!tid||tid==self) continue; if(b.Priority!=kTargetPriority&&b.BasePriority!=kTargetPriority) continue; ++st.seenPriority16; if(ShouldSkipCachedThread(tc,pid,tid,scanId)){++st.cachedSkipped; continue;} DWORD err=0; if(setThread(th,kThreadBasePriority,(void*)&kNormalThreadBasePriority,sizeof(KPRIORITY))>=0){++st.fixedPriority16; RememberThread(tc,pid,tid,scanId,1);} else { err=GetLastError(); if(err==ERROR_ACCESS_DENIED){++st.openFailures; RememberThread(tc,pid,tid,scanId,2);} else {++st.fixFailures; RememberThread(tc,pid,tid,scanId,3);} }
        }
        if(prev) closeHandle(prev); closeHandle(proc);
    }
    pc.cursor=(pc.cursor+kProcessesPerIncrementalScan)%kProcessCacheSize; return st;
}

int wmain(int argc, wchar_t** argv){
    HMODULE ntdll=GetModuleHandleW(L"ntdll.dll"); if(!ntdll) return 1;
    auto alloc=(RtlAllocateHeapFn)GetProcAddress(ntdll,"RtlAllocateHeap"); auto freeHeap=(RtlFreeHeapFn)GetProcAddress(ntdll,"RtlFreeHeap"); auto reallocHeap=(RtlReAllocateHeapFn)GetProcAddress(ntdll,"RtlReAllocateHeap"); auto createHeap=(RtlCreateHeapFn)GetProcAddress(ntdll,"RtlCreateHeap"); auto destroyHeap=(RtlDestroyHeapFn)GetProcAddress(ntdll,"RtlDestroyHeap");
    auto openTok=(NtOpenProcessTokenFn)GetProcAddress(ntdll,"NtOpenProcessToken"); auto qTok=(NtQueryInformationTokenFn)GetProcAddress(ntdll,"NtQueryInformationToken"); auto adjTok=(NtAdjustPrivilegesTokenFn)GetProcAddress(ntdll,"NtAdjustPrivilegesToken");
    auto openThread=(NtOpenThreadFn)GetProcAddress(ntdll,"NtOpenThread"); auto openProcess=(NtOpenProcessFn)GetProcAddress(ntdll,"NtOpenProcess"); auto query=(NtQuerySystemInformationFn)GetProcAddress(ntdll,"NtQuerySystemInformation"); auto queryThread=(NtQueryInformationThreadFn)GetProcAddress(ntdll,"NtQueryInformationThread"); auto setThread=(NtSetInformationThreadFn)GetProcAddress(ntdll,"NtSetInformationThread"); auto getNextThread=(NtGetNextThreadFn)GetProcAddress(ntdll,"NtGetNextThread"); auto closeHandle=(NtCloseFn)GetProcAddress(ntdll,"NtClose"); auto delay=(NtDelayExecutionFn)GetProcAddress(ntdll,"NtDelayExecution");
    if(!alloc||!freeHeap||!reallocHeap||!createHeap||!destroyHeap||!openTok||!qTok||!adjTok||!openThread||!openProcess||!query||!queryThread||!setThread||!getNextThread||!closeHandle||!delay) return 1;

    PVOID heap=createHeap(kHeapGrowable,nullptr,0,0,nullptr,nullptr); if(!heap) return 1; EnableAllTokenPrivileges(alloc,freeHeap,heap,openTok,qTok,adjTok,closeHandle);
    ULONG cap=256*1024; PVOID buf=alloc(heap,0,cap); if(!buf){cap=64*1024; buf=alloc(heap,0,cap);} if(!buf) return 1;

    ThreadCache tc{}; ProcessCache pc{}; uint32_t scanId=1; uint32_t interval=ReadIntervalMs(argc,argv); uint32_t scansPerFull = interval? (kFullScanPeriodMs/interval):1; if(scansPerFull==0) scansPerFull=1;
    std::printf("interval=%u ms, full scan each ~%u scans (<=120s), incremental budget=%zu processes/tick\n", interval, scansPerFull, kProcessesPerIncrementalScan);

    do {
        bool doFull = (interval==0) || (scanId==1) || ((scanId % scansPerFull)==0);
        ScanStats s = doFull ? FullScan(query,reallocHeap,heap,buf,cap,openThread,setThread,closeHandle,tc,pc,scanId)
                            : IncrementalScan(openProcess,getNextThread,queryThread,setThread,closeHandle,tc,pc,scanId);
        if(interval==0||s.fixedPriority16||s.openFailures||s.fixFailures){ std::printf("full=%u seen=%u fixed=%u skipped=%u open_fail=%u prot=%u trans=%u fix_fail=%u\n", doFull?1u:0u,s.seenPriority16,s.fixedPriority16,s.cachedSkipped,s.openFailures,s.protectedFailures,s.transientFailures,s.fixFailures); }
        if(interval==0) break; ++scanId; LARGE_INTEGER d{}; d.QuadPart = -static_cast<LONGLONG>(interval) * 10000LL; delay(FALSE,&d);
    } while(true);

    freeHeap(heap,0,buf); destroyHeap(heap); return 0;
}
