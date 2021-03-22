#pragma once

#include <stdint.h>
#include "windows.h"
#include "wininet.h"

#define FAIL 0
#define SUCCESS 1

uint64_t getFunctionPtr(unsigned long, unsigned long);

// ----  KERNEL32 ----
#define HASH_KERNEL32 0x7040ee75 
#define HASH_LOADLIBRARYA 0x5fbff0fb
#define HASH_LSTRCMPW 0xd2bfde01

typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef int(WINAPI* LSTRCMPW)(LPCWSTR, LPCWSTR);

// ---- USER32 ----
#define HASH_USER32 0x5a6bd3f3
#define HASH_MESSAGEBOXA 0x384f14b4
#define HASH_WSPRINTFA 0xf898b8c3

typedef int(WINAPI* MESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);
typedef int(WINAPI* WSPRINTFA)(LPSTR, LPCSTR, ...);

// ---- shlwapi.dll ----
#define HASH_SHLWAPI 0xa70d9427
#define HASH_STRSTRA 0xfb62238

typedef PCSTR(WINAPI* STRSTRA)(PCSTR, PCSTR);

// ---- Ole32.dll ----
#define HASH_OLE32 0xf92c2394
#define HASH_CONITIALIZEEX 0xc1cd8ee6
#define HASH_COCREATEINSTANCE 0xbecc6920
#define HASH_COTASKMEMFREE 0xe4f194ab
#define HASH_COUNINITIALIZE 0x145f84c
#define HASH_COINITIALIZESECURITY 0x428dffe1

typedef HRESULT(WINAPI* COINITIALIZEEX)(LPVOID, DWORD);
typedef HRESULT(WINAPI* COCREATEINSTANCE)(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
typedef void(WINAPI* COTASKMEMFREE)(LPVOID);
typedef void(WINAPI* COUNINITIALIZE)();
typedef HRESULT (WINAPI* COINITIALIZESECURITY)( PSECURITY_DESCRIPTOR, LONG, SOLE_AUTHENTICATION_SERVICE*, void*, DWORD , DWORD ,void* , DWORD , void* );

// ---- Oleaut32.dll ----
#define HASH_OLEAUT32 0xe6ab711e
#define HASH_SYSALLOCSTRING 0x785668a6
#define HASH_SYSFREESTRING 0x8d88867d

typedef BSTR(WINAPI* SYSALLOCSTRING)(OLECHAR FAR*);
typedef void(WINAPI* SYSFREESTRING)(BSTR);

typedef struct _UNICODE_STR {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR pBuffer;
} UNICODE_STR, * PUNICODE_STR;

typedef struct _PEB_LDR_DATA
{
    DWORD dwLength;
    DWORD dwInitialized;
    LPVOID lpSsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    LPVOID lpEntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

//redefine PEB_FREE_BLOCK struct
typedef struct _PEB_FREE_BLOCK
{
    struct _PEB_FREE_BLOCK* pNext;
    DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

//redefine PEB struct
typedef struct __PEB
{
    BYTE bInheritedAddressSpace;
    BYTE bReadImageFileExecOptions;
    BYTE bBeingDebugged;
    BYTE bSpareBool;
    LPVOID lpMutant;
    LPVOID lpImageBaseAddress;
    PPEB_LDR_DATA pLdr;
    LPVOID lpProcessParameters;
    LPVOID lpSubSystemData;
    LPVOID lpProcessHeap;
    PRTL_CRITICAL_SECTION pFastPebLock;
    LPVOID lpFastPebLockRoutine;
    LPVOID lpFastPebUnlockRoutine;
    DWORD dwEnvironmentUpdateCount;
    LPVOID lpKernelCallbackTable;
    DWORD dwSystemReserved;
    DWORD dwAtlThunkSListPtr32;
    PPEB_FREE_BLOCK pFreeList;
    DWORD dwTlsExpansionCounter;
    LPVOID lpTlsBitmap;
    DWORD dwTlsBitmapBits[2];
    LPVOID lpReadOnlySharedMemoryBase;
    LPVOID lpReadOnlySharedMemoryHeap;
    LPVOID lpReadOnlyStaticServerData;
    LPVOID lpAnsiCodePageData;
    LPVOID lpOemCodePageData;
    LPVOID lpUnicodeCaseTableData;
    DWORD dwNumberOfProcessors;
    DWORD dwNtGlobalFlag;
    LARGE_INTEGER liCriticalSectionTimeout;
    DWORD dwHeapSegmentReserve;
    DWORD dwHeapSegmentCommit;
    DWORD dwHeapDeCommitTotalFreeThreshold;
    DWORD dwHeapDeCommitFreeBlockThreshold;
    DWORD dwNumberOfHeaps;
    DWORD dwMaximumNumberOfHeaps;
    LPVOID lpProcessHeaps;
    LPVOID lpGdiSharedHandleTable;
    LPVOID lpProcessStarterHelper;
    DWORD dwGdiDCAttributeList;
    LPVOID lpLoaderLock;
    DWORD dwOSMajorVersion;
    DWORD dwOSMinorVersion;
    WORD wOSBuildNumber;
    WORD wOSCSDVersion;
    DWORD dwOSPlatformId;
    DWORD dwImageSubsystem;
    DWORD dwImageSubsystemMajorVersion;
    DWORD dwImageSubsystemMinorVersion;
    DWORD dwImageProcessAffinityMask;
    DWORD dwGdiHandleBuffer[34];
    LPVOID lpPostProcessInitRoutine;
    LPVOID lpTlsExpansionBitmap;
    DWORD dwTlsExpansionBitmapBits[32];
    DWORD dwSessionId;
    ULARGE_INTEGER liAppCompatFlags;
    ULARGE_INTEGER liAppCompatFlagsUser;
    LPVOID lppShimData;
    LPVOID lpAppCompatInfo;
    UNICODE_STR usCSDVersion;
    LPVOID lpActivationContextData;
    LPVOID lpProcessAssemblyStorageMap;
    LPVOID lpSystemDefaultActivationContextData;
    LPVOID lpSystemAssemblyStorageMap;
    DWORD dwMinimumStackCommit;
} _PEB, * _PPEB;
