#pragma once

#include <stdint.h>
#include "windows.h"

#include "wininet.h"

uint64_t getFunctionPtr(unsigned long, unsigned long);

// ----  KERNEL32 ----
#define HASH_KERNEL32 0x7040ee75 
#define HASH_LOADLIBRARYA 0x5fbff0fb
#define HASH_VIRTUALFREE 0x668fcf2e
#define HASH_VIRTUALALLOC 0x382c0f97

typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef BOOL(WINAPI* VIRTUALFREE)(LPVOID, SIZE_T, DWORD);
typedef LPVOID(WINAPI* VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);

// ---- USER32 ----
#define HASH_USER32 0x5a6bd3f3
#define HASH_MESSAGEBOXA 0x384f14b4

typedef int(WINAPI* MESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);

// ---- Wininet.dll ----
#define HASH_WININET 0x8dbd9c6d
#define HASH_INTERNETOPENA 0xf4ad70a1
#define HASH_INTERNETREADFILE 0xfb4f8eaa
#define HASH_INTERNETCLOSEHANDLE 0x4241bef0
#define HASH_INTERNETCONNECTA 0x44536159
#define HASH_HTTPOPENREQUESTA 0xf0fcb9e1
#define HASH_HTTPSENDREQUESTA 0x915115b9

typedef HINTERNET(WINAPI* INTERNETOPENA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
typedef BOOL(WINAPI* INTERNETREADFILE)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI* INTERNETCLOSEHANDLE)(HINTERNET);
typedef HINTERNET(WINAPI* INTERNETCONNECTA)(HINTERNET, LPCSTR, INTERNET_PORT, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
typedef HINTERNET(WINAPI* HTTPOPENREQUESTA)(HINTERNET, LPCTSTR, LPCTSTR, LPCTSTR, LPCTSTR, LPCTSTR*, DWORD, DWORD_PTR);
typedef BOOL(WINAPI* HTTPSENDREQUESTA)(HINTERNET, LPCSTR, DWORD, LPVOID, DWORD);

typedef PCSTR(WINAPI* STRSTRA)(PCSTR, PCSTR);

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

typedef struct _PEB_FREE_BLOCK
{
    struct _PEB_FREE_BLOCK* pNext;
    DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

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
