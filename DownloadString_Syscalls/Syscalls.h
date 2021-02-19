#pragma once

#include "windows.h"
#include "syscalls-asm.h"

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define STATUS_SUCCESS 0

EXTERN_C NTSTATUS NtAllocateVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN ULONG ZeroBits,
	IN OUT PSIZE_T RegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect);
