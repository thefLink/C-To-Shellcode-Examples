#pragma once
#include "Syscalls.h"

#define ZwAllocateVirtualMemory NtAllocateVirtualMemory
__asm__("NtAllocateVirtualMemory: \n\
	mov rax, gs:[0x60]                                  \n\
NtAllocateVirtualMemory_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtAllocateVirtualMemory_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtAllocateVirtualMemory_Check_10_0_XXXX \n\
	jmp NtAllocateVirtualMemory_SystemCall_Unknown \n\
NtAllocateVirtualMemory_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtAllocateVirtualMemory_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtAllocateVirtualMemory_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtAllocateVirtualMemory_SystemCall_6_3_XXXX \n\
	jmp NtAllocateVirtualMemory_SystemCall_Unknown \n\
NtAllocateVirtualMemory_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtAllocateVirtualMemory_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtAllocateVirtualMemory_SystemCall_6_1_7601 \n\
	jmp NtAllocateVirtualMemory_SystemCall_Unknown \n\
NtAllocateVirtualMemory_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtAllocateVirtualMemory_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtAllocateVirtualMemory_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtAllocateVirtualMemory_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtAllocateVirtualMemory_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtAllocateVirtualMemory_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtAllocateVirtualMemory_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtAllocateVirtualMemory_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtAllocateVirtualMemory_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtAllocateVirtualMemory_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtAllocateVirtualMemory_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtAllocateVirtualMemory_SystemCall_10_0_19042 \n\
	jmp NtAllocateVirtualMemory_SystemCall_Unknown \n\
NtAllocateVirtualMemory_SystemCall_6_1_7600:           \n\
	mov eax, 0x0015 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_6_1_7601:           \n\
	mov eax, 0x0015 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x0016 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x0017 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_10_0_10240:         \n\
	mov eax, 0x0018 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_10_0_10586:         \n\
	mov eax, 0x0018 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_10_0_14393:         \n\
	mov eax, 0x0018 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_10_0_15063:         \n\
	mov eax, 0x0018 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_10_0_16299:         \n\
	mov eax, 0x0018 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_10_0_17134:         \n\
	mov eax, 0x0018 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_10_0_17763:         \n\
	mov eax, 0x0018 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_10_0_18362:         \n\
	mov eax, 0x0018 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_10_0_18363:         \n\
	mov eax, 0x0018 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_10_0_19041:         \n\
	mov eax, 0x0018 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_10_0_19042:         \n\
	mov eax, 0x0018 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_Unknown:            \n\
	ret \n\
NtAllocateVirtualMemory_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");


