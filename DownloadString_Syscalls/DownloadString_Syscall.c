#include "APIResolve.h"
#ifndef  _DEBUG
#include "Syscalls.h"
#endif 

#define FAIL 0
#define SUCCESS 1

#define MAX_BUFFER 512 * 512

#ifdef  _DEBUG
int
main(void) {
#else
int
go(void) {
#endif 

	uint64_t _InternetCloseHandle = getFunctionPtr(HASH_WININET, HASH_INTERNETCLOSEHANDLE);
	uint64_t _InternetOpenA = getFunctionPtr(HASH_WININET, HASH_INTERNETOPENA);
	uint64_t _InternetConnectA = getFunctionPtr(HASH_WININET, HASH_INTERNETCONNECTA);
	uint64_t _HttpOpenRequestA = getFunctionPtr(HASH_WININET, HASH_HTTPOPENREQUESTA);
	uint64_t _InternetReadFile = getFunctionPtr(HASH_WININET, HASH_INTERNETREADFILE);
	uint64_t _HttpSendRequestA = getFunctionPtr(HASH_WININET, HASH_HTTPSENDREQUESTA);
	uint64_t _VirtualFree = getFunctionPtr(HASH_KERNEL32, HASH_VIRTUALFREE);
	uint64_t _MessageBoxA = getFunctionPtr(HASH_USER32, HASH_MESSAGEBOXA);

	if ( _InternetCloseHandle == 0x00 || _InternetOpenA == 0x00 || _InternetConnectA == 0x00 || _HttpOpenRequestA == 0x00 || _InternetReadFile == 0x00 || _VirtualFree == 0x00 || _HttpSendRequestA == 0x00 || _MessageBoxA == 0x00)
		return FAIL;

	char hostname[] = { '1', '2', '7', '.', '0','.', '0', '.', '1', 0x00 };
	char endpoint[] = { 'x', 0x00 };
	uint32_t port = 80;
	HINTERNET h_session = NULL, h_connect = NULL, h_request = NULL;
	DWORD dw_read = 0, dw_read_total = 0, dw_success = FAIL;
	char method[] = { 'G', 'E', 'T', 0x00 };

	SIZE_T mem_size = MAX_BUFFER;
	LPVOID ptr_memory = NULL;

#ifndef _DEBUG
	NTSTATUS status = ZwAllocateVirtualMemory(NtCurrentProcess(), &ptr_memory, 0, &mem_size, MEM_COMMIT, PAGE_READWRITE);
	if (status != STATUS_SUCCESS) 
		goto cleanup;
#else
	uint64_t _VirtualAlloc = getFunctionPtr(HASH_KERNEL32, HASH_VIRTUALALLOC);
	ptr_memory = ((VIRTUALALLOC)_VirtualAlloc)(0, mem_size, MEM_COMMIT, PAGE_READWRITE);
#endif 

	h_session = ((INTERNETOPENA)_InternetOpenA)(NULL, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (!h_session)
		goto cleanup;

	h_connect = ((INTERNETCONNECTA)_InternetConnectA)(h_session, hostname, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 1);
	if (!h_connect)
		goto cleanup;

	h_request = ((HTTPOPENREQUESTA)_HttpOpenRequestA)(h_connect, (LPCTSTR)&method, (LPCTSTR)&endpoint, NULL, NULL, NULL, INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_RELOAD, 1);
	if (!h_request)
		goto cleanup;

	if (((HTTPSENDREQUESTA)_HttpSendRequestA)(h_request, NULL, 0, NULL, 0) == FAIL)
		goto cleanup;

	do {

		if (((INTERNETREADFILE)_InternetReadFile)(h_request, (LPVOID)((uint64_t)ptr_memory + dw_read_total), MAX_BUFFER - dw_read_total, &dw_read) == FAIL) 
			break;		

		dw_read_total += dw_read;

	} while (dw_read);

	if(dw_read_total)
		((MESSAGEBOXA)_MessageBoxA)(0, ptr_memory, ptr_memory, 1);

	dw_success = SUCCESS;

cleanup:

	((INTERNETCLOSEHANDLE)_InternetCloseHandle)(h_session);
	((INTERNETCLOSEHANDLE)_InternetCloseHandle)(h_connect);
	((INTERNETCLOSEHANDLE)_InternetCloseHandle)(h_request);

	if(ptr_memory != NULL)
		((VIRTUALFREE)_VirtualFree)(ptr_memory, 0, MEM_RELEASE);

	return dw_success;

}