#include "APIResolve.h"

#define FAIL 0
#define SUCCESS 1

#ifdef  _DEBUG
int
main(void) {
#else
int
go(void) {
#endif 

	uint64_t _CloseHandle = getFunctionPtr(HASH_KERNEL32, HASH_CLOSEHANDLE);
	uint64_t _CreateProcessA = getFunctionPtr(HASH_KERNEL32, HASH_CREATEPROCESSA);

	if (_CloseHandle == 0x00 || _CreateProcessA == 0x00)
		return FAIL;

	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	DWORD dw_success = FAIL;

	char file[] = { 'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y','s','t','e', 'm','3','2','\\', 'c', 'a', 'l', 'c', '.', 'e', 'x', 'e', 0x00 };

	for (uint8_t i = 0; i < sizeof(si); i++)
		*((uint8_t*)(&si) + i) = 0x00;

	for (uint8_t i = 0; i < sizeof(pi); i++)
		*((uint8_t*)(&pi) + i) = 0x00;

	si.cb = sizeof(si);

	dw_success = ((CREATEPROCESSA)_CreateProcessA)(0, file, 0, 0, TRUE, 0, 0, 0, &si, &pi);
	if (dw_success == FAIL)
		goto cleanup;

	dw_success = SUCCESS;

cleanup:
	((CLOSEHANDLE)_CloseHandle)(pi.hThread);
	((CLOSEHANDLE)_CloseHandle)(pi.hProcess);


	return dw_success;

}