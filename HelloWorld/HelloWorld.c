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

	uint64_t _MessageBoxA = getFunctionPtr(HASH_USER32, HASH_MESSAGEBOXA);

	if (_MessageBoxA == 0x00)
		return FAIL;

	char message[] = { 'M', 'o', 'i', 'n', 0x00 };
	((MESSAGEBOXA)_MessageBoxA)(0, message, message, 1);

	return SUCCESS;

}