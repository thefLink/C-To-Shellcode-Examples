#include "APIResolve.h"

static uint64_t getDllBase(unsigned long);
static uint64_t loadDll(unsigned long);
static uint64_t loadDll_byName(char*);
static uint64_t parseHdrForPtr(uint64_t, unsigned long);
static uint64_t followExport(char*, unsigned long);

static unsigned long djb2(unsigned char*);
static unsigned long unicode_djb2(const wchar_t* str);
static WCHAR* toLower(WCHAR* str);

uint64_t
getFunctionPtr(unsigned long dll_hash, unsigned long function_hash) {

	uint64_t dll_base = 0x00;
	uint64_t ptr_function = 0x00;

	dll_base = getDllBase(dll_hash);
	if (dll_base == 0) {
		dll_base = loadDll(dll_hash);
		if (dll_base == 0)
			return FAIL;
	}

	ptr_function = parseHdrForPtr(dll_base, function_hash);

	return ptr_function;

}

static uint64_t
loadDll(unsigned long dll_hash) {

	uint64_t kernel32_base = 0x00;
	uint64_t fptr_loadLibary = 0x00;
	uint64_t ptr_loaded_dll = 0x00;

	kernel32_base = getDllBase(HASH_KERNEL32);
	if (kernel32_base == 0x00)
		return FAIL;

	fptr_loadLibary = parseHdrForPtr(kernel32_base, HASH_LOADLIBRARYA);
	if (fptr_loadLibary == 0x00)
		return FAIL;

	if (dll_hash == HASH_USER32) {
		char dll_name[] = { 'U', 's', 'e', 'r', '3' ,'2' ,'.', 'd', 'l', 'l', 0x00 };
		ptr_loaded_dll = (uint64_t)((LOADLIBRARYA)fptr_loadLibary)(dll_name);
	} else if (dll_hash == HASH_OLE32) {
		char dll_name[] = { 'O', 'l', 'e', '3', '2', '.', 'd','l','l',0x00 };
		ptr_loaded_dll = (uint64_t)((LOADLIBRARYA)fptr_loadLibary)(dll_name);
	} else if (dll_hash == HASH_OLEAUT32) {
		char dll_name[] = { 'o', 'l', 'e', 'a', 'u', 't', '3','2', '.', 'd','l','l',0x00 };
		ptr_loaded_dll = (uint64_t)((LOADLIBRARYA)fptr_loadLibary)(dll_name);
	} else if (dll_hash == HASH_SHLWAPI) {
		char dll_name[] = { 'S', 'h', 'l', 'w', 'a', 'p', 'i', '.', 'd','l','l',0x00 };
		ptr_loaded_dll = (uint64_t)((LOADLIBRARYA)fptr_loadLibary)(dll_name);
	}

	return ptr_loaded_dll;

}

static uint64_t
loadDll_byName(char* dll_name) {

	uint64_t kernel32_base = 0x00;
	uint64_t fptr_loadLibary = 0x00;
	uint64_t ptr_loaded_dll = 0x00;

	kernel32_base = getDllBase(HASH_KERNEL32);
	if (kernel32_base == 0x00)
		return FAIL;

	fptr_loadLibary = parseHdrForPtr(kernel32_base, HASH_LOADLIBRARYA);
	if (fptr_loadLibary == 0x00)
		return FAIL;

	ptr_loaded_dll = (uint64_t)((LOADLIBRARYA)fptr_loadLibary)(dll_name);

	return ptr_loaded_dll;

}


static uint64_t
parseHdrForPtr(uint64_t dll_base, unsigned long function_hash) {

	PIMAGE_NT_HEADERS nt_hdrs = NULL;
	PIMAGE_DATA_DIRECTORY data_dir = NULL;
	PIMAGE_EXPORT_DIRECTORY export_dir = NULL;

	uint32_t* ptr_exportadrtable = 0x00;
	uint32_t* ptr_namepointertable = 0x00;
	uint16_t* ptr_ordinaltable = 0x00;

	uint32_t idx_functions = 0x00;

	unsigned char* ptr_function_name = NULL;


	nt_hdrs = (PIMAGE_NT_HEADERS)(dll_base + (uint64_t)((PIMAGE_DOS_HEADER)(size_t)dll_base)->e_lfanew);
	data_dir = (PIMAGE_DATA_DIRECTORY)&nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	export_dir = (PIMAGE_EXPORT_DIRECTORY)(dll_base + (uint64_t)data_dir->VirtualAddress);

	ptr_exportadrtable = (uint32_t*)(dll_base + (uint64_t)export_dir->AddressOfFunctions);
	ptr_namepointertable = (uint32_t*)(dll_base + (uint64_t)export_dir->AddressOfNames);
	ptr_ordinaltable = (uint16_t*)(dll_base + (uint64_t)export_dir->AddressOfNameOrdinals);

	for (idx_functions = 0; idx_functions < export_dir->NumberOfNames; idx_functions++) {

		ptr_function_name = (unsigned char*)dll_base + (ptr_namepointertable[idx_functions]);
		if (djb2(ptr_function_name) == function_hash) {

			WORD nameord = ptr_ordinaltable[idx_functions];
			DWORD rva = ptr_exportadrtable[nameord];


			if (dll_base + rva >= dll_base + data_dir->VirtualAddress && dll_base + rva <= dll_base + data_dir->VirtualAddress + (uint64_t)data_dir->Size) {
				// This is a forwarded export 

				char* ptr_forward = (char*)(dll_base + rva);
				return followExport(ptr_forward, function_hash);

			}


			return dll_base + rva;
		}

	}

	return FAIL;
}

static uint64_t followExport(char* ptr_forward, unsigned long function_hash) {

	uint64_t _StrStrA = getFunctionPtr(HASH_SHLWAPI, HASH_STRSTRA);

	if (_StrStrA == 0x00)
		return FAIL;

	char del[] = { '.', 0x00 };
	char forward_dll[MAX_PATH] = { 0 };
	uint8_t i = 0;
	uint64_t fwd_dll_base = 0x00, forwarded_export = 0x00;

	while (*ptr_forward)
		forward_dll[i++] = *ptr_forward++;

	*(char*)((STRSTRA)_StrStrA)(forward_dll, del) = 0x00;

	fwd_dll_base = getDllBase(djb2((unsigned char*)forward_dll));
	if (fwd_dll_base == 0x00) {
		fwd_dll_base = loadDll_byName(forward_dll);
		if (fwd_dll_base == 0x00)
			return FAIL;
	}

	forwarded_export = parseHdrForPtr(fwd_dll_base, function_hash);

	return forwarded_export;

}

static uint64_t
getDllBase(unsigned long dll_hash) {

	_PPEB ptr_peb = NULL;
	PPEB_LDR_DATA ptr_ldr_data = NULL;
	PLDR_DATA_TABLE_ENTRY ptr_module_entry = NULL, ptr_start_module = NULL;
	PUNICODE_STR dll_name = NULL;

	ptr_peb = (_PEB*)__readgsqword(0x60);
	ptr_ldr_data = ptr_peb->pLdr;
	ptr_module_entry = ptr_start_module = (PLDR_DATA_TABLE_ENTRY)ptr_ldr_data->InMemoryOrderModuleList.Flink;

	do {

		dll_name = &ptr_module_entry->BaseDllName;

		if (dll_name->pBuffer == NULL)
			return FAIL;

		if (unicode_djb2(toLower(dll_name->pBuffer)) == dll_hash)
			return (uint64_t)ptr_module_entry->DllBase;

		ptr_module_entry = (PLDR_DATA_TABLE_ENTRY)ptr_module_entry->InMemoryOrderModuleList.Flink;

	} while (ptr_module_entry != ptr_start_module);

	return FAIL;

}

static unsigned long
djb2(unsigned char* str)
{
	unsigned long hash = 5381;
	int c;

	while ((c = *str++))
		hash = ((hash << 5) + hash) + c;

	return hash;
}

unsigned long
unicode_djb2(const wchar_t* str)
{

	unsigned long hash = 5381;
	DWORD val;

	while (*str != 0) {
		val = (DWORD)*str++;
		hash = ((hash << 5) + hash) + val;
	}

	return hash;

}

static WCHAR*
toLower(WCHAR* str)
{

	WCHAR* start = str;

	while (*str) {

		if (*str <= L'Z' && *str >= 'A') {
			*str += 32;
		}

		str += 1;

	}

	return start;

}