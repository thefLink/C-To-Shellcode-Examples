#include "windows.h"
#include "stdint.h"
#include "wbemidl.h"
#include "shobjidl.h"

#include "APIResolve.h"

#ifdef _DEBUG
int
main(int argc, char** argv) {
#else
int go() {
#endif

	COINITIALIZEEX _CoInitializeEx = (COINITIALIZEEX)getFunctionPtr(HASH_OLE32, HASH_CONITIALIZEEX);
	COCREATEINSTANCE _CoCreateinstance = (COCREATEINSTANCE)getFunctionPtr(HASH_OLE32, HASH_COCREATEINSTANCE);
	COINITIALIZESECURITY _CoInitializeSecurity = (COINITIALIZESECURITY)getFunctionPtr(HASH_OLE32, HASH_COINITIALIZESECURITY);
	COUNINITIALIZE _CoUnitialize = (COUNINITIALIZE)getFunctionPtr(HASH_OLE32, HASH_COUNINITIALIZE);
	SYSALLOCSTRING _SysAllocString = (SYSALLOCSTRING)getFunctionPtr(HASH_OLEAUT32, HASH_SYSALLOCSTRING);
	SYSFREESTRING _SysFreeString = (SYSFREESTRING)getFunctionPtr(HASH_OLEAUT32, HASH_SYSFREESTRING);
	LSTRCMPW _lstrcmpw = (LSTRCMPW)getFunctionPtr(HASH_KERNEL32, HASH_LSTRCMPW);
	
	WSPRINTFA _wsprintfA = (WSPRINTFA)getFunctionPtr(HASH_USER32, HASH_WSPRINTFA);
	MESSAGEBOXA _MessageBoxA = (MESSAGEBOXA)getFunctionPtr(HASH_USER32, HASH_MESSAGEBOXA);

	if (_CoInitializeEx == 0x00 || _CoCreateinstance == 0x00 || _CoInitializeSecurity == 0x00 || _CoUnitialize == 0x00 || _SysAllocString == 0x00 || _SysFreeString == 0x00 ||
		_lstrcmpw == NULL || _MessageBoxA == 0x00 || _wsprintfA == 0x00)
		return FAIL;

	GUID _CLSID_WbemLocator = { 0x4590f811, 0x1d3a, 0x11d0 , { 0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24 } };
	IID   _IID_IWbemLocator = { 0xdc12a687, 0x737f, 0x11cf , { 0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24 } };
	wchar_t w_server[] = {'R', 'O', 'O', 'T', '\\', 'C', 'I', 'M', 'V', '2', 0x00};
	wchar_t w_wql[] = { 'W', 'Q', 'L', 0x00 };
	wchar_t w_query[] = { 's', 'e', 'l', 'e', 'c', 't', ' ', 'n', 'a', 'm', 'e', ',', 'p', 'r', 'o', 'c', 'e', 's', 's', 'i', 'd', ' ', 'f', 'r' ,'o', 'm', 
		' ', 'W', 'i', 'n', '3','2','_', 'S', 'e','r','v', 'i','c','e', 0x00 };
	wchar_t w_nameservice[] = { 'E', 'v', 'e', 'n', 't', 'L', 'o', 'g', 0x00 };
	wchar_t w_column_name[] = { 'n', 'a', 'm', 'e', 0x00 };
	wchar_t w_column_processid[] = {'p' , 'r', 'o', 'c', 'e', 's', 's' , 'i', 'd', 0x00};

	BSTR bstr_server = NULL;
	BSTR bstr_wql = NULL;
	BSTR bstr_query = NULL;

	HRESULT h_res = 0;
	IWbemLocator* p_loc = NULL;
	IWbemServices* p_svc = NULL;
	IEnumWbemClassObject* p_enumerator = NULL;
	IWbemClassObject* p_cls_obj = NULL;
	VARIANT vt_prop;
	ULONG u_return = 0x00;
	DWORD dw_success = FAIL;
	uint32_t pid_eventservice = 0x00;

	bstr_server = _SysAllocString(w_server);
	bstr_wql = _SysAllocString(w_wql);
	bstr_query = _SysAllocString(w_query);

	if (bstr_server == NULL || bstr_wql == NULL || bstr_query == NULL)
		goto cleanup;

	h_res = _CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(h_res))
		return FAIL;

	h_res = _CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
	if (FAILED(h_res))
		goto cleanup;
	
	h_res = _CoCreateinstance(&_CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, &_IID_IWbemLocator, (LPVOID*)&p_loc);
	if (FAILED(h_res))
		goto cleanup;

	h_res = p_loc->lpVtbl->ConnectServer(p_loc, bstr_server, NULL, NULL, 0, 0, 0, 0, &p_svc);
	if (FAILED(h_res))
		goto cleanup;

	h_res = p_svc->lpVtbl->ExecQuery(p_svc, bstr_wql, bstr_query, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &p_enumerator);
	if (FAILED(h_res))
		goto cleanup;

	while (p_enumerator) {

		h_res = p_enumerator->lpVtbl->Next(p_enumerator, WBEM_INFINITE, 1, &p_cls_obj, &u_return);
		if (FAILED(h_res))
			goto cleanup;

		if (u_return == 0x00)
			break;

		h_res = p_cls_obj->lpVtbl->Get(p_cls_obj, w_column_name, 0, &vt_prop, 0, 0);
		if (FAILED(h_res))
			goto cleanup;

		if (!_lstrcmpw(vt_prop.bstrVal, w_nameservice)) {
			
			h_res = p_cls_obj->lpVtbl->Get(p_cls_obj, w_column_processid, 0, &vt_prop, 0, 0);
			if (FAILED(h_res))
				goto cleanup;

			pid_eventservice = vt_prop.lVal;

			char c_pid[512] = { 0x00 };
			char c_fmt[] = { '0', 'x', '%', 'x', 0x00 };

			_wsprintfA(c_pid, c_fmt, pid_eventservice);

			_MessageBoxA(0, c_pid, c_pid, 1);

			break;

		}

	}

	dw_success = SUCCESS;

cleanup:

	if (p_svc != NULL)
		p_svc->lpVtbl->Release(p_svc);

	if (p_loc != NULL)
		p_loc->lpVtbl->Release(p_loc);

	if (p_enumerator != NULL)
		p_enumerator->lpVtbl->Release(p_enumerator);

	if (p_cls_obj != NULL)
		p_cls_obj->lpVtbl->Release(p_cls_obj);

	if (bstr_server != NULL)
		_SysFreeString(bstr_server);

	if (bstr_query != NULL)
		_SysFreeString(bstr_query);

	if (bstr_wql != NULL)
		_SysFreeString(bstr_wql);

	_CoUnitialize();

	return dw_success;

}