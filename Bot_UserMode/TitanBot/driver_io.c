#include "driver_io.h"


BOOL SetupDriver(HANDLE hDriver, LPWSTR lpszDeviceName) {
	BOOL rv = FALSE;
	hDriver = CreateFileW(lpszDeviceName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
	if (hDriver != INVALID_HANDLE_VALUE) {
		rv = TRUE;
	}
	return rv;
}

BOOL SendData(HANDLE hDriver, LONG Control_Code, LPWSTR lpszData) {
	BOOL status = FALSE;
	HANDLE hControlDeviceEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (hControlDeviceEvent != NULL) {
		OVERLAPPED overlapped;
		ZeroBuffer(&overlapped, sizeof(OVERLAPPED));
		overlapped.hEvent = hControlDeviceEvent;
		BOOL rv = FALSE;
		switch (Control_Code) {
		case FILE_INSERT:
		{
			rv = DeviceIoControl(hDriver, FILE_INSERT, lpszData, (wcslen(lpszData) + 1) * sizeof(WCHAR), NULL, 0, NULL, &overlapped);
			break;
		}
		case REGISTRY_INSERT:
		{
			rv = DeviceIoControl(hDriver, REGISTRY_INSERT, lpszData, (wcslen(lpszData) + 1) * sizeof(WCHAR), NULL, 0, NULL, &overlapped);
			break;
		}
		}
		if (!rv && GetLastError() == ERROR_IO_PENDING) {
			DWORD dwBytesRead = 0;
			if (GetOverlappedResult(hDriver, &overlapped, &dwBytesRead, TRUE)) {
				status = TRUE;
			}
		}
		else if (rv) {
			status = TRUE;
		}
		CloseHandle(hControlDeviceEvent);
	}
	return status;
}