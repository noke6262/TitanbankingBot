#include "driver_query.h"

BOOL IsServiceRunning(LPWSTR lpszService)
{
	BOOL rv = FALSE;
	SC_HANDLE hSCM = _OpenSCManagerW(0, 0, SC_MANAGER_ALL_ACCESS);
	if (hSCM) {
		SC_HANDLE hService = _OpenServiceW(hSCM, lpszService, SERVICE_QUERY_STATUS);
		if (hService) {
			SERVICE_STATUS ss;
			if (_QueryServiceStatus(hService, &ss) && ss.dwCurrentState) {
				if (ss.dwCurrentState == SERVICE_RUNNING || ss.dwCurrentState == SERVICE_START_PENDING) {
					rv = TRUE;
				}
			}
			_CloseServiceHandle(hService);
		}
		_CloseServiceHandle(hSCM);
	}
	return rv;
}
