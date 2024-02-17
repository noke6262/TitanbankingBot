#ifndef DRIVER_INSTALL
#define DRIVER_INSTALL
#include "service.h"
#include "HTTP_Main.h"
BOOL DriverFileExists(LPWSTR);
BOOL DropDriver(LPWSTR);
BOOL InstallDriver(LPWSTR, LPWSTR);
#endif