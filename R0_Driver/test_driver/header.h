#include <fltKernel.h>
#include <Ntifs.h>
#include <ntddk.h>
#include <Ntstrsafe.h>
#include <wdmsec.h>
#include <wsk.h>
#pragma comment(lib, "Ntstrsafe.lib")

DRIVER_INITIALIZE DriverEntry;
PVOID hCallback = NULL;
LARGE_INTEGER liRegistry;
PDEVICE_OBJECT hGlobalDevice = NULL;
OB_CALLBACK_REGISTRATION Callback = { 0 };
OB_OPERATION_REGISTRATION Operation[1] = { {0} };
FLT_PREOP_CALLBACK_STATUS FltCreateFilePre(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);
NTSTATUS FilterSetup(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_SETUP_FLAGS Flags, DEVICE_TYPE VolumeDeviceType, FLT_FILESYSTEM_TYPE VolumeFilesystemType);
/*
Function codes 0-2047 are reserved for Microsoft; codes 2048-4095 are reserved for OEMs and IHVs.
A function code can be no larger then 4095
*/
#define REGISTRY_INSERT CTL_CODE(FILE_DEVICE_UNKNOWN, 2048, METHOD_IN_DIRECT, FILE_ANY_ACCESS)
#define FILE_INSERT CTL_CODE(FILE_DEVICE_UNKNOWN, 2049, METHOD_IN_DIRECT, FILE_ANY_ACCESS)
#define LOAD_KL_DRIVER CTL_CODE (FILE_DEVICE_UNKNOWN, 2050, METHOD_IN_DIRECT, FILE_ANY_ACCESS)
#define DEVICE_NAME (L"\\Device\\HandleResponse")
#define DOS_DEVICE_NAME (L"\\DosDevices\\HandleResponse")
#define PROCESS_CREATE_THREAD  (0x0002)
#define PROCESS_CREATE_PROCESS (0x0080)
#define PROCESS_TERMINATE      (0x0001) 
#define PROCESS_VM_WRITE       (0x0020)
#define PROCESS_VM_READ        (0x0010)
#define PROCESS_VM_OPERATION   (0x0008) 
#define PROCESS_SUSPEND_RESUME (0x0800)
#define PROCESS_SET_QUOTA (0x0100)
#define PROCESS_SET_INFORMATION (0x0200)
#define TAG 'aSed'
#define BUFFER_SIZE                     0x400   

typedef NTSYSAPI HANDLE(NTAPI *__PsGetCurrentProcessId)();
typedef NTSYSAPI VOID (NTAPI *__RtlInitUnicodeString)(
	PUNICODE_STRING         DestinationString,
	__drv_aliasesMem PCWSTR SourceString
);
typedef NTSTATUS (NTAPI *__WdmlibIoCreateDeviceSecure)(
	PDRIVER_OBJECT   DriverObject,
	ULONG            DeviceExtensionSize,
	PUNICODE_STRING  DeviceName,
	DEVICE_TYPE      DeviceType,
	ULONG            DeviceCharacteristics,
	BOOLEAN          Exclusive,
	PCUNICODE_STRING DefaultSDDLString,
	LPCGUID          DeviceClassGuid,
	PDEVICE_OBJECT   *DeviceObject
);

typedef NTSTATUS (NTAPI *__IoCreateSymbolicLink)(
	PUNICODE_STRING SymbolicLinkName,
	PUNICODE_STRING DeviceName
);
typedef VOID (NTAPI *__KeInitializeSpinLock)(
	PKSPIN_LOCK SpinLock
);

typedef NTSTATUS(NTAPI *__CmRegisterCallbackEx)(
	PEX_CALLBACK_FUNCTION Function,
	PCUNICODE_STRING      Altitude,
	PVOID                 Driver,
	PVOID                 Context,
	PLARGE_INTEGER        Cookie,
	PVOID                 Reserved
);
typedef NTSTATUS (NTAPI *__ObRegisterCallbacks)(
	POB_CALLBACK_REGISTRATION CallbackRegistration,
	PVOID                     *RegistrationHandle
);
typedef PVOID (NTAPI *__ExAllocatePoolWithTag)(
	__drv_strictTypeMatch(__drv_typeExpr)POOL_TYPE PoolType,
	SIZE_T                                         NumberOfBytes,
	ULONG                                          Tag
);
typedef NTSTATUS (NTAPI *__IoQueryFullDriverPath)(
	PDRIVER_OBJECT  DriverObject,
	PUNICODE_STRING FullPath
);
typedef VOID (FASTCALL *__IofCompleteRequest)(
	_In_ PIRP Irp,
	_In_ CCHAR PriorityBoost
);
typedef KIRQL (FASTCALL *__KfAcquireSpinLock)(
	_Inout_ PKSPIN_LOCK SpinLock
);
typedef VOID (FASTCALL *__KfReleaseSpinLock)(
	_Inout_ PKSPIN_LOCK SpinLock,
	_In_ _IRQL_restores_ KIRQL NewIrql
);
typedef ULONG (NTAPI *__IoGetRequestorProcessId)(
	_In_ PIRP Irp
);
typedef NTSTATUS (NTAPI *__CmUnRegisterCallback)(_In_ LARGE_INTEGER    Cookie);
typedef VOID (NTAPI *__ObUnRegisterCallbacks)(
	PVOID RegistrationHandle
);
typedef NTSTATUS (NTAPI *__PsRemoveCreateThreadNotifyRoutine)(
	_In_ PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine
);
typedef NTSTATUS (NTAPI *__IoDeleteSymbolicLink)(
	_In_ PUNICODE_STRING SymbolicLinkName
);
typedef VOID (NTAPI *__IoDeleteDevice)(
	_In_ __drv_freesMem(Mem) PDEVICE_OBJECT DeviceObject
);
typedef NTSTATUS (NTAPI *__ObQueryNameString)(
	_In_ PVOID Object,
	_Out_writes_bytes_opt_(Length) POBJECT_NAME_INFORMATION ObjectNameInfo,
	_In_ ULONG Length,
	_Out_ PULONG ReturnLength
);
typedef HANDLE (NTAPI *__PsGetCurrentProcessId)(
	
);
typedef HANDLE (NTAPI *__PsGetProcessId)(
	_In_ PEPROCESS Process
);
typedef LONG (NTAPI *__RtlCompareUnicodeString)(
	_In_ PCUNICODE_STRING String1,
	_In_ PCUNICODE_STRING String2,
	_In_ BOOLEAN CaseInSensitive
);

__PsGetCurrentProcessId _PsGetCurrentProcessId;
__RtlInitUnicodeString _RtlInitUnicodeString;
__WdmlibIoCreateDeviceSecure _WdmlibIoCreateDeviceSecure;
__IoCreateSymbolicLink _IoCreateSymbolicLink;
__KeInitializeSpinLock _KeInitializeSpinLock;
__CmRegisterCallbackEx _CmRegisterCallbackEx;
__ObRegisterCallbacks _ObRegisterCallbacks;
__ExAllocatePoolWithTag _ExAllocatePoolWithTag;
__IoQueryFullDriverPath _IoQueryFullDriverPath;
__IofCompleteRequest _IofCompleteRequest;
__KfAcquireSpinLock _KfAcquireSpinLock;
__KfReleaseSpinLock _KfReleaseSpinLock;
__IoGetRequestorProcessId _IoGetRequestorProcessId;
__CmUnRegisterCallback _CmUnRegisterCallback;
__ObUnRegisterCallbacks _ObUnRegisterCallbacks;
__PsRemoveCreateThreadNotifyRoutine _PsRemoveCreateThreadNotifyRoutine;
__IoDeleteSymbolicLink _IoDeleteSymbolicLink;
__IoDeleteDevice _IoDeleteDevice;
__ObQueryNameString _ObQueryNameString;
__PsGetCurrentProcessId _PsGetCurrentProcessId;
__PsGetProcessId _PsGetProcessId;
__RtlCompareUnicodeString _RtlCompareUnicodeString;

//FltGetRoutineAddress 
typedef NTSTATUS (FLTAPI *__FltRegisterFilter)(
	PDRIVER_OBJECT         Driver,
	const FLT_REGISTRATION *Registration,
	PFLT_FILTER            *RetFilter
);
typedef NTSTATUS (FLTAPI *__FltStartFiltering)(
	PFLT_FILTER Filter
);
typedef VOID (FLTAPI *__FltUnregisterFilter)(
	_In_ PFLT_FILTER Filter
);
typedef VOID (FLTAPI *__FltReleaseFileNameInformation)(
	_In_ PFLT_FILE_NAME_INFORMATION FileNameInformation
);
typedef NTSTATUS (FLTAPI *__FltGetFileNameInformation)(
	_In_ PFLT_CALLBACK_DATA CallbackData,
	_In_ FLT_FILE_NAME_OPTIONS NameOptions,
	_Outptr_ PFLT_FILE_NAME_INFORMATION *FileNameInformation
);
__FltRegisterFilter _FltRegisterFilter;
__FltStartFiltering _FltStartFiltering;
__FltUnregisterFilter _FltUnregisterFilter;
__FltReleaseFileNameInformation _FltReleaseFileNameInformation;
__FltGetFileNameInformation _FltGetFileNameInformation;