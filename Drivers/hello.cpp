/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 RanShaoEFCH
 *
 * EDiskFreeze - A lightweight reboot-to-restore disk protection driver.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include <ntstrsafe.h>
#include <wchar.h>
#include <ntimage.h>
#include <windef.h>
#include <minwindef.h>
#include <stdlib.h>
#include <fltKernel.h>
#include <intrin.h>
#include "h/IrpFile.h"
#include "h/DataVerify.h"
#include "h/common.h"
#include "h/diskhook.h"

#if defined(_DEBUG) || defined(DBG)
#define DbgPrint(...) (DbgPrint)(__VA_ARGS__)
#else
#define DbgPrint(...) ((void)0)
#endif

PDRIVER_OBJECT driver;
PDEVICE_OBJECT deviceObject = NULL;
#define IOCTL_KILLPROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS) //ZwTerminateProcess
#define IOCTL_SUSPENDPROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS) //PsSuspendProcess
#define IOCTL_RESUMEPROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS) //PsResumeProcess

#define IOCTL_PROTECTPROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS) //ObRegisterCallbacks
#define IOCTL_UNPROTECTPROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS) //ObRegisterCallbacks
#define IOCTL_SETPPL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS) //设置PP/PPL
#define IOCTL_SETPROCESSCRITICAL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS) //ZwSetInformationProcess
#define IOCTL_EPROCESSENUMPROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS) //EProcessEnumProcess
#define IOCTL_GETPPL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80C, METHOD_BUFFERED, FILE_ANY_ACCESS) //GetPPL
#define IOCTL_GETPROCESSIMAGENAME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80E, METHOD_BUFFERED, FILE_ANY_ACCESS) //SeLocateProcessImageName

#define IOCTL_OCCUPYFILE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS) //ZwCreateFile
#define IOCTL_WRITEDISK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS) //ZwWriteFile
#define IOCTL_FORCEDELETEFILE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x905, METHOD_BUFFERED, FILE_ANY_ACCESS) //IrpDeleteFile
#define IOCTL_FORCEWRITEDISK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x906, METHOD_BUFFERED, FILE_ANY_ACCESS) //IrpWriteFile
#define IOCTL_FORCEOCCUPYFILE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x907, METHOD_BUFFERED, FILE_ANY_ACCESS) //IrpCreateFile
#define IOCTL_FORCEWRITEFILE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x908, METHOD_BUFFERED, FILE_ANY_ACCESS) //IrpCreateFile+IrpWriteFile
#define IOCTL_IRPQUERYFILEANDFOLDERS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x909, METHOD_BUFFERED, FILE_ANY_ACCESS) //IrpQueryDirectoryFile
#define IOCTL_IRPSETINFORMATIONFILE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x90A, METHOD_BUFFERED, FILE_ANY_ACCESS) //_IrpSetInformationFile
#define IOCTL_IRPRENAMEFILE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x90B, METHOD_BUFFERED, FILE_ANY_ACCESS) //_IrpSetInformationFile

#define IOCTL_ZWWRITEFILE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x910, METHOD_BUFFERED, FILE_ANY_ACCESS) //ZwWriteFile

#define IOCTL_IRPREADFILE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x912, METHOD_BUFFERED, FILE_ANY_ACCESS) //IrpReadFile
#define IOCTL_IRPGETFILESIZE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x913, METHOD_BUFFERED, FILE_ANY_ACCESS) //IrpQueryInformationFile
#define IOCTL_IRPREADDISK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x914, METHOD_BUFFERED, FILE_ANY_ACCESS) //IrpReadDisk
#define IOCTL_IRPGETFILEANDFOLDERQUANTITY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x915, METHOD_BUFFERED, FILE_ANY_ACCESS) //Fs_GetFileAndFolderQuantity_UNICODE_Irp
#define IOCTL_POSIXFORCEDELETEFILE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x916, METHOD_BUFFERED, FILE_ANY_ACCESS) //IrpDeleteFile,只支持Win10RS3+
#define IOCTL_FORCEWRITEDISKBYPASSDISKHOOK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x917, METHOD_BUFFERED, FILE_ANY_ACCESS) //IrpWriteFile
#define IOCTL_FORCEREADDISKBYPASSDISKHOOK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x918, METHOD_BUFFERED, FILE_ANY_ACCESS) //IrpWriteFile

#define IOCTL_KEBUGCHECK CTL_CODE(FILE_DEVICE_UNKNOWN, 0xB00, METHOD_BUFFERED, FILE_ANY_ACCESS) //KeBugCheck
#define IOCTL_SYSTEMBSOD CTL_CODE(FILE_DEVICE_UNKNOWN, 0xB01, METHOD_BUFFERED, FILE_ANY_ACCESS) //KeBugCheck

#define IOCTL_HALPOWERCONTROL CTL_CODE(FILE_DEVICE_UNKNOWN, 0xB05, METHOD_BUFFERED, FILE_ANY_ACCESS) //HalReturnToFirmware

#define IOCTL_SENDDATA_TO_PORT CTL_CODE(FILE_DEVICE_UNKNOWN, 0xB0B, METHOD_BUFFERED, FILE_ANY_ACCESS) //Send data to port
#define IOCTL_READDATA_IN_PORT CTL_CODE(FILE_DEVICE_UNKNOWN, 0xB0C, METHOD_BUFFERED, FILE_ANY_ACCESS) //Read data in port
#define IOCTL_ENUMDRIVERS CTL_CODE(FILE_DEVICE_UNKNOWN, 0xB0D, METHOD_BUFFERED, FILE_ANY_ACCESS) //Enum Drivers
#define IOCTL_ENUMDEVICES CTL_CODE(FILE_DEVICE_UNKNOWN, 0xB0E, METHOD_BUFFERED, FILE_ANY_ACCESS) //Enum Devices

#define IOCTL_ENUMDRIVERSPATH CTL_CODE(FILE_DEVICE_UNKNOWN, 0xB10, METHOD_BUFFERED, FILE_ANY_ACCESS) //Enum Drivers Path

#define IOCTL_HOOK_QUERYSTATUS CTL_CODE(FILE_DEVICE_UNKNOWN, 0xD05, METHOD_BUFFERED, FILE_ANY_ACCESS) //Query Hook Status

#define IOCTL_ESECURITY_SETPROTECTSTATUS CTL_CODE(FILE_DEVICE_UNKNOWN, 0xD52, METHOD_BUFFERED, FILE_ANY_ACCESS) //Set Protect Status
#define IOCTL_EDISKPROTECT_SETPROTECTSECTORS CTL_CODE(FILE_DEVICE_UNKNOWN, 0xD53, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ESECURITY_GETPROTECTSTATUS CTL_CODE(FILE_DEVICE_UNKNOWN, 0xD54, METHOD_BUFFERED, FILE_ANY_ACCESS) //

#define IOCTL_BUILDTEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0xFFF, METHOD_BUFFERED, FILE_ANY_ACCESS) //Build Test

#define DEVICE_NAME_SHORT     L"EDiskFreezeDrv64"
#define DEVICE_NAME     L"\\Device\\EDiskFreezeDrv64"   
#define DOS_DEVICE_NAME L"\\DosDevices\\EDiskFreezeDrv64" 

#define PROCESS_ACTIVE_PROCESS_LINKS_OFFSET	0x188
#define PROCESS_FLAG_OFFSET					0x440
#define PROCESS_TERMINATE                  (0x0001)
#define PROCESS_CREATE_THREAD              (0x0002)
#define PROCESS_SET_SESSIONID              (0x0004)
#define PROCESS_VM_OPERATION               (0x0008)
#define PROCESS_VM_READ                    (0x0010)
#define PROCESS_VM_WRITE                   (0x0020)
#define PROCESS_DUP_HANDLE                 (0x0040)
#define PROCESS_CREATE_PROCESS             (0x0080)
#define PROCESS_SET_QUOTA                  (0x0100)
#define PROCESS_SET_INFORMATION            (0x0200)
#define PROCESS_QUERY_INFORMATION          (0x0400)
#define PROCESS_SUSPEND_RESUME             (0x0800)
#define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)
#define PROCESS_SET_LIMITED_INFORMATION    (0x2000)

#define MAX_PROTECTED_PIDS 256
#define CUSTOM_ALTITUDE L"321240"

#define PPL_None 0x00
#define PPL_Authenticode 0x11
#define PPL_CodeGen 0x21
#define PPL_Antimalware 0x31
#define PPL_Lsa 0x41
#define PPL_Windows 0x51
#define PPL_WinTcb 0x61
#define PPL_WinSystem 0x71

#define PP_Authenticode 0x12
#define PP_CodeGen 0x22
#define PP_Antimalware 0x32
#define PP_Lsa 0x42
#define PP_Windows 0x52
#define PP_WinTcb 0x62
#define PP_WinSystem 0x72

#define GDI_HANDLE_BUFFER_SIZE 34
#define RTL_MAX_DRIVE_LETTERS 32

#define IA32_FEATURE_CONTROL 0x3A
#define IA32_VMX_BASIC 0x480
#define CR4_VMXE 0x00002000UL

#ifndef STATUS_HV_FEATURE_UNAVAILABLE
#define STATUS_HV_FEATURE_UNAVAILABLE ((NTSTATUS)0xC0350002L)
#endif

#define SYSTEM_ADDRESS_START 0x00007ffffffeffff
#define SYSTEM_ADDRESS_START32 0x7fffffff

HANDLE MyProcess;

#ifdef NDEBUG
#define DbgPrint(...) ((void)0)
#endif

#define MAX_DRIVER_COUNT 1024;

#define HOOK_MAX_PROTECTED_PROCESSES 128
HANDLE HOOK_ProtectedProcesses[HOOK_MAX_PROTECTED_PROCESSES];
ULONG HOOK_ProtectedProcessCount = 0;
BOOLEAN HOOK_PROTECTPROCESS_STARTED;

#define HOOK_MAX_PROTECTED_THREADS 512
HANDLE HOOK_ProtectedThreads[HOOK_MAX_PROTECTED_THREADS];
ULONG HOOK_ProtectedThreadCount = 0;
BOOLEAN HOOK_PROTECTTHREAD_STARTED;

PVOID g_RegistrationHandle = NULL;
FAST_MUTEX g_ProtectLock;
ULONG g_ProtectedPids[MAX_PROTECTED_PIDS] = { 0 };

ULONG ProtectionOffset = 0x87a;
ULONG_PTR Offset_hp = 0;
ULONG BreakOnTerminationOffset = 0x464;
ULONG UniqueProcessIdOffset = 0x440;
ULONG Flags2Offset = 0x460;
ULONG FlagsOffset = 0x464;
ULONG TokenOffset = 0x4b8;
ULONG PEBOffset = 0x550;
ULONG ThreadListHandOffset = 0x5e0;
ULONG ET_ThreadListEntryOffset = 0x690;
ULONG ET_StartAddressOffset = 0x658;
ULONG KT_MiscFlagsOffset = 0x74;
ULONG KT_SystemThreadBit = 10;

ULONG g_ImageNameOffset = 0x450;

BOOLEAN HookLoaded = FALSE;
BOOLEAN KeBugCheckExIsHooked = FALSE;
BOOLEAN DisableLoadDriver_ = FALSE;
BOOLEAN DisableCreateProcess_ = FALSE;
BOOLEAN DisableRegisterControl_ = FALSE;
BOOLEAN EnableDiskFreeze = FALSE;

BOOLEAN CanUnload = FALSE;
BOOLEAN FirstCreateDone = FALSE;

WCHAR EDF_Password[128] = { 0 };

#if (NTDDI_VERSION >= NTDDI_WIN10_RS1)
#define PSGETNEXTPROCESS(proc) PsGetNextProcess(proc)
#else
#define PSGETNEXTPROCESS(proc) PsGetNextProcess(proc, 0)
#endif
#define THREAD_QUERY_INFORMATION				(0x0040)  

EXTERN_C_START
NTSTATUS ZwAdjustPrivilegesToken(IN HANDLE TokenHandle,
	IN BOOLEAN DisableAllPrivileges,
	IN PTOKEN_PRIVILEGES NewState OPTIONAL,
	IN ULONG BufferLength OPTIONAL,
	OUT PTOKEN_PRIVILEGES PreviousState OPTIONAL,
	OUT PULONG ReturnLength);
NTSTATUS
ZwSetInformationProcess(
	IN HANDLE                    ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	IN PVOID                     ProcessInformation,
	IN ULONG                     ProcessInformationLength);
/*
NTSTATUS NTAPI ZwQuerySystemInformation(
	DWORD32 systemInformationClass,
	PVOID systemInformation,
	ULONG systemInformationLength,
	PULONG returnLength);
*/

NTSTATUS ZwOpenThread(
	_Out_  PHANDLE ThreadHandle,
	_In_   ACCESS_MASK DesiredAccess,
	_In_   POBJECT_ATTRIBUTES ObjectAttributes,
	_In_   PCLIENT_ID ClientId
);
NTKERNELAPI PVOID NTAPI ObGetObjectType(IN PVOID pObject);
NTSTATUS NTAPI ObReferenceObjectByName(IN PUNICODE_STRING ObjectName, IN ULONG64 Attributes, IN PACCESS_STATE PassedAccessState OPTIONAL, IN ACCESS_MASK DesiredAccess OPTIONAL, IN POBJECT_TYPE ObjectType, IN KPROCESSOR_MODE AccessMode, IN OUT PVOID ParseContext OPTIONAL, OUT PVOID* Object);
NTSTATUS PsSuspendProcess(PEPROCESS Process);
NTSTATUS PsResumeProcess(PEPROCESS Process);

/*/NTSTATUS SeCreateAccessState(
	PACCESS_STATE AccessState,
	PVOID AuxData,
	ACCESS_MASK DesiredAccess,
	PGENERIC_MAPPING GenericMapping
);
NTSTATUS ObCreateObject(
	__in KPROCESSOR_MODE ProbeMode,
	__in POBJECT_TYPE ObjectType,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in KPROCESSOR_MODE OwnershipMode,
	__inout_opt PVOID ParseContext,
	__in ULONG ObjectBodySize,
	__in ULONG PagedPoolCharge,
	__in ULONG NonPagedPoolCharge,
	__out PVOID* Object
);
*/
NTSYSAPI
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(
	IN PVOID                ModuleAddress);
VOID IoUnregisterPriorityCallback(_In_ PDRIVER_OBJECT DriverObject);
VOID PoUnregisterCoalescingCallback(
	_In_  PVOID Handle);

NTSTATUS PsSetCreateProcessNotifyRoutineEx2(
	PSCREATEPROCESSNOTIFYTYPE NotifyType,
	PVOID                     NotifyInformation,
	BOOLEAN                   Remove
);

PVOID NTAPI RtlFindExportedRoutineByName(_In_ PVOID ImageBase, _In_ PCCH RoutineName);
NTKERNELAPI VOID NTAPI HalReturnToFirmware(
	LONG lReturnType
);

VOID
_sgdt(
	_Out_ PVOID Descriptor
);
NTKERNELAPI PPEB NTAPI PsGetProcessPeb(IN PEPROCESS Process);
NTKERNELAPI PVOID NTAPI PsGetThreadTeb(PETHREAD pEthread);
NTKERNELAPI NTSTATUS
PsReferenceProcessFilePointer(
	IN PEPROCESS Process,
	OUT PVOID* pFilePointer
);
NTSYSAPI
UCHAR*
PsGetProcessImageFileName(
	PEPROCESS Process
);
EXTERN_C_END
/*
typedef NTSTATUS(__fastcall* _PspTerminateProcess)(
	PVOID Process,       // EPROCESS (rcx)
	PVOID Thread,        // 当前线程 (rdx)
	NTSTATUS ExitStatus, // 退出状态码 (r8)
	ULONG Flags          // 控制标志 (r9)
	);// For Windows 10 22H2 19045.6216
_PspTerminateProcess pspTerminateProcess = NULL;
*/

typedef unsigned int(__fastcall* _PspTerminateProcess)(
	__int64 Process,     // EPROCESS (RCX)
	__int64 Thread,      // ETHREAD (RDX) 
	unsigned int ExitCode, // 退出状态码 (R8)
	int Flags           // 控制标志 (R9)
	);
_PspTerminateProcess pspTerminateProcess = NULL;

typedef NTSTATUS(__stdcall* _NtTerminateProcess)(
	HANDLE ProcessHandle,
	NTSTATUS ExitStatus
	);
static PVOID ntterminateprocess = NULL;

typedef NTSTATUS(__stdcall* _PsSuspendProcess)(
	PEPROCESS Process
	);

static PVOID pssuspendprocess = NULL;
static PVOID ntdeviceiocontrolfile = NULL;

typedef void(__stdcall* _KeBugCheckEx)(
	_In_ ULONG BugCheckCode,
	_In_ ULONG_PTR BugCheckParameter1,
	_In_ ULONG_PTR BugCheckParameter2,
	_In_ ULONG_PTR BugCheckParameter3,
	_In_ ULONG_PTR BugCheckParameter4
	);

typedef NTSTATUS(NTAPI* _NtDeviceIoControlFile)(
	HANDLE FileHandle,
	HANDLE Event,
	PIO_APC_ROUTINE ApcRoutine,
	PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG IoControlCode,
	PVOID InputBuffer,
	ULONG InputBufferLength,
	PVOID OutputBuffer,
	ULONG OutputBufferLength
	);

static PVOID kebugcheckex = NULL;

typedef struct _LDR_DATA
{
	struct _LIST_ENTRY InLoadOrderLinks;
	struct _LIST_ENTRY InMemoryOrderLinks;
	struct _LIST_ENTRY InInitializationOrderLinks;
	VOID* DllBase;
	VOID* EntryPoint;
	ULONG32      SizeOfImage;
	UINT8        _PADDING0_[0x4];
	struct _UNICODE_STRING FullDllName;
	struct _UNICODE_STRING BaseDllName;
	ULONG32      Flags;
}LDR_DATA, * PLDR_DATA;

typedef struct _DATA_INFO {
	WCHAR wcstr[1024];
	ULONG ulongdata4;
} DATA_INFO, * PDATA_INFO;

typedef struct _DRIVERS_INFO {
	WCHAR wcstr[1024];
	ULONG BaseAddress;

} DRIVERS_INFO, * PDRIVERS_INFO;

enum FIRMWARE_REENTRY
{
	HalHaltRoutine,
	HalPowerDownRoutine,
	HalRestartRoutine,
	HalRebootRoutine,
	HalInteractiveModeRoutine,
	HalMaximumRoutine
} FIRMWARE_REENTRY, * PFIRMWARE_REENTRY;

typedef struct _PROCESS_BREAK_ON_TERMINATION {
	ULONG BreakOnTermination;
} PROCESS_BREAK_ON_TERMINATION, * PPROCESS_BREAK_ON_TERMINATION;

typedef struct _APC_CONTEXT {
	PEPROCESS TargetProcess;
	PETHREAD TargetThread;
} APC_CONTEXT, * PAPC_CONTEXT;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
	struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
	struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
	VOID* DllBase;                                                          //0x30
	VOID* EntryPoint;                                                       //0x38
	ULONG SizeOfImage;                                                      //0x40
	struct _UNICODE_STRING FullDllName;                                     //0x48
	struct _UNICODE_STRING BaseDllName;                                     //0x58
	union
	{
		UCHAR FlagGroup[4];                                                 //0x68
		ULONG Flags;                                                        //0x68
		struct
		{
			ULONG PackagedBinary : 1;                                         //0x68
			ULONG MarkedForRemoval : 1;                                       //0x68
			ULONG ImageDll : 1;                                               //0x68
			ULONG LoadNotificationsSent : 1;                                  //0x68
			ULONG TelemetryEntryProcessed : 1;                                //0x68
			ULONG ProcessStaticImport : 1;                                    //0x68
			ULONG InLegacyLists : 1;                                          //0x68
			ULONG InIndexes : 1;                                              //0x68
			ULONG ShimDll : 1;                                                //0x68
			ULONG InExceptionTable : 1;                                       //0x68
			ULONG ReservedFlags1 : 2;                                         //0x68
			ULONG LoadInProgress : 1;                                         //0x68
			ULONG LoadConfigProcessed : 1;                                    //0x68
			ULONG EntryProcessed : 1;                                         //0x68
			ULONG ProtectDelayLoad : 1;                                       //0x68
			ULONG ReservedFlags3 : 2;                                         //0x68
			ULONG DontCallForThreads : 1;                                     //0x68
			ULONG ProcessAttachCalled : 1;                                    //0x68
			ULONG ProcessAttachFailed : 1;                                    //0x68
			ULONG CorDeferredValidate : 1;                                    //0x68
			ULONG CorImage : 1;                                               //0x68
			ULONG DontRelocate : 1;                                           //0x68
			ULONG CorILOnly : 1;                                              //0x68
			ULONG ChpeImage : 1;                                              //0x68
			ULONG ReservedFlags5 : 2;                                         //0x68
			ULONG Redirected : 1;                                             //0x68
			ULONG ReservedFlags6 : 2;                                         //0x68
			ULONG CompatDatabaseProcessed : 1;                                //0x68
		};
	};
	USHORT ObsoleteLoadCount;                                               //0x6c
	USHORT TlsIndex;                                                        //0x6e
	struct _LIST_ENTRY HashLinks;                                           //0x70
	ULONG TimeDateStamp;                                                    //0x80
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
	VOID* Lock;                                                             //0x90
	struct _LDR_DDAG_NODE* DdagNode;                                        //0x98
	struct _LIST_ENTRY NodeModuleLink;                                      //0xa0
	struct _LDRP_LOAD_CONTEXT* LoadContext;                                 //0xb0
	VOID* ParentDllBase;                                                    //0xb8
	VOID* SwitchBackContext;                                                //0xc0
	struct _RTL_BALANCED_NODE BaseAddressIndexNode;                         //0xc8
	struct _RTL_BALANCED_NODE MappingInfoIndexNode;                         //0xe0
	ULONGLONG OriginalBase;                                                 //0xf8
	union _LARGE_INTEGER LoadTime;                                          //0x100
	ULONG BaseNameHashValue;                                                //0x108
	enum _LDR_DLL_LOAD_REASON LoadReason;                                   //0x10c
	ULONG ImplicitPathOptions;                                              //0x110
	ULONG ReferenceCount;                                                   //0x114
	ULONG DependentLoadFlags;                                               //0x118
	UCHAR SigningLevel;                                                     //0x11c
}LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _OBJECT_DIRECTORY_INFORMATION {
	UNICODE_STRING Name;
	UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;

typedef NTSTATUS(NTAPI* ZWQUERYDIRECTORYOBJECT)(
	_In_ HANDLE DirectoryHandle,
	_Out_opt_ PVOID Buffer,
	_In_ ULONG Length,
	_In_ BOOLEAN ReturnSingleEntry,
	_In_ BOOLEAN RestartScan,
	_Inout_ PULONG Context,
	_Out_opt_ PULONG ReturnLength
	);

typedef struct _UNLOAD_THREAD_CONTEXT {
	PDRIVER_OBJECT DriverObject;
	BOOLEAN HasUnloadRoutine;
	KEVENT CompletionEvent;
	NTSTATUS Result;
} UNLOAD_THREAD_CONTEXT, * PUNLOAD_THREAD_CONTEXT;

typedef struct _Lite_Driver_Info {
	WCHAR BaseDllName[512];
} Lite_Driver_Info, * PLite_Driver_Info;

typedef struct _Lite_Driver_Info2 {
	WCHAR BaseDllName[512];
} Lite_Driver_Info2, * PLite_Driver_Info2;

PLDR_DATA_TABLE_ENTRY ntoskrnl_PLDR;

BOOLEAN IsAddressValid(PVOID Address)
{
	__try
	{
		volatile UCHAR test = *(PUCHAR)Address;
		return TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return FALSE;
	}
}

VOID UnicodeToChar(PUNICODE_STRING dst, char* src)
{
	ANSI_STRING string;
	RtlUnicodeStringToAnsiString(&string, dst, TRUE);
	strcpy(src, string.Buffer);
	RtlFreeAnsiString(&string);
}

WCHAR ProbeForReadChar(_In_ PWCHAR Address)
{
	__try {
		// 验证内存可读
		ProbeForRead(Address, sizeof(WCHAR), sizeof(WCHAR));
		return *Address;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return 0;
	}
}

__forceinline BOOLEAN IsUserModeAddress(PVOID Address)
{
	return ((ULONG_PTR)Address < (ULONG_PTR)MmHighestUserAddress);
}

BOOLEAN UnicodeStringContainsManual(
	_In_ PUNICODE_STRING Source,
	_In_ PUNICODE_STRING Target,
	_In_ BOOLEAN CaseInsensitive
)
{
	USHORT sourceLen = Source->Length / sizeof(WCHAR);
	USHORT targetLen = Target->Length / sizeof(WCHAR);

	if (sourceLen < targetLen || targetLen == 0) {
		return FALSE;
	}

	PWCHAR sourceBuf = Source->Buffer;
	PWCHAR targetBuf = Target->Buffer;

	for (USHORT i = 0; i <= sourceLen - targetLen; i++) {
		BOOLEAN found = TRUE;

		for (USHORT j = 0; j < targetLen; j++) {
			WCHAR srcChar = sourceBuf[i + j];
			WCHAR tgtChar = targetBuf[j];

			if (CaseInsensitive) {
				srcChar = RtlUpcaseUnicodeChar(srcChar);
				tgtChar = RtlUpcaseUnicodeChar(tgtChar);
			}

			if (srcChar != tgtChar) {
				found = FALSE;
				break;
			}
		}

		if (found) {
			return TRUE;
		}
	}

	return FALSE;
}

BOOLEAN SafeUnicodeStringContainsUniversal(
	_In_ PUNICODE_STRING Source,
	_In_ PUNICODE_STRING Target,
	_In_ BOOLEAN CaseInsensitive
)
{
	NTSTATUS status = STATUS_SUCCESS;
	BOOLEAN result = FALSE;

	if (Source == NULL || Target == NULL ||
		Source->Buffer == NULL || Target->Buffer == NULL) {
		return FALSE;
	}

	// 判断内存类型
	BOOLEAN sourceIsUser = IsUserModeAddress(Source->Buffer);
	BOOLEAN targetIsUser = IsUserModeAddress(Target->Buffer);

	// 如果都是内核内存，可以直接访问
	if (!sourceIsUser && !targetIsUser) {
		return UnicodeStringContainsManual(Source, Target, CaseInsensitive);
	}

	// 如果有用户内存，需要复制到内核缓冲区
	PWCHAR sourceCopy = NULL;
	PWCHAR targetCopy = NULL;
	ULONG sourceCopySize = 0;
	ULONG targetCopySize = 0;

	__try {
		// 分配内核缓冲区
		sourceCopySize = Source->Length + sizeof(WCHAR);
		targetCopySize = Target->Length + sizeof(WCHAR);

		sourceCopy = (PWCHAR)ExAllocatePoolWithTag(
			NonPagedPoolNx,  // 使用NX内存，防止执行
			sourceCopySize,
			'StrC'
		);

		targetCopy = (PWCHAR)ExAllocatePoolWithTag(
			NonPagedPoolNx,
			targetCopySize,
			'StrC'
		);

		if (sourceCopy == NULL || targetCopy == NULL) {
			DbgPrint("[ERROR] ExAllocatePoolWithTag\n");
			__leave;
		}

		RtlZeroMemory(sourceCopy, sourceCopySize);
		RtlZeroMemory(targetCopy, targetCopySize);

		// 复制源字符串
		if (sourceIsUser) {
			// 用户内存：安全复制
			__try {
				for (ULONG i = 0; i < Source->Length / sizeof(WCHAR); i++) {
					sourceCopy[i] = ProbeForReadChar(&Source->Buffer[i]);
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				DbgPrint("[WARN] Read Failed\n");
				__leave;
			}
		}
		else {
			// 内核内存：直接复制
			RtlCopyMemory(sourceCopy, Source->Buffer, Source->Length);
		}

		// 复制目标字符串
		if (targetIsUser) {
			// 用户内存：安全复制
			__try {
				for (ULONG i = 0; i < Target->Length / sizeof(WCHAR); i++) {
					targetCopy[i] = ProbeForReadChar(&Target->Buffer[i]);
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				DbgPrint("[WARN] Read Failed\n");
				__leave;
			}
		}
		else {
			// 内核内存：直接复制
			RtlCopyMemory(targetCopy, Target->Buffer, Target->Length);
		}

		// 创建安全的UNICODE_STRING结构
		UNICODE_STRING safeSource, safeTarget;

		safeSource.Buffer = sourceCopy;
		safeSource.Length = Source->Length;
		safeSource.MaximumLength = (USHORT)sourceCopySize;

		safeTarget.Buffer = targetCopy;
		safeTarget.Length = Target->Length;
		safeTarget.MaximumLength = (USHORT)targetCopySize;

		// 进行比较
		result = UnicodeStringContainsManual(&safeSource, &safeTarget, CaseInsensitive);

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("[ERROR] EXCEPTION_EXECUTE_HANDLER\n");
		result = FALSE;
	}

	// 清理内存
	if (sourceCopy) {
		ExFreePoolWithTag(sourceCopy, 'StrC');
	}
	if (targetCopy) {
		ExFreePoolWithTag(targetCopy, 'StrC');
	}

	return result;
}

typedef enum _SHUTDOWN_ACTION {
	ShutdownNoReboot = 0,   // 关闭系统
	ShutdownReboot,         // 重启系统
	ShutdownPowerOff         // 关闭电源
} SHUTDOWN_ACTION;

static NTSTATUS
(__fastcall* NtSuspendThread)(
	__in HANDLE ThreadHandle,
	__out_opt PULONG PreviousSuspendCount
	);
static NTSTATUS
(__fastcall* NtResumeThread)(
	__in HANDLE ThreadHandle,
	__out_opt PULONG PreviousSuspendCount
	);
static NTSTATUS
(__fastcall* NtTerminateThread)(
	__in_opt HANDLE ThreadHandle,
	__in NTSTATUS ExitStatus
	);

/*
typedef NTSTATUS (NTAPI *PNT_SHUTDOWN_SYSTEM)(
	_In_ SHUTDOWN_ACTION Action
);
*/
static NTSTATUS
(__fastcall* NtShutdownSystem)(
	_In_ SHUTDOWN_ACTION Action
	);
typedef unsigned long ULONG;
typedef unsigned short wchar_t;
typedef unsigned long DWORD;
typedef int                 BOOL;
#define RANDOM_SEED_INIT 0x3AF84E05
static ULONG RandomSeed = RANDOM_SEED_INIT;

NTSTATUS DispatchEmpty(PDEVICE_OBJECT pDriverObj, PIRP pIrp)
{
	DbgPrint("[EFCHKMD] DispatchEmpty,PDO:%p,PIRP:%p", pDriverObj, pIrp);
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS GetProcessByPid(HANDLE pid, PEPROCESS* Process)
{
	NTSTATUS status;
	CLIENT_ID clientId;
	OBJECT_ATTRIBUTES objectAttributes;

	InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	clientId.UniqueProcess = pid;
	clientId.UniqueThread = 0;

	HANDLE hProcess;
	status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objectAttributes, &clientId);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("Failed to open process: 0x%X\n", status);
		return status;
	}

	status = ObReferenceObjectByHandle(hProcess, PROCESS_ALL_ACCESS, NULL, KernelMode, (PVOID*)Process, NULL);
	ZwClose(hProcess);

	return status;
}
NTSTATUS ZwGetProcessHandlePAAByEProcess(PEPROCESS EProcess, PHANDLE Handle)
{
	NTSTATUS status = ObOpenObjectByPointer(
		EProcess,
		OBJ_KERNEL_HANDLE,
		NULL,
		PROCESS_ALL_ACCESS,
		NULL,
		KernelMode,
		Handle
	);
	return status;
}
NTSTATUS ZwGetProcessHandlePAAByPID(ULONG PID, PHANDLE Handle)
{
	OBJECT_ATTRIBUTES obj = { 0 };
	InitializeObjectAttributes(&obj, NULL, 0, NULL, NULL);
	CLIENT_ID clentid = { 0 };
	clentid.UniqueProcess = (HANDLE)PID;
	NTSTATUS zopstatus = ZwOpenProcess(Handle, PROCESS_ALL_ACCESS, &obj, &clentid);
	return zopstatus;
}
BOOLEAN TerminateProcessByAPI(ULONG PID, ULONG ExitCode)
{
	PEPROCESS PEProc = NULL;
	NTSTATUS status;
	status = PsLookupProcessByProcessId((HANDLE)PID, &PEProc);
	if (!NT_SUCCESS(status))
	{
		return FALSE;
	}
	HANDLE hProcess;
	status = ZwGetProcessHandlePAAByEProcess(PEProc, &hProcess);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[EFCHKMD] TerminateProcessByAPI:Error!ObOpenObjectByPointer Failed");
		return FALSE;
	}
	BOOLEAN kpstatus = NT_SUCCESS(ZwTerminateProcess(hProcess, ExitCode));
	ObfDereferenceObject(PEProc);
	ZwClose(hProcess);
	return kpstatus;
}

NTSTATUS GetProcessDosImageName(PEPROCESS Process, PUNICODE_STRING pDestPath)
{
	PFILE_OBJECT fileObj = NULL;
	POBJECT_NAME_INFORMATION pDosName = NULL;
	NTSTATUS status = PsReferenceProcessFilePointer(Process, (PVOID*)&fileObj);
	if (!NT_SUCCESS(status)) return status;

	status = IoQueryFileDosDeviceName(fileObj, &pDosName);
	ObDereferenceObject(fileObj);

	if (NT_SUCCESS(status)) {
		if (pDestPath->MaximumLength >= pDosName->Name.Length) {
			RtlCopyUnicodeString(pDestPath, &pDosName->Name);
			if (pDestPath->Length >= 8 &&
				pDestPath->Buffer[0] == L'\\' && pDestPath->Buffer[1] == L'?' &&
				pDestPath->Buffer[2] == L'?' && pDestPath->Buffer[3] == L'\\') {
				pDestPath->Buffer += 4;
				pDestPath->Length -= 8;
				pDestPath->MaximumLength -= 8;
			}
		}
		else {
			status = STATUS_BUFFER_TOO_SMALL;
		}
		ExFreePool(pDosName);
	}
	return status;
}

NTSTATUS SuspendProcess(ULONG PID)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS PEProc = NULL;
	status = PsLookupProcessByProcessId((HANDLE)PID, &PEProc);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	status = PsSuspendProcess(PEProc);
	ObDereferenceObject(PEProc);
	return status;
}

NTSTATUS ResumeProcess(ULONG PID)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS PEProc = NULL;
	status = PsLookupProcessByProcessId((HANDLE)PID, &PEProc);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	status = PsResumeProcess(PEProc);
	ObDereferenceObject(PEProc);
	return status;
}

OB_PREOP_CALLBACK_STATUS ProtectCallback(
	PVOID RegistrationContext,
	POB_PRE_OPERATION_INFORMATION OperationInfo)
{
	UNREFERENCED_PARAMETER(RegistrationContext);

	/*
	if (OperationInfo->KernelHandle)
		return OB_PREOP_SUCCESS;
	*/
	PEPROCESS TargetProcess = (PEPROCESS)OperationInfo->Object;
	ULONG pid = (ULONG)PsGetProcessId(TargetProcess);

	// 获取请求进程信息
	PEPROCESS RequestingProcess = PsGetCurrentProcess();
	ULONG reqPid = (ULONG)PsGetProcessId(RequestingProcess);

	// 如果是自身操作则放行
	if (pid == reqPid)
		return OB_PREOP_SUCCESS;

	BOOLEAN isProtected = FALSE;
	ExAcquireFastMutex(&g_ProtectLock);
	for (int i = 0; i < MAX_PROTECTED_PIDS; i++) {
		if (g_ProtectedPids[i] == pid) {
			isProtected = TRUE;
			break;
		}
	}
	ExReleaseFastMutex(&g_ProtectLock);

	if (!isProtected)
		return OB_PREOP_SUCCESS;
	if (OperationInfo->KernelHandle) {
		OperationInfo->Parameters->CreateHandleInformation.DesiredAccess = 0;
		//DbgPrint("[EFCHKMD] Blocked kernel handle to protected process!");
		return OB_PREOP_SUCCESS;
	}
	switch (OperationInfo->Operation) {
	case OB_OPERATION_HANDLE_CREATE:
	{
		ACCESS_MASK* pDesiredAccess = &OperationInfo->Parameters->CreateHandleInformation.DesiredAccess;
		ACCESS_MASK originalAccess = *pDesiredAccess;
		*pDesiredAccess &= ~(
			PROCESS_TERMINATE |
			PROCESS_VM_READ |
			PROCESS_VM_WRITE |
			PROCESS_VM_OPERATION |
			PROCESS_CREATE_THREAD |
			PROCESS_SUSPEND_RESUME |
			PROCESS_SET_INFORMATION |
			PROCESS_DUP_HANDLE |
			PROCESS_QUERY_LIMITED_INFORMATION |
			PROCESS_SET_QUOTA |
			PROCESS_SET_SESSIONID |
			DELETE
			);

		if (originalAccess != *pDesiredAccess) {
			//DbgPrint("[EFCHKMD] Blocked handle create: PID=%lu ReqBy=%lu Access=0x%X->0x%X\n",
			//	pid, reqPid, originalAccess, *pDesiredAccess);
		}
		break;
	}

	case OB_OPERATION_HANDLE_DUPLICATE:
	{
		ACCESS_MASK* pDesiredAccess = &OperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess;
		ACCESS_MASK originalAccess = *pDesiredAccess;

		*pDesiredAccess &= ~(
			PROCESS_DUP_HANDLE |
			PROCESS_SET_INFORMATION
			);

		if (originalAccess != *pDesiredAccess) {
			//DbgPrint("[EFCHKMD] Blocked handle duplicate: PID=%lu ReqBy=%lu Access=0x%X->0x%X\n",
			//	pid, reqPid, originalAccess, *pDesiredAccess);
		}
		break;
	}
	}

	return OB_PREOP_SUCCESS;
}

NTSTATUS ProtectProcess(ULONG pid)
{
	PEPROCESS process;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)pid, &process);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Invalid PID: %lu (Status: 0x%X)\n", pid, status);
		return STATUS_INVALID_PARAMETER;
	}
	ObDereferenceObject(process);

	ExAcquireFastMutex(&g_ProtectLock);

	for (int i = 0; i < MAX_PROTECTED_PIDS; i++) {
		if (g_ProtectedPids[i] == pid) {
			ExReleaseFastMutex(&g_ProtectLock);
			DbgPrint("PID %lu already protected\n", pid);
			return STATUS_OBJECT_NAME_EXISTS;
		}
	}

	for (int i = 0; i < MAX_PROTECTED_PIDS; i++) {
		if (g_ProtectedPids[i] == 0) {
			g_ProtectedPids[i] = pid;
			ExReleaseFastMutex(&g_ProtectLock);
			DbgPrint("Protected PID: %lu\n", pid);
			return STATUS_SUCCESS;
		}
	}

	ExReleaseFastMutex(&g_ProtectLock);
	return STATUS_TOO_MANY_CONTEXT_IDS;
}

// 取消保护
NTSTATUS UnprotectProcess(ULONG pid)
{
	ExAcquireFastMutex(&g_ProtectLock);

	NTSTATUS status = STATUS_NOT_FOUND;
	for (int i = 0; i < MAX_PROTECTED_PIDS; i++) {
		if (g_ProtectedPids[i] == pid) {
			g_ProtectedPids[i] = 0;
			status = STATUS_SUCCESS;
			DbgPrint("[EFCHKMD] Unprotected PID: %lu\n", pid);
			break;
		}
	}

	ExReleaseFastMutex(&g_ProtectLock);
	return status;
}

// 初始化回调注册
NTSTATUS InitProcessProtection()
{
	OB_OPERATION_REGISTRATION operations[] = {
		{
			PsProcessType,
			OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
			ProtectCallback,
			NULL
		}
	};

	UNICODE_STRING altitude = RTL_CONSTANT_STRING(CUSTOM_ALTITUDE);

	OB_CALLBACK_REGISTRATION callbackReg = {
		OB_FLT_REGISTRATION_VERSION,
		1,
		altitude,
		NULL,
		operations
	};

	return ObRegisterCallbacks(&callbackReg, &g_RegistrationHandle);
}

NTSTATUS SetPPL(ULONG pid, int PPLLevel)
{
	PEPROCESS process;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)pid, &process);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	if (NT_SUCCESS(status))
	{
		*(UCHAR*)((ULONG64)process + ProtectionOffset) = (UCHAR)PPLLevel; //设置PPL有问题就UCHAR改int
		ObDereferenceObject(process);
	}
	return STATUS_SUCCESS;
}

NTSTATUS GetPPL(ULONG pid, OUT int* PPLLevel)
{
	PEPROCESS process;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)pid, &process);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	if (NT_SUCCESS(status))
	{
		// 只读取1个字节
		UCHAR protection = *(UCHAR*)((ULONG64)process + ProtectionOffset);
		*PPLLevel = (int)protection;  // 将字节转换为int
		ObDereferenceObject(process);
	}
	return STATUS_SUCCESS;
}

NTSTATUS SetPID(HANDLE pid, HANDLE NewPID)
{
	PEPROCESS process;
	NTSTATUS status = PsLookupProcessByProcessId(pid, &process);

	if (!NT_SUCCESS(status))
	{
		return status;
	}
	*(HANDLE*)((ULONG64)process + UniqueProcessIdOffset) = NewPID;
	ObDereferenceObject(process);
	return STATUS_SUCCESS;
}

NTSTATUS SetProcessCritical(HANDLE pid, ULONG IsCritical)
{
	PEPROCESS process;
	HANDLE hProcess;
	PROCESS_BREAK_ON_TERMINATION breakOnTermination;
	NTSTATUS status = PsLookupProcessByProcessId(pid, &process);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	status = ZwGetProcessHandlePAAByEProcess(process, &hProcess);
	if (hProcess == NULL)
	{
		ObDereferenceObject(process);
		return STATUS_INVALID_HANDLE;
	}
	if (!NT_SUCCESS(status))
	{
		ObDereferenceObject(process);
		return STATUS_INVALID_HANDLE;
	}
	breakOnTermination.BreakOnTermination = IsCritical ? 1 : 0;
	//status = ZwSetInformationProcess(hProcess, ProcessBreakOnTermination, &breakOnTermination, sizeof(ULONG));
	status = ZwSetInformationProcess(hProcess, ProcessBreakOnTermination, &breakOnTermination, sizeof(ULONG));
	ZwClose(hProcess);
	ObDereferenceObject(process);
	return status;
}

ULONG EPROCESSEnumProcess(OUT ULONG* PIDs)
{
	PEPROCESS process;
	ULONG count = 0;
	ULONG lastValidPID = 0;

	RtlZeroMemory(PIDs, 65535 * sizeof(ULONG));

	for (ULONG i = 4; i < 65535; i++)
	{
		NTSTATUS status = PsLookupProcessByProcessId((HANDLE)i, &process);
		if (NT_SUCCESS(status))
		{
			// 检查是否是新的有效PID组
			// 如果当前PID与上一个有效PID不连续，说明是新的一组
			if (i != lastValidPID + 1)
			{
				// 这是新的一组，记录第一个PID
				PIDs[count] = i;
				count++;
				DbgPrint("Valid PID: %u\n", i);
			}
			else
			{
				DbgPrint("Skipping fake PID: %u\n", i);
			}

			lastValidPID = i;
			ObDereferenceObject(process);
		}
	}

	DbgPrint("Total valid processes after filtering: %u\n", count);
	return count;
}

//File

NTSTATUS WriteToDisk(ULONG StartSector, ULONG SectorCount, PVOID DataBuffer) {
	UNICODE_STRING diskPath;
	OBJECT_ATTRIBUTES objAttr;
	IO_STATUS_BLOCK ioStatus;
	HANDLE hDisk = NULL;
	LARGE_INTEGER offset;
	NTSTATUS status;

	// 打开物理磁盘（示例使用第一个物理磁盘）
	RtlInitUnicodeString(&diskPath, L"\\Device\\Harddisk0\\DR0");
	InitializeObjectAttributes(&objAttr, &diskPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	status = ZwCreateFile(
		&hDisk,
		GENERIC_WRITE | SYNCHRONIZE,
		&objAttr,
		&ioStatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_WRITE | FILE_SHARE_READ,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0
	);

	if (!NT_SUCCESS(status)) {
		DbgPrint("打开磁盘失败: 0x%X\n", status);
		return status;
	}

	// 计算字节偏移量 (扇区号 * 512)
	offset.QuadPart = (LONGLONG)StartSector * 512;

	// 写入数据
	status = ZwWriteFile(
		hDisk,
		NULL, NULL, NULL,
		&ioStatus,
		DataBuffer,
		SectorCount * 512,
		&offset,
		NULL
	);

	if (!NT_SUCCESS(status)) {
		DbgPrint("WriteFile Fail: 0x%X\n", status);
	}

	ZwClose(hDisk);
	return status;
}
NTSTATUS WriteToDiskEx(LARGE_INTEGER StartSector, ULONG SectorCount, PVOID DataBuffer)
{
	UNICODE_STRING diskPath;
	OBJECT_ATTRIBUTES objAttr;
	IO_STATUS_BLOCK ioStatus;
	HANDLE hDisk = NULL;
	NTSTATUS status;

	// 修改2：使用动态磁盘路径（示例）
	RtlInitUnicodeString(&diskPath, L"\\Device\\Harddisk0\\DR0");

	InitializeObjectAttributes(&objAttr, &diskPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	// 修改3：添加写入权限
	status = ZwCreateFile(
		&hDisk,
		GENERIC_WRITE | SYNCHRONIZE | FILE_WRITE_DATA,
		&objAttr,
		&ioStatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_WRITE | FILE_SHARE_READ,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0
	);

	if (!NT_SUCCESS(status)) {
		DbgPrint("Open Disk Failed: 0x%X\n", status);
		return status;
	}

	// 修改4：直接使用64位偏移量
	LARGE_INTEGER offset;
	offset.QuadPart = StartSector.QuadPart * 512;

	status = ZwWriteFile(
		hDisk,
		NULL, NULL, NULL,
		&ioStatus,
		DataBuffer,
		SectorCount * 512,
		&offset,
		NULL
	);

	if (!NT_SUCCESS(status)) {
		DbgPrint("WriteFile Failed: 0x%X\n", status);
	}

	if (hDisk) ZwClose(hDisk);
	return status;
}

BOOLEAN DontFreezeDisk()
{
	NTSTATUS status;
	PFILE_OBJECT pDiskFileObject = NULL;
	UNICODE_STRING uni_dr0;
	PVOID buffer = NULL;
	LARGE_INTEGER byteOffset;
	BOOLEAN result = FALSE;

	// 初始化 DR0 路径
	RtlInitUnicodeString(&uni_dr0, L"\\Device\\Harddisk0\\DR0");
	status = IrpOpenDisk(&pDiskFileObject, &uni_dr0);
	if (!NT_SUCCESS(status)) {
		return FALSE;
	}

	buffer = ExAllocatePoolWithTag(NonPagedPool, 512, 'Chk1');
	if (!buffer) {
		ObDereferenceObject(pDiskFileObject);
		return FALSE;
	}

	byteOffset.QuadPart = (LONGLONG)2011 * 512;
	status = IrpReadDisk(pDiskFileObject, byteOffset, 512, buffer);
	if (!NT_SUCCESS(status)) {
	}
	else {
		UCHAR firstByte = ((PUCHAR)buffer)[0];
		if (firstByte == 0x01) {
			result = TRUE;
		}
		else {
		}
	}
	ExFreePoolWithTag(buffer, 'Chk1');
	ObDereferenceObject(pDiskFileObject);

	return result;
}

NTSTATUS IrpWriteToDiskEx(LARGE_INTEGER StartSector, ULONG SectorCount, PVOID DataBuffer)
{
	NTSTATUS status;
	PFILE_OBJECT pFileObject = NULL;
	UNICODE_STRING diskPath;

	// 初始化磁盘路径 (这里使用第一个物理磁盘)
	RtlInitUnicodeString(&diskPath, L"\\Device\\Harddisk0\\DR0");

	// 1. 打开磁盘设备
	status = IrpOpenDisk(&pFileObject, &diskPath);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	// 2. 计算字节偏移和长度
	LARGE_INTEGER ByteOffset;
	ULONG Length = SectorCount * 512;
	ByteOffset.QuadPart = StartSector.QuadPart * 512;

	// 3. 执行磁盘写入
	status = IrpWriteDisk(pFileObject, ByteOffset, Length, DataBuffer);

	// 4. 清理资源
	ObDereferenceObject(pFileObject);
	return status;
}

NTSTATUS WriteOriginalSectorEx(LARGE_INTEGER StartSector, ULONG SectorCount, PVOID DataBuffer)
{
	NTSTATUS status;
	LARGE_INTEGER ByteOffset;
	ULONG Length = SectorCount * 512;
	ByteOffset.QuadPart = StartSector.QuadPart * 512;
	status = WriteOriginalSector(ByteOffset, Length, DataBuffer);
	return status;
}

NTSTATUS IrpReadDiskEx(LARGE_INTEGER StartSector, ULONG SectorCount, OUT PVOID DataBuffer)
{
	NTSTATUS status;
	PFILE_OBJECT pFileObject = NULL;
	UNICODE_STRING diskPath;

	RtlInitUnicodeString(&diskPath, L"\\Device\\Harddisk0\\DR0");


	status = IrpOpenDisk(&pFileObject, &diskPath);
	if (!NT_SUCCESS(status)) {
		DbgPrint("打开磁盘设备失败: 0x%X\n", status);
		return status;
	}

	LARGE_INTEGER ByteOffset;
	ULONG Length = SectorCount * 512;
	ByteOffset.QuadPart = StartSector.QuadPart * 512;

	status = IrpReadDisk(pFileObject, ByteOffset, Length, DataBuffer);
	ObDereferenceObject(pFileObject);
	return status;
}
NTSTATUS ReadOriginalSectorEx(LARGE_INTEGER StartSector, ULONG SectorCount, OUT PVOID DataBuffer)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG i;
	PUCHAR buffer = (PUCHAR)DataBuffer;
	ULONGLONG currentSector;

	for (i = 0; i < SectorCount; i++)
	{
		currentSector = StartSector.QuadPart + i;
		status = ReadOriginalSector(currentSector, buffer + (i * 512));
		if (!NT_SUCCESS(status))
		{
			break;
		}
	}

	return status;
}
NTSTATUS ForceDeleteFile(UNICODE_STRING ustrFileName)
{
	NTSTATUS status = STATUS_SUCCESS;
	PFILE_OBJECT pFileObject = NULL;
	IO_STATUS_BLOCK iosb = { 0 };
	FILE_BASIC_INFORMATION fileBaseInfo = { 0 };
	FILE_DISPOSITION_INFORMATION fileDispositionInfo = { 0 };
	PVOID pImageSectionObject = NULL;
	PVOID pDataSectionObject = NULL;
	PVOID pSharedCacheMap = NULL;

	// 发送IRP打开文件
	status = IrpCreateFile(&pFileObject, GENERIC_READ | GENERIC_WRITE, &ustrFileName,
		&iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | IO_IGNORE_SHARE_ACCESS_CHECK, NULL, 0);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("IrpCreateFile Error[0x%X]\n", status);
		return FALSE;
	}
	// 发送IRP设置文件属性, 去掉只读属性, 修改为 FILE_ATTRIBUTE_NORMAL
	RtlZeroMemory(&fileBaseInfo, sizeof(fileBaseInfo));
	fileBaseInfo.FileAttributes = FILE_ATTRIBUTE_NORMAL;
	status = _IrpSetInformationFile(pFileObject, &iosb, &fileBaseInfo, sizeof(fileBaseInfo), FileBasicInformation);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("IrpSetInformationFile[SetInformation] Error[0x%X]\n", status);
		return status;
	}
	// 清空PSECTION_OBJECT_POINTERS结构
	if (pFileObject->SectionObjectPointer)
	{
		// 保存旧值
		pImageSectionObject = pFileObject->SectionObjectPointer->ImageSectionObject;
		pDataSectionObject = pFileObject->SectionObjectPointer->DataSectionObject;
		pSharedCacheMap = pFileObject->SectionObjectPointer->SharedCacheMap;
		// 置为空
		pFileObject->SectionObjectPointer->ImageSectionObject = NULL;
		pFileObject->SectionObjectPointer->DataSectionObject = NULL;
		pFileObject->SectionObjectPointer->SharedCacheMap = NULL;
	}
	// 发送IRP设置文件属性, 设置删除文件操作
	RtlZeroMemory(&fileDispositionInfo, sizeof(fileDispositionInfo));
	fileDispositionInfo.DeleteFile = TRUE;
	status = _IrpSetInformationFile(pFileObject, &iosb, &fileDispositionInfo, sizeof(fileDispositionInfo), FileDispositionInformation);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("IrpSetInformationFile[DeleteFile] Error[0x%X]\n", status);
		return status;
	}
	//还原旧值  
	if (pFileObject->SectionObjectPointer)
	{
		pFileObject->SectionObjectPointer->ImageSectionObject = pImageSectionObject;
		pFileObject->SectionObjectPointer->DataSectionObject = pDataSectionObject;
		pFileObject->SectionObjectPointer->SharedCacheMap = pSharedCacheMap;
	}
	// 关闭文件对象
	ObDereferenceObject(pFileObject);
	return status;
}
NTSTATUS POSIXForceDeleteFile(UNICODE_STRING ustrFileName)
{
	NTSTATUS status = STATUS_SUCCESS;
	PFILE_OBJECT pFileObject = NULL;
	IO_STATUS_BLOCK iosb = { 0 };
	FILE_DISPOSITION_INFORMATION_EX fileDispositionInfoEx = { 0 };
	PVOID pImageSectionObject = NULL;
	PVOID pDataSectionObject = NULL;
	PVOID pSharedCacheMap = NULL;
	// 发送IRP打开文件
	status = IrpCreateFile(&pFileObject, GENERIC_READ | GENERIC_WRITE, &ustrFileName,
		&iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | IO_IGNORE_SHARE_ACCESS_CHECK, NULL, 0);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("IrpCreateFile Error[0x%X]\n", status);
		status = IrpCreateFile(&pFileObject, 0, &ustrFileName,
			&iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | IO_IGNORE_SHARE_ACCESS_CHECK, NULL, 0); //0权限也能发IRP,可以绕过独占,但FSD同不同意不一定
		if (!NT_SUCCESS(status))
		{
			DbgPrint("IrpCreateFile 0ACCESS Error[0x%X]\n", status);
			return FALSE;
		}
	}
	if (pFileObject->SectionObjectPointer)
	{
		// 保存旧值
		pImageSectionObject = pFileObject->SectionObjectPointer->ImageSectionObject;
		pDataSectionObject = pFileObject->SectionObjectPointer->DataSectionObject;
		pSharedCacheMap = pFileObject->SectionObjectPointer->SharedCacheMap;
		// 置为空
		pFileObject->SectionObjectPointer->ImageSectionObject = NULL;
		pFileObject->SectionObjectPointer->DataSectionObject = NULL;
		pFileObject->SectionObjectPointer->SharedCacheMap = NULL;
	}
	// 发送IRP设置文件属性, 设置删除文件操作
	RtlZeroMemory(&fileDispositionInfoEx, sizeof(fileDispositionInfoEx));
	fileDispositionInfoEx.Flags = FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX_SEMANTICS | FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE;
	status = _IrpSetInformationFile(pFileObject, &iosb, &fileDispositionInfoEx, sizeof(fileDispositionInfoEx), FileDispositionInformationEx);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("IrpSetInformationFile[DeleteFile] Error[0x%X]\n", status);
		return status;
	}
	if (pFileObject->SectionObjectPointer)
	{
		pFileObject->SectionObjectPointer->ImageSectionObject = pImageSectionObject;
		pFileObject->SectionObjectPointer->DataSectionObject = pDataSectionObject;
		pFileObject->SectionObjectPointer->SharedCacheMap = pSharedCacheMap;
	}
	// 关闭文件对象
	ObDereferenceObject(pFileObject);
	return status;
}

BOOLEAN OccupyFile(_In_ UNICODE_STRING pwzFileName, _Out_ PHANDLE OutHandle)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	HANDLE hFile = NULL;
	OBJECT_ATTRIBUTES objAttr;
	IO_STATUS_BLOCK ioStatus;
	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
	{
		return FALSE;
	}
	if (pwzFileName.Buffer == NULL || pwzFileName.Length <= 0)
	{
		return FALSE;
	}
	InitializeObjectAttributes(
		&objAttr,
		&pwzFileName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL
	);
	status = ZwCreateFile(
		&hFile,
		FILE_READ_DATA,
		&objAttr,
		&ioStatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE,
		NULL,
		0
	);
	*OutHandle = hFile;
	return NT_SUCCESS(status);
}

ULONG Fs_QueryFileAndFileFolder_UNICODE_Irp(PUNICODE_STRING ustrPath, PDATA_INFO pBuffer)
{
	ULONG nCount = 0;
	PFILE_OBJECT FileObject = NULL;
	OBJECT_ATTRIBUTES objectAttributes = { 0 };
	IO_STATUS_BLOCK iosb = { 0 };
	NTSTATUS status = STATUS_SUCCESS;

	// 添加参数验证
	if (ustrPath == NULL || ustrPath->Buffer == NULL || ustrPath->Length == 0)
	{
		DbgPrint("Invalid path in Fs_QueryFileAndFileFolder_UNICODE_Irp\n");
		return 0;
	}

	InitializeObjectAttributes(&objectAttributes, ustrPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	status = IrpCreateFile(&FileObject, FILE_LIST_DIRECTORY | SYNCHRONIZE | FILE_ANY_ACCESS, ustrPath, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT, NULL, NULL);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("IrpCreateFile failed with status: 0x%X for path: %wZ\n", status, ustrPath);
		return 0;
	}

	ULONG ulLength = (2 * 4096 + sizeof(FILE_BOTH_DIR_INFORMATION)) * 0x2000;
	PFILE_BOTH_DIR_INFORMATION pDir = (PFILE_BOTH_DIR_INFORMATION)ExAllocatePool(PagedPool, ulLength);

	if (pDir == NULL)
	{
		DbgPrint("Memory allocation failed in Fs_QueryFileAndFileFolder_UNICODE_Irp\n");
		ObDereferenceObject(FileObject);
		return 0;
	}

	PFILE_BOTH_DIR_INFORMATION pBeginAddr = pDir;

	// 确保内存清零
	RtlZeroMemory(pDir, ulLength);

	status = IrpQueryDirectoryFile(FileObject, &iosb, pDir, ulLength, FileBothDirectoryInformation, NULL);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("IrpQueryDirectoryFile failed with status: 0x%X\n", status);
		ExFreePool(pBeginAddr);
		ObDereferenceObject(FileObject);
		return 0;
	}

	UNICODE_STRING ustrTemp;
	UNICODE_STRING ustrOne;
	UNICODE_STRING ustrTwo;

	RtlInitUnicodeString(&ustrOne, L".");
	RtlInitUnicodeString(&ustrTwo, L"..");

	WCHAR wcFileName[1024] = { 0 };

	BOOLEAN countOnly = (pBuffer == NULL);

	while (TRUE)
	{
		// 安全检查：确保文件名长度不会导致缓冲区溢出
		if (pDir->FileNameLength >= sizeof(wcFileName))
		{
			DbgPrint("File name too long, skipping\n");
			// 跳过这个文件继续处理下一个
			if (0 == pDir->NextEntryOffset)
				break;
			pDir = (PFILE_BOTH_DIR_INFORMATION)((PUCHAR)pDir + pDir->NextEntryOffset);
			continue;
		}

		RtlZeroMemory(wcFileName, sizeof(wcFileName));
		RtlCopyMemory(wcFileName, pDir->FileName, pDir->FileNameLength);
		RtlInitUnicodeString(&ustrTemp, wcFileName);

		if ((0 != RtlCompareUnicodeString(&ustrTemp, &ustrOne, TRUE)) &&
			(0 != RtlCompareUnicodeString(&ustrTemp, &ustrTwo, TRUE)))
		{
			if (!countOnly)
			{
				// 安全检查：防止数组越界
				if (nCount < MAXULONG) // 防止计数器溢出
				{
					if (pDir->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
					{
						pBuffer[nCount].ulongdata4 = TRUE;
					}
					else
					{
						pBuffer[nCount].ulongdata4 = FALSE;
					}
					// 使用安全的字符串复制
					RtlStringCbCopyW(pBuffer[nCount].wcstr, sizeof(pBuffer[nCount].wcstr), wcFileName);
				}
			}
			nCount++;
		}

		if (0 == pDir->NextEntryOffset)
		{
			break;
		}
		pDir = (PFILE_BOTH_DIR_INFORMATION)((PUCHAR)pDir + pDir->NextEntryOffset);
	}

	ExFreePool(pBeginAddr);
	ObDereferenceObject(FileObject);

	DbgPrint("Fs_QueryFileAndFileFolder_UNICODE_Irp counted %lu items\n", nCount);
	return nCount;
}

NTSTATUS IrpRenameFile(
	IN PUNICODE_STRING OldPath,
	IN PUNICODE_STRING NewPath
)
{
	NTSTATUS status = STATUS_SUCCESS;
	PFILE_OBJECT pFileObject = NULL;
	IO_STATUS_BLOCK ioStatusBlock = { 0 };
	FILE_RENAME_INFORMATION* pRenameInfo = NULL;
	ULONG renameInfoSize = 0;

	// 计算所需缓冲区大小
	renameInfoSize = sizeof(FILE_RENAME_INFORMATION) + NewPath->Length;

	// 分配重命名信息结构内存
	pRenameInfo = (PFILE_RENAME_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, renameInfoSize, 'RENI');
	if (pRenameInfo == NULL) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlZeroMemory(pRenameInfo, renameInfoSize);

	// 填充重命名信息
	pRenameInfo->ReplaceIfExists = TRUE;  // 覆盖已存在文件
	pRenameInfo->RootDirectory = NULL;    // 使用绝对路径
	pRenameInfo->FileNameLength = NewPath->Length;
	RtlCopyMemory(pRenameInfo->FileName, NewPath->Buffer, NewPath->Length);

	// 打开原文件 (需要DELETE权限)
	status = IrpCreateFile(
		&pFileObject,
		DELETE | SYNCHRONIZE,  // 必须包含DELETE权限
		OldPath,
		&ioStatusBlock,
		NULL,                  // AllocationSize
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN,             // 打开现有文件
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,                  // EaBuffer
		0                      // EaLength
	);

	if (!NT_SUCCESS(status)) {
		DbgPrint("IrpCreateFile Failed(DELETE ACCESS):0x%X", status);
		status = IrpCreateFile(
			&pFileObject,
			0,
			OldPath,
			&ioStatusBlock,
			NULL,                  // AllocationSize
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			FILE_OPEN,             // 打开现有文件
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,                  // EaBuffer
			0                      // EaLength
		);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("IrpCreateFile Failed(0 ACCESS):0x%X", status);
			ExFreePoolWithTag(pRenameInfo, 'RENI');
			return status;
		}
	}

	status = _IrpSetInformationFile(
		pFileObject,
		&ioStatusBlock,
		pRenameInfo,
		renameInfoSize,
		FileRenameInformation
	);

	ObDereferenceObject(pFileObject);
	ExFreePoolWithTag(pRenameInfo, 'RENI');

	return status;
}

NTSTATUS ZwGetFileSize(UNICODE_STRING filepath, PULONGLONG dx)
{
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hFile = NULL;
	IO_STATUS_BLOCK iosb = { 0 };
	OBJECT_ATTRIBUTES oa = { 0 };
	FILE_STANDARD_INFORMATION fileInfo;

	InitializeObjectAttributes(
		&oa,
		&filepath,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		NULL,
		NULL
	);

	status = ZwCreateFile(&hFile, GENERIC_READ, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = ZwQueryInformationFile(hFile, &iosb, &fileInfo, sizeof(fileInfo), FileStandardInformation);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hFile);
		return status;
	}
	ZwClose(hFile);
	*dx = (ULONG)fileInfo.EndOfFile.LowPart;

	return status;
}

NTSTATUS IrpGetFileSize(UNICODE_STRING filepath, PULONGLONG dx)
{
	NTSTATUS status = STATUS_SUCCESS;
	IO_STATUS_BLOCK iosb = { 0 };
	OBJECT_ATTRIBUTES oa = { 0 };
	FILE_STANDARD_INFORMATION fileInfo;
	PFILE_OBJECT FileObject = NULL;

	InitializeObjectAttributes(
		&oa,
		&filepath,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		NULL,
		NULL
	);

	status = IrpCreateFile(
		&FileObject,
		FILE_READ_DATA | SYNCHRONIZE,
		&filepath,
		&iosb,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);
	if (!NT_SUCCESS(status))
	{
		status = IrpCreateFile(
			&FileObject,
			0,
			&filepath,
			&iosb,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ,
			FILE_OPEN,
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0);
		if (!NT_SUCCESS(status))
		{
			return status;
		}

	}

	status = IrpQueryInformationFile(FileObject, &iosb, &fileInfo, sizeof(fileInfo), FileStandardInformation);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	ObDereferenceObject(FileObject);
	*dx = (ULONG)fileInfo.EndOfFile.LowPart;
	return status;
}

ULONG Fs_GetFileAndFolderQuantity_UNICODE_Irp(PUNICODE_STRING pUniPath)
{
	if (pUniPath == NULL || pUniPath->Buffer == NULL || pUniPath->Length == 0)
	{
		DbgPrint("Invalid path parameter in Fs_GetFileAndFolderQuantity_UNICODE_Irp\n");
		return 0;
	}

	// 验证路径格式
	if (pUniPath->Length >= sizeof(WCHAR) * 1024) // 合理的路径长度限制
	{
		DbgPrint("Path too long in Fs_GetFileAndFolderQuantity_UNICODE_Irp\n");
		return 0;
	}

	DbgPrint("Counting files in path: %wZ\n", pUniPath);

	return Fs_QueryFileAndFileFolder_UNICODE_Irp(pUniPath, NULL);
}

//System
void SYSTEMBSOD() //Only E Disk Freeze or System Error can use
{
	HANDLE hFile = NULL;
	KeBugCheckEx(0xDEADDEAD, 0x01, NULL, NULL, NULL);
	KeBugCheckEx(0x24, 0x01, NULL, NULL, NULL);
	KeBugCheckEx(0x124, 0x01, NULL, NULL, NULL);
	ZwCreateFile(&hFile, FILE_READ_DATA, NULL, NULL, NULL, 13, 78, 91, 13, NULL, 0);
	__writecr0(0);
	__writecr2(0);
	__writecr3(0);
	__writecr4(0);
	__writecr8(0);
}

ZWQUERYDIRECTORYOBJECT GetZwQueryDirectoryObject()
{
	UNICODE_STRING funcName = RTL_CONSTANT_STRING(L"ZwQueryDirectoryObject");
	return (ZWQUERYDIRECTORYOBJECT)MmGetSystemRoutineAddress(&funcName);
}

NTSTATUS ComputeSha256(PVOID pData, ULONG dataLen, PUCHAR pHashOut) {
	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	ULONG hashLen = 0, objLen = 0, cbResult = 0;
	PUCHAR hashObj = NULL;

	// 打开 SHA-256 算法提供者
	status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
	if (!NT_SUCCESS(status))
		return status;

	// 获取哈希对象大小和哈希值长度（必须提供 pcbResult）
	status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &cbResult, 0);
	if (!NT_SUCCESS(status))
		goto Cleanup;
	status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(hashLen), &cbResult, 0);
	if (!NT_SUCCESS(status))
		goto Cleanup;
	if (hashLen != 32) {
		status = STATUS_UNSUCCESSFUL;
		goto Cleanup;
	}

	hashObj = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, objLen, 'SHAT');
	if (!hashObj) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto Cleanup;
	}

	status = BCryptCreateHash(hAlg, &hHash, hashObj, objLen, NULL, 0, 0);
	if (!NT_SUCCESS(status))
		goto Cleanup;

	status = BCryptHashData(hHash, (PUCHAR)pData, dataLen, 0);
	if (!NT_SUCCESS(status))
		goto Cleanup;

	status = BCryptFinishHash(hHash, pHashOut, hashLen, 0);
	if (!NT_SUCCESS(status))
		goto Cleanup;

Cleanup:
	if (hHash)
		BCryptDestroyHash(hHash);
	if (hashObj)
		ExFreePoolWithTag(hashObj, 'SHAT');
	if (hAlg)
		BCryptCloseAlgorithmProvider(hAlg, 0);
	return status;
}

ULONG EnumAllDriverPath(OUT Lite_Driver_Info2* LDI, IN ULONG ulBufferSize)
{
	HANDLE hDirectory = NULL;
	OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING dirName;
	NTSTATUS status;
	ULONG context = 0;
	ULONG returnLength = 0;
	ULONG entryCount = 0;
	POBJECT_DIRECTORY_INFORMATION dirInfo = NULL;
	ULONG bufferSize = PAGE_SIZE;

	// 获取函数指针
	ZWQUERYDIRECTORYOBJECT pZwQueryDirectoryObject = GetZwQueryDirectoryObject();
	if (!pZwQueryDirectoryObject) {
		DbgPrint("EnumAllDriverPath: Failed to get ZwQueryDirectoryObject\n");
		return 0;
	}

	// 初始化 "\Driver" 目录路径
	RtlInitUnicodeString(&dirName, L"\\Driver");
	InitializeObjectAttributes(&objAttr, &dirName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	// 打开驱动目录
	status = ZwOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &objAttr);
	if (!NT_SUCCESS(status)) {
		DbgPrint("EnumAllDriverPath: Failed to open \\Driver directory: 0x%08X\n", status);
		return 0;
	}

	// 分配缓冲区
	dirInfo = (POBJECT_DIRECTORY_INFORMATION)ExAllocatePoolWithTag(
		NonPagedPool, bufferSize, 'vrD');

	if (!dirInfo) {
		ZwClose(hDirectory);
		DbgPrint("EnumAllDriverPath: Failed to allocate memory\n");
		return 0;
	}

	DbgPrint("EnumAllDriverPath: Starting enumeration of \\Driver directory\n");

	// 枚举驱动
	while (TRUE) {
		RtlZeroMemory(dirInfo, bufferSize);

		status = pZwQueryDirectoryObject(
			hDirectory,
			dirInfo,
			bufferSize,
			FALSE,      // 不返回单个条目
			FALSE,      // 不重新开始扫描
			&context,
			&returnLength
		);

		// 检查是否完成或出错
		if (status == STATUS_NO_MORE_ENTRIES) {
			DbgPrint("EnumAllDriverPath: No more entries\n");
			break;
		}

		if (!NT_SUCCESS(status)) {
			DbgPrint("EnumAllDriverPath: QueryDirectory failed: 0x%08X\n", status);
			break;
		}

		// 处理每个条目
		POBJECT_DIRECTORY_INFORMATION current = dirInfo;
		while (current->Name.Length > 0) {
			// 检查缓冲区是否已满
			if (entryCount >= ulBufferSize) {
				DbgPrint("EnumAllDriverPath: Buffer full, stopping at %lu entries\n", entryCount);
				break;
			}

			// 检查指针有效性
			if ((PUCHAR)current < (PUCHAR)dirInfo ||
				(PUCHAR)current >= (PUCHAR)dirInfo + bufferSize) {
				DbgPrint("EnumAllDriverPath: Pointer out of range\n");
				break;
			}

			// 跳过无效名称
			if (current->Name.Buffer == NULL || current->Name.Length == 0) {
				current = (POBJECT_DIRECTORY_INFORMATION)((PUCHAR)current + sizeof(OBJECT_DIRECTORY_INFORMATION));
				continue;
			}

			// 计算名称长度（字符数）
			ULONG nameCharCount = current->Name.Length / sizeof(WCHAR);

			// 跳过过长的名称
			if (nameCharCount > 256) {  // 假设BaseDllName缓冲区为256字符
				DbgPrint("EnumAllDriverPath: Name too long (%lu chars), skipping\n", nameCharCount);
				current = (POBJECT_DIRECTORY_INFORMATION)((PUCHAR)current + sizeof(OBJECT_DIRECTORY_INFORMATION));
				continue;
			}

			// 构建完整的驱动路径：\Driver\ + 驱动名
			WCHAR fullPath[512] = { 0 };
			NTSTATUS strStatus;

			// 复制前缀
			strStatus = RtlStringCchCopyW(fullPath, ARRAYSIZE(fullPath), L"\\Driver\\");
			if (!NT_SUCCESS(strStatus)) {
				current = (POBJECT_DIRECTORY_INFORMATION)((PUCHAR)current + sizeof(OBJECT_DIRECTORY_INFORMATION));
				continue;
			}

			// 追加驱动名称
			strStatus = RtlStringCchCatNW(
				fullPath,
				ARRAYSIZE(fullPath),
				current->Name.Buffer,
				nameCharCount
			);

			if (NT_SUCCESS(strStatus)) {
				// 复制到输出结构体的BaseDllName字段
				strStatus = RtlStringCchCopyW(
					LDI[entryCount].BaseDllName,
					sizeof(LDI[entryCount].BaseDllName) / sizeof(WCHAR),
					fullPath
				);

				if (NT_SUCCESS(strStatus)) {
					DbgPrint("EnumAllDriverPath: Found driver: %ws\n", fullPath);
					entryCount++;
				}
				else {
					DbgPrint("EnumAllDriverPath: Failed to copy to output buffer: 0x%08X\n", strStatus);
				}
			}
			else {
				DbgPrint("EnumAllDriverPath: Failed to build full path: 0x%08X\n", strStatus);
			}

			// 移动到下一个条目
			current = (POBJECT_DIRECTORY_INFORMATION)((PUCHAR)current + sizeof(OBJECT_DIRECTORY_INFORMATION));
		}

		// 检查是否因缓冲区满而停止
		if (entryCount >= ulBufferSize) {
			break;
		}
	}

	// 清理资源
	if (dirInfo) {
		ExFreePoolWithTag(dirInfo, 'vrD');
	}

	if (hDirectory) {
		ZwClose(hDirectory);
	}

	DbgPrint("EnumAllDriverPath: Enumeration complete, found %lu drivers\n", entryCount);

	return entryCount;
}

ULONG EnumAllDevicePath(OUT Lite_Driver_Info2* LDI, IN ULONG ulBufferSize)
{
	HANDLE hDirectory = NULL;
	OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING dirName;
	NTSTATUS status;
	ULONG context = 0;
	ULONG returnLength = 0;
	ULONG entryCount = 0;
	POBJECT_DIRECTORY_INFORMATION dirInfo = NULL;
	ULONG bufferSize = PAGE_SIZE;
	ZWQUERYDIRECTORYOBJECT pZwQueryDirectoryObject = GetZwQueryDirectoryObject();
	if (!pZwQueryDirectoryObject) {
		return 0;
	}

	RtlInitUnicodeString(&dirName, L"\\Device");
	InitializeObjectAttributes(&objAttr, &dirName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &objAttr);
	if (!NT_SUCCESS(status)) {
		return 0;
	}

	dirInfo = (POBJECT_DIRECTORY_INFORMATION)ExAllocatePoolWithTag(
		NonPagedPool, bufferSize, 'eviD');

	if (!dirInfo) {
		ZwClose(hDirectory);
		return 0;
	}

	while (TRUE) {
		RtlZeroMemory(dirInfo, bufferSize);

		status = pZwQueryDirectoryObject(
			hDirectory,
			dirInfo,
			bufferSize,
			FALSE,      // 不返回单个条目
			FALSE,      // 不重新开始扫描
			&context,
			&returnLength
		);

		if (!NT_SUCCESS(status)) {
			break;
		}
		POBJECT_DIRECTORY_INFORMATION current = dirInfo;
		while (current->Name.Length > 0) {
			if (entryCount >= ulBufferSize) {
				DbgPrint("EnumAllDevicePath: Buffer full at entry %lu\n", entryCount);
				break;
			}
			if ((PUCHAR)current < (PUCHAR)dirInfo ||
				(PUCHAR)current >= (PUCHAR)dirInfo + bufferSize) {
				DbgPrint("EnumAllDevicePath: Current pointer out of range\n");
				break;
			}
			if (current->Name.Buffer == NULL) {
				current = (POBJECT_DIRECTORY_INFORMATION)((PUCHAR)current + sizeof(OBJECT_DIRECTORY_INFORMATION));
				continue;
			}
			if (current->Name.Length == 0 || current->Name.Length > 1024 * sizeof(WCHAR)) {
				current = (POBJECT_DIRECTORY_INFORMATION)((PUCHAR)current + sizeof(OBJECT_DIRECTORY_INFORMATION));
				continue;
			}
			WCHAR fullPath[512] = { 0 };
			NTSTATUS strStatus;
			if (current->Name.Length > 0) {
				ULONG maxNameLen = min(current->Name.Length / sizeof(WCHAR),
					ARRAYSIZE(fullPath) - wcslen(L"\\Device\\") - 1);

				if (maxNameLen > 0) {
					strStatus = RtlStringCchPrintfW(
						fullPath,
						ARRAYSIZE(fullPath),
						L"\\Device\\%.*ws",
						maxNameLen,
						current->Name.Buffer
					);

					if (NT_SUCCESS(strStatus)) {
						strStatus = RtlStringCchCopyNW(
							LDI[entryCount].BaseDllName,
							sizeof(LDI[entryCount].BaseDllName) / sizeof(WCHAR),
							fullPath,
							min(wcslen(fullPath), sizeof(LDI[entryCount].BaseDllName) / sizeof(WCHAR) - 1)
						);

						if (NT_SUCCESS(strStatus)) {
							entryCount++;
							DbgPrint("EnumAllDevicePath: Added device %ws\n", fullPath);
						}
					}
				}
			}
			current = (POBJECT_DIRECTORY_INFORMATION)((PUCHAR)current + sizeof(OBJECT_DIRECTORY_INFORMATION));
		}
		if (entryCount >= ulBufferSize) {
			break;
		}
	}

	ExFreePoolWithTag(dirInfo, 'eviD');
	ZwClose(hDirectory);

	return entryCount;
}

ULONG EnumDriver(OUT Lite_Driver_Info* LDI, IN ULONG ulBufferSize)
{
	ULONG ulDriverCount = 0;
	PLIST_ENTRY pListEntry = NULL;
	PLDR_DATA_TABLE_ENTRY pLdrEntry = NULL;

	// 获取已加载模块链表
	PLIST_ENTRY pListHead = &PsLoadedModuleList;

	if (!pListHead || !LDI || ulBufferSize == 0) {
		return 0;
	}

	// 计算最大可存储的驱动数量
	ULONG ulMaxDrivers = ulBufferSize / sizeof(Lite_Driver_Info);
	if (ulMaxDrivers == 0) {
		return 0;
	}

	__try {
		// 遍历链表
		pListEntry = pListHead->Flink;

		while (pListEntry != pListHead && ulDriverCount < ulMaxDrivers) {
			// 获取LDR_DATA_TABLE_ENTRY结构
			pLdrEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			if (!pLdrEntry) {
				break;
			}

			// 检查是否为有效驱动
			if (pLdrEntry->DllBase) {
				// 复制驱动名
				if (pLdrEntry->BaseDllName.Buffer && pLdrEntry->BaseDllName.Length > 0) {
					ULONG ulCopyLen = min(pLdrEntry->BaseDllName.Length, sizeof(LDI[ulDriverCount].BaseDllName) - sizeof(WCHAR));

					// 安全地复制字符串
					RtlZeroMemory(LDI[ulDriverCount].BaseDllName, sizeof(LDI[ulDriverCount].BaseDllName));
					RtlCopyMemory(LDI[ulDriverCount].BaseDllName,
						pLdrEntry->BaseDllName.Buffer,
						ulCopyLen);

					// 确保字符串以NULL结尾
					ULONG maxChars = (sizeof(LDI[ulDriverCount].BaseDllName) / sizeof(WCHAR)) - 1;
					ULONG copiedChars = ulCopyLen / sizeof(WCHAR);
					if (copiedChars > maxChars) {
						copiedChars = maxChars;
					}
					LDI[ulDriverCount].BaseDllName[copiedChars] = L'\0';
				}
				else {
					// 如果没有驱动名，设置为空字符串
					LDI[ulDriverCount].BaseDllName[0] = L'\0';
				}

				ulDriverCount++;
			}

			pListEntry = pListEntry->Flink;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		// 发生异常时，返回已枚举的数量
		DbgPrint("EnumDriver: Exception occurred\n");
	}

	return ulDriverCount;
}

BOOLEAN IsRealDriverObject(PDRIVER_OBJECT DriverObject)
{
	if (!DriverObject) {
		return FALSE;
	}

	__try {
		if (DriverObject->Type != IO_TYPE_DRIVER ||
			DriverObject->Size != sizeof(DRIVER_OBJECT)) {
			return FALSE;
		}
		if ((ULONG_PTR)DriverObject < (ULONG_PTR)MmSystemRangeStart) {
			return FALSE;
		}

		return TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}
}

PVOID GetDriverEntryByImageBase(PVOID ImageBase)
{
	PIMAGE_DOS_HEADER pDOSHeader;
	PIMAGE_NT_HEADERS64 pNTHeader;
	PVOID pEntryPoint;
	pDOSHeader = (PIMAGE_DOS_HEADER)ImageBase;
	pNTHeader = (PIMAGE_NT_HEADERS64)((ULONG64)ImageBase + pDOSHeader->e_lfanew);
	pEntryPoint = (PVOID)((ULONG64)ImageBase + pNTHeader->OptionalHeader.AddressOfEntryPoint);
	return pEntryPoint;
}

//Register

NTSTATUS WriteRegisterKey(UNICODE_STRING keyPath, UNICODE_STRING keyName, ULONG keyType, PVOID data, ULONG datasize)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	HANDLE hKey = NULL;
	OBJECT_ATTRIBUTES obj = { 0 };
	InitializeObjectAttributes(
		&obj,
		&keyPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL
	);
	status = ZwCreateKey(&hKey,
		KEY_ALL_ACCESS,
		&obj,
		0,
		NULL,
		REG_OPTION_NON_VOLATILE,
		NULL
	);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	status = ZwSetValueKey(hKey,
		&keyName,
		0,
		keyType,
		data,
		datasize);
	ZwClose(hKey);
	return status;
}
NTSTATUS DeleteRegisterKey(UNICODE_STRING keyPath, UNICODE_STRING keyName)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	HANDLE hKey = NULL;
	OBJECT_ATTRIBUTES obj = { 0 };
	InitializeObjectAttributes(
		&obj,
		&keyPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL
	);
	status = ZwCreateKey(&hKey,
		KEY_ALL_ACCESS,
		&obj,
		0,
		NULL,
		REG_OPTION_NON_VOLATILE,
		NULL
	);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	status = ZwDeleteValueKey(hKey, &keyName);
	ZwClose(hKey);
	return status;
}

NTSTATUS DeleteSubtree(__in HANDLE hKeyParent)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG index = 0;
	PKEY_BASIC_INFORMATION keyInfo = NULL;
	ULONG bufferSize = 512;
	HANDLE hSubKey = NULL;
	OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING subKeyName;
	ULONG context = 0;
	while (1) {
		PVOID newBuffer = ExAllocatePoolWithTag(PagedPool, bufferSize, 'subk');
		if (!newBuffer) {
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		if (keyInfo) ExFreePool(keyInfo);
		keyInfo = (PKEY_BASIC_INFORMATION)newBuffer;
		status = ZwEnumerateKey(
			hKeyParent,
			index,
			KeyBasicInformation,
			keyInfo,
			bufferSize,
			&bufferSize
		);

		if (status == STATUS_BUFFER_OVERFLOW || status == STATUS_BUFFER_TOO_SMALL) {
			continue;
		}

		if (status == STATUS_NO_MORE_ENTRIES) {
			break;
		}

		if (!NT_SUCCESS(status)) {
			break;
		}
		subKeyName.Length = (USHORT)keyInfo->NameLength;
		subKeyName.MaximumLength = (USHORT)keyInfo->NameLength;
		subKeyName.Buffer = keyInfo->Name;
		InitializeObjectAttributes(
			&objAttr,
			&subKeyName,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			hKeyParent,
			NULL
		);

		status = ZwOpenKey(
			&hSubKey,
			DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE,
			&objAttr
		);

		if (NT_SUCCESS(status)) {
			NTSTATUS subtreeStatus = DeleteSubtree(hSubKey);
			ZwClose(hSubKey);
			hSubKey = NULL;
			ZwDeleteKey(hSubKey ? hSubKey : (HANDLE)-1);
			if (!NT_SUCCESS(subtreeStatus)) {
				DbgPrint("Failed to delete subtree: 0x%X\n", subtreeStatus);
			}
		}
		index++;
	}
	if (keyInfo) {
		ExFreePool(keyInfo);
		keyInfo = NULL;
	}
	index = 0;
	PKEY_VALUE_BASIC_INFORMATION valueInfo = NULL;
	bufferSize = 256;

	while (1) {
		PVOID newBuffer = ExAllocatePoolWithTag(PagedPool, bufferSize, 'valk');
		if (!newBuffer) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		if (valueInfo) ExFreePool(valueInfo);
		valueInfo = (PKEY_VALUE_BASIC_INFORMATION)newBuffer;

		status = ZwEnumerateValueKey(
			hKeyParent,
			index,
			KeyValueBasicInformation,
			valueInfo,
			bufferSize,
			&bufferSize
		);

		if (status == STATUS_BUFFER_OVERFLOW || status == STATUS_BUFFER_TOO_SMALL) {
			continue;
		}
		if (status == STATUS_NO_MORE_ENTRIES) {
			status = STATUS_SUCCESS; 
			break;
		}
		if (!NT_SUCCESS(status)) {
			break;
		}
		UNICODE_STRING valueName;
		valueName.Length = (USHORT)valueInfo->NameLength;
		valueName.MaximumLength = (USHORT)valueInfo->NameLength;
		valueName.Buffer = valueInfo->Name;
		ZwDeleteValueKey(hKeyParent, &valueName);
		index++;
	}

	if (valueInfo) {
		ExFreePool(valueInfo);
		valueInfo = NULL;
	}

	return status;
}

// 主删除函数
NTSTATUS DeleteRegisterTree(__in PUNICODE_STRING keyPath)
{
	NTSTATUS status;
	HANDLE hKey;
	OBJECT_ATTRIBUTES objAttr;

	// 初始化对象属性
	InitializeObjectAttributes(
		&objAttr,
		keyPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL
	);

	// 打开目标键
	status = ZwOpenKey(
		&hKey,
		DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE,
		&objAttr
	);

	if (!NT_SUCCESS(status)) {
		DbgPrint("ZwOpenKey failed: 0x%X\n", status);
		return status;
	}

	// 递归删除子树
	status = DeleteSubtree(hKey);

	// 即使子树删除失败，也尝试删除键本身
	NTSTATUS deleteStatus = ZwDeleteKey(hKey);
	if (!NT_SUCCESS(deleteStatus)) {
		DbgPrint("ZwDeleteKey failed: 0x%X (Subtree status: 0x%X)\n", deleteStatus, status);

		// 如果子树删除成功但键删除失败，返回键删除状态
		if (NT_SUCCESS(status)) {
			status = deleteStatus;
		}
	}

	ZwClose(hKey);
	return status;
}

NTSTATUS GetKeyPathUnicodeString(HANDLE KeyHandle, PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;
	ULONG resultLength = 0;
	PKEY_NAME_INFORMATION keyInfo = NULL;

	// 初始化输出
	RegistryPath->Length = 0;
	RegistryPath->MaximumLength = 0;
	RegistryPath->Buffer = NULL;

	// 第一次调用获取所需大小
	status = ZwQueryKey(
		KeyHandle,
		KeyNameInformation,
		NULL,
		0,
		&resultLength);

	if (status != STATUS_BUFFER_TOO_SMALL) {
		return status;
	}

	// 分配缓冲区
	keyInfo = (PKEY_NAME_INFORMATION)ExAllocatePoolWithTag(
		PagedPool,
		resultLength,
		'KeyP');

	if (!keyInfo) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(keyInfo, resultLength);

	// 第二次调用获取实际数据
	status = ZwQueryKey(
		KeyHandle,
		KeyNameInformation,
		keyInfo,
		resultLength,
		&resultLength);

	if (!NT_SUCCESS(status)) {
		ExFreePoolWithTag(keyInfo, 'KeyP');
		return status;
	}

	// 验证获取的数据
	if (keyInfo->NameLength == 0 || keyInfo->NameLength > 1024 * sizeof(WCHAR)) {
		ExFreePoolWithTag(keyInfo, 'KeyP');
		return STATUS_INVALID_PARAMETER;
	}

	// 分配输出缓冲区（多分配一个WCHAR用于终止符）
	RegistryPath->Buffer = (PWCHAR)ExAllocatePoolWithTag(
		PagedPool,
		keyInfo->NameLength + sizeof(WCHAR),
		'StrB');

	if (!RegistryPath->Buffer) {
		ExFreePoolWithTag(keyInfo, 'KeyP');
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// 复制并清理数据
	RtlZeroMemory(RegistryPath->Buffer, keyInfo->NameLength + sizeof(WCHAR));
	RtlCopyMemory(RegistryPath->Buffer, keyInfo->Name, keyInfo->NameLength);

	// 确保路径以null终止
	RegistryPath->Buffer[keyInfo->NameLength / sizeof(WCHAR)] = L'\0';

	// 设置UNICODE_STRING字段
	RegistryPath->Length = (USHORT)keyInfo->NameLength;
	RegistryPath->MaximumLength = (USHORT)(keyInfo->NameLength + sizeof(WCHAR));

	// 释放临时缓冲区
	ExFreePoolWithTag(keyInfo, 'KeyP');

	return STATUS_SUCCESS;
}

//other

BOOLEAN SafeReadMemory(PVOID Address, PVOID Buffer, SIZE_T Size)
{
	PMDL Mdl = IoAllocateMdl(Address, (ULONG)Size, FALSE, FALSE, NULL);
	if (!Mdl) return FALSE;

	__try {
		MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
		PVOID MappedAddress = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
		if (MappedAddress) {
			RtlCopyMemory(Buffer, MappedAddress, Size);
			MmUnlockPages(Mdl);
			IoFreeMdl(Mdl);
			return TRUE;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		if (Mdl) {
			MmUnlockPages(Mdl);
			IoFreeMdl(Mdl);
		}
		return FALSE;
	}

	if (Mdl) IoFreeMdl(Mdl);
	return FALSE;
}

PVOID SearchPattern(
	PVOID BaseAddress,
	SIZE_T SearchSize,
	const UCHAR* Pattern,
	SIZE_T PatternSize,
	UCHAR Wildcard
) {
	for (SIZE_T i = 0; i <= SearchSize - PatternSize; i++) {
		BOOLEAN Found = TRUE;
		PVOID CurrentAddress = (PUCHAR)BaseAddress + i;

		UCHAR* CurrentPattern = (UCHAR*)Pattern;
		for (SIZE_T j = 0; j < PatternSize; j++) {
			UCHAR MemoryByte;

			if (!SafeReadMemory((PUCHAR)CurrentAddress + j, &MemoryByte, sizeof(UCHAR))) {
				Found = FALSE;
				break;
			}

			if (CurrentPattern[j] != Wildcard && MemoryByte != CurrentPattern[j]) {
				Found = FALSE;
				break;
			}
		}

		if (Found) {
			return CurrentAddress;
		}
	}
	return NULL;
}

BOOLEAN Hook_IsProcessProtected(HANDLE pid) {
	for (int i = 0; i < HOOK_ProtectedProcessCount; i++) {
		if (HOOK_ProtectedProcesses[i] == pid) {
			return TRUE;
		}
	}
	return FALSE;
}

NTSTATUS Hook_AddProtectedProcess(HANDLE pid) {
	if (HOOK_ProtectedProcessCount >= HOOK_MAX_PROTECTED_PROCESSES) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	if (Hook_IsProcessProtected(pid)) {
		return STATUS_SUCCESS;
	}

	HOOK_ProtectedProcesses[HOOK_ProtectedProcessCount++] = pid;
	return STATUS_SUCCESS;
}

NTSTATUS Hook_RemoveProtectedProcess(HANDLE pid) {
	for (int i = 0; i < HOOK_ProtectedProcessCount; i++) {
		if (HOOK_ProtectedProcesses[i] == pid) {
			for (int j = i; j < HOOK_ProtectedProcessCount - 1; j++) {
				HOOK_ProtectedProcesses[j] = HOOK_ProtectedProcesses[j + 1];
			}
			HOOK_ProtectedProcessCount--;
			return STATUS_SUCCESS;
		}
	}
	return STATUS_NOT_FOUND;
}

BOOLEAN Hook_IsThreadProtected(HANDLE tid) {
	for (int i = 0; i < HOOK_ProtectedThreadCount; i++) {
		if (HOOK_ProtectedThreads[i] == tid) {
			return TRUE;
		}
	}
	return FALSE;
}

NTSTATUS Hook_AddProtectedThread(HANDLE tid) {
	if (HOOK_ProtectedProcessCount >= HOOK_MAX_PROTECTED_THREADS) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	if (Hook_IsThreadProtected(tid)) {
		return STATUS_SUCCESS;
	}

	HOOK_ProtectedThreads[HOOK_ProtectedThreadCount++] = tid;
	return STATUS_SUCCESS;
}

NTSTATUS Hook_RemoveProtectedThread(HANDLE tid) {
	for (int i = 0; i < HOOK_ProtectedThreadCount; i++) {
		if (HOOK_ProtectedThreads[i] == tid) {
			for (int j = i; j < HOOK_ProtectedThreadCount - 1; j++) {
				HOOK_ProtectedThreads[j] = HOOK_ProtectedThreads[j + 1];
			}
			HOOK_ProtectedThreadCount--;
			return STATUS_SUCCESS;
		}
	}
	return STATUS_NOT_FOUND;
}

NTSTATUS ReadRegistryPassword() {
	NTSTATUS status;
	UNICODE_STRING keyPath;
	UNICODE_STRING valueName;
	HANDLE hKey = NULL;
	OBJECT_ATTRIBUTES objAttr;
	ULONG resultLength = 0;
	PKEY_VALUE_PARTIAL_INFORMATION pvInfo = NULL;

	RtlInitUnicodeString(&keyPath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\EDiskFreezeDrv64\\Parameters");
	RtlInitUnicodeString(&valueName, L"Password");

	InitializeObjectAttributes(&objAttr, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwOpenKey(&hKey, KEY_QUERY_VALUE, &objAttr);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ZwOpenKey failed: 0x%08X\n", status);
		return status;
	}

	status = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation, NULL, 0, &resultLength);
	if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ZwQueryValueKey size query failed: 0x%08X\n", status);
		goto Cleanup;
	}

	pvInfo = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, resultLength, 'pwdR');
	if (pvInfo == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ExAllocatePoolWithTag failed\n");
		goto Cleanup;
	}

	status = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation, pvInfo, resultLength, &resultLength);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ZwQueryValueKey data query failed: 0x%08X\n", status);
		goto Cleanup;
	}

	if (pvInfo->Type != REG_SZ) {
		status = STATUS_OBJECT_TYPE_MISMATCH;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Value type not REG_SZ (actual: %lu)\n", pvInfo->Type);
		goto Cleanup;
	}

	ULONG copyLen = min(pvInfo->DataLength, (sizeof(EDF_Password) - sizeof(WCHAR)));
	RtlCopyMemory(EDF_Password, pvInfo->Data, copyLen);
	EDF_Password[copyLen / sizeof(WCHAR)] = L'\0';

	status = STATUS_SUCCESS;

Cleanup:
	if (pvInfo) ExFreePoolWithTag(pvInfo, 'pwdR');
	if (hKey) ZwClose(hKey);
	return status;
}
NTSTATUS DeviceIoctl(PDEVICE_OBJECT Device, PIRP pIrp)
{
	NTSTATUS status;
	// 获取IRP消息的数据
	PIO_STACK_LOCATION irps = IoGetCurrentIrpStackLocation(pIrp);
	// 获取传过来的控制码
	ULONG CODE = irps->Parameters.DeviceIoControl.IoControlCode;
	ULONG info = 0;
	ULONG funcCode = (CODE >> 2) & 0xFFF;
	if (CODE == IOCTL_DISK_DELETE_DRIVE_LAYOUT)
	{
		pIrp->IoStatus.Information = 0;
		pIrp->IoStatus.Status = STATUS_ACCESS_DENIED;
		IoCompleteRequest(pIrp, IO_NO_INCREMENT);
		return pIrp->IoStatus.Status;
	}
	if (Device != g_ControlDeviceObject) {
		return g_OriginalDiskDeviceControl(Device, pIrp);
	}
	if (funcCode < 0x800 || funcCode > 0xFFF)
	{
		return DiskHook_DispatchDeviceControl(Device,pIrp);
	}
	if (CODE != IOCTL_FORCEREADDISKBYPASSDISKHOOK &&
		CODE != IOCTL_SETPPL &&
		CODE != IOCTL_PROTECTPROCESS) {
		DbgPrint("password\n");
		DbgPrint("DeviceIoctl: CODE = 0x%08X\n", CODE);
		PVOID buffer = pIrp->AssociatedIrp.SystemBuffer;
		ULONG inLen = irps->Parameters.DeviceIoControl.InputBufferLength;

		// 输入缓冲区至少需要 64 字节（SHA-512 长度）
		if (inLen < 64) {
			status = STATUS_INVALID_PARAMETER;
			DbgPrint("inLen < 64\n");
			goto InvalidPassword;
		}

		UCHAR computedHash[32];
		status = ComputeSha256(buffer, 64, computedHash);
		DbgPrint("computedHash: %02X%02X...", computedHash[0], computedHash[1]);
		DbgPrint("EDF_Password: %02X%02X...", EDF_Password[0], EDF_Password[1]);
		if (!NT_SUCCESS(status)) {
			status = STATUS_HASH_NOT_SUPPORTED;
			goto InvalidPassword;
		}
		WCHAR kernelSha256HexString[65] = { 0 };
		for (int i = 0; i < 32; i++) {
			RtlStringCchPrintfW(&kernelSha256HexString[i * 2], 3, L"%02x", computedHash[i]);
		}
		DbgPrint("kernelSha256HexString: %ws\n", kernelSha256HexString);
		DbgPrint("EDF_Password: %ws\n", EDF_Password);
		// 比较哈希值是否与预设密码匹配
		if (_wcsicmp(EDF_Password, kernelSha256HexString) != 0) {
			status = STATUS_WRONG_PASSWORD;
			goto InvalidPassword;
		}

		// 密码正确：将后面的私有数据移动到缓冲区开头
		ULONG privateLen = inLen - 64;
		if (privateLen > 0) {
			RtlMoveMemory(buffer, (PUCHAR)buffer + 64, privateLen);
		}
		// 更新输入缓冲区长度，后续处理将只看到私有数据
		irps->Parameters.DeviceIoControl.InputBufferLength = privateLen;
	}
	else
	{
		PVOID buffer = pIrp->AssociatedIrp.SystemBuffer;
		ULONG inLen = irps->Parameters.DeviceIoControl.InputBufferLength;

		if (inLen < 64) {
			status = STATUS_INVALID_PARAMETER;
			goto InvalidPassword;
		}

		ULONG privateLen = inLen - 64;
		if (privateLen > 0) {
			RtlMoveMemory(buffer, (PUCHAR)buffer + 64, privateLen);
		}
		irps->Parameters.DeviceIoControl.InputBufferLength = privateLen;
	}
	//DbgPrint("IoControlCode:%d", CODE);
	switch (CODE)
	{
	case IOCTL_KILLPROCESS:
	{
		DbgPrint("Enter the IO KP \n");
		ULONG pid = *(PLONG)(pIrp->AssociatedIrp.SystemBuffer);
		DbgPrint("Get PID : %d\n", pid);
		if (TerminateProcessByAPI(pid, 0))
		{
			DbgPrint("[EFCHKMD] Kill Process Successful\n");
			status = STATUS_SUCCESS;
		}
		else
		{
			DbgPrint("[EFCHKMD] Kill Process Failed\n");
			status = STATUS_UNSUCCESSFUL;
		}
		break;
	}
	case IOCTL_SUSPENDPROCESS:
	{
		DbgPrint("Enter the IO SuspendProcess \n");
		ULONG pid = *(PLONG)(pIrp->AssociatedIrp.SystemBuffer);
		DbgPrint("Get PID : %d\n", pid);
		status = SuspendProcess(pid);
		if (NT_SUCCESS(status))
		{
			DbgPrint("[EFCHKMD] Suspend Process Successful\n");
		}
		else
		{
			DbgPrint("[EFCHKMD] Suspend Process Failed\n");
		}
		break;
	}
	case IOCTL_RESUMEPROCESS:
	{
		DbgPrint("Enter the IO ResumeProcess \n");
		ULONG pid = *(PLONG)(pIrp->AssociatedIrp.SystemBuffer);
		DbgPrint("Get PID : %d\n", pid);
		status = ResumeProcess(pid);
		if (NT_SUCCESS(status))
		{
			DbgPrint("[EFCHKMD] Resume Process Successful\n");
		}
		else
		{
			DbgPrint("[EFCHKMD] Resume Process Failed\n");
		}
		break;
	}
	case IOCTL_PROTECTPROCESS:
	{
		DbgPrint("Enter the IO ProtectProcess\n");
		ULONG pid = *(PLONG)(pIrp->AssociatedIrp.SystemBuffer);
		DbgPrint("Get PID : %d\n", pid);
		if (ProtectProcess(pid))
		{
			DbgPrint("[EFCHKMD] ProtectProcess Successful\n");
			status = STATUS_SUCCESS;
		}
		else
		{
			DbgPrint("[EFCHKMD] ProtectProcess Failed\n");
			status = STATUS_UNSUCCESSFUL;
		}
		break;
	}
	case IOCTL_UNPROTECTPROCESS:
	{
		DbgPrint("Enter the IO UnProtectProcess\n");
		ULONG pid = *(PLONG)(pIrp->AssociatedIrp.SystemBuffer);
		DbgPrint("Get PID : %d\n", pid);
		if (UnprotectProcess(pid))
		{
			DbgPrint("[EFCHKMD] UnProtectProcess Successful\n");
			status = STATUS_SUCCESS;
		}
		else
		{
			DbgPrint("[EFCHKMD] UnProtectProcess Failed\n");
			status = STATUS_UNSUCCESSFUL;
		}
		break;
	}
	case IOCTL_SETPPL:
	{
		DbgPrint("Enter the IO SetPP/PPL\n");
		PULONG inputBuffer = (PULONG)pIrp->AssociatedIrp.SystemBuffer;
		if (pIrp->AssociatedIrp.SystemBuffer == NULL ||
			irps->Parameters.DeviceIoControl.InputBufferLength < 8)
		{
			DbgPrint("[EFCHKMD] Invalid inputbuffer\n");
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		ULONG pid = inputBuffer[0];
		ULONG ppltype = inputBuffer[1];
		status = SetPPL(pid, ppltype);
		if (NT_SUCCESS(status))
		{
			DbgPrint("[EFCHKMD] SetPP/PPL Successful\n");
		}
		else
		{
			DbgPrint("[EFCHKMD] SetPP/PPL Failed\n");
		}
		break;
	}
	case IOCTL_SETPROCESSCRITICAL:
	{
		DbgPrint("Enter the IO SetProcessCritical\n");
		PULONG inputBuffer = (PULONG)pIrp->AssociatedIrp.SystemBuffer;
		if (irps->Parameters.DeviceIoControl.InputBufferLength < 12)
		{
			DbgPrint("[EFCHKMD] Invalid inputbuffer\n");
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		HANDLE pid = *(PHANDLE)inputBuffer;
		ULONG IsCritical = *(PULONG)(inputBuffer + 8);
		status = SetProcessCritical(pid, IsCritical);
		if (NT_SUCCESS(status)) {
			DbgPrint("[EFCHKMD] SetProcessCritical Successful\n");
		}
		else {
			DbgPrint("[EFCHKMD] SetProcessCritical Failed: 0x%X\n", status);
		}
		break;
	}
	case IOCTL_EPROCESSENUMPROCESS:
	{
		DbgPrint("Enter the IO EProcessEnumProcess\n");

		// 动态分配PID数组
		ULONG bufferSize = 65535 * sizeof(ULONG);
		ULONG* PIDs = (ULONG*)ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'PIDT');

		if (PIDs == NULL) {
			DbgPrint("[EFCHKMD] Memory allocation failed\n");
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		// 枚举进程
		ULONG PIDNumber = EPROCESSEnumProcess(PIDs);
		DbgPrint("PIDNumber:%u", PIDNumber);

		if (PIDNumber != 0)
		{
			DbgPrint("[EFCHKMD] EProcessEnumProcess Successful\n");

			// 计算实际需要的数据大小
			ULONG requiredSize = PIDNumber * sizeof(ULONG);

			// 检查输出缓冲区是否足够大
			if (irps->Parameters.DeviceIoControl.OutputBufferLength < requiredSize)
			{
				DbgPrint("[EFCHKMD] Outbuffer too small, need %u bytes\n", requiredSize);
				ExFreePoolWithTag(PIDs, 'PIDT');
				status = STATUS_BUFFER_TOO_SMALL;
				break;
			}

			// 将PID数组作为连续字节流复制到输出缓冲区
			RtlCopyMemory(
				pIrp->AssociatedIrp.SystemBuffer,
				PIDs,
				requiredSize
			);

			// 设置返回的信息长度
			info = requiredSize;
			status = STATUS_SUCCESS;
		}
		else
		{
			DbgPrint("[EFCHKMD] EProcessEnumProcess Failed\n");
			info = 0;
			status = STATUS_UNSUCCESSFUL;
		}

		// 释放动态分配的内存
		ExFreePoolWithTag(PIDs, 'PIDT');
		break;
	}
	case IOCTL_GETPPL:
	{
		DbgPrint("Enter the IO GetPPL\n");
		PULONG inputBuffer = (PULONG)pIrp->AssociatedIrp.SystemBuffer;
		DbgPrint("[EFCHKMD] PID:%u", *inputBuffer);
		int PPL = 0;
		status = GetPPL(*inputBuffer, &PPL);
		if (NT_SUCCESS(status))
		{
			DbgPrint("[EFCHKMD] PPL:%u", PPL);
			DbgPrint("[EFCHKMD] GetPPL Successful\n");
			int* outputBuffer = (int*)pIrp->AssociatedIrp.SystemBuffer;
			*outputBuffer = PPL;
			info = sizeof(int);
		}
		else
		{
			DbgPrint("[EFCHKMD] GetPPL Failed\n");
			info = 0;
		}
		break;
	}
	case IOCTL_GETPROCESSIMAGENAME:
	{
		PEPROCESS process;
		HANDLE pid = *(PHANDLE)(pIrp->AssociatedIrp.SystemBuffer);
		PUCHAR outputBuffer = (PUCHAR)pIrp->AssociatedIrp.SystemBuffer;
		ULONG outputLen = irps->Parameters.DeviceIoControl.OutputBufferLength; // 获取输出缓冲区大小

		status = PsLookupProcessByProcessId(pid, &process);
		if (!NT_SUCCESS(status)) {
			DbgPrint("[EFCHKMD] PsLookup failed\n");
			break;
		}

		WCHAR buffer[1024];
		UNICODE_STRING u;
		RtlInitEmptyUnicodeString(&u, buffer, sizeof(buffer));
		status = GetProcessDosImageName(process, &u);
		ObDereferenceObject(process);
		if (NT_SUCCESS(status)) {
			DbgPrint("Path: %wZ\n", &u);
			if (outputLen >= u.Length) {
				RtlCopyMemory(outputBuffer, u.Buffer, u.Length);
				info = u.Length;
			}
			else {
				status = STATUS_BUFFER_TOO_SMALL;
				info = 0;
			}
		}
		break;
	}
	case IOCTL_OCCUPYFILE:
	{
		DbgPrint("Enter the IO OccupyFile\n");
		WCHAR* filePatch = (WCHAR*)pIrp->AssociatedIrp.SystemBuffer;
		HANDLE hFile = NULL;
		UNICODE_STRING uniPath;
		RtlInitUnicodeString(&uniPath, filePatch);
		if (OccupyFile(uniPath, &hFile))
		{
			DbgPrint("[EFCHKMD] OccupyFile Successful\n");
			status = STATUS_SUCCESS;
		}
		else
		{
			DbgPrint("[EFCHKMD] OccupyFile Failed\n");
			status = STATUS_UNSUCCESSFUL;
		}
		break;
	}
	case IOCTL_WRITEDISK:
	{
		DbgPrint("Enter the IO WriteDisk\n");
		PUCHAR inputBuffer = (PUCHAR)pIrp->AssociatedIrp.SystemBuffer;
		ULONG inputLength = irps->Parameters.DeviceIoControl.InputBufferLength;

		if (inputLength < 17) {
			DbgPrint("WriteDisk Failed: InBuffer Error\n");
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		LARGE_INTEGER startSector = *(PLARGE_INTEGER)inputBuffer;
		LARGE_INTEGER sectorCount = *(PLARGE_INTEGER)(inputBuffer + 8);
		ULONG dataLength = (ULONG)(sectorCount.QuadPart * 512);

		// 关键修改：创建新的缓冲区副本
		PVOID safeBuffer = ExAllocatePoolWithTag(NonPagedPoolNx, dataLength, 'mbr0');
		if (!safeBuffer) {
			DbgPrint("内存分配失败\n");
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		// 复制用户传入的数据
		RtlCopyMemory(safeBuffer, inputBuffer + 17, dataLength);

		DbgPrint("WriteDisk Params: StartSector=%lld, SectorCount=%lld, DataLen=%d\n",
			startSector.QuadPart, sectorCount.QuadPart, dataLength);

		// 使用安全缓冲区写入
		status = WriteToDiskEx(
			startSector,
			(ULONG)sectorCount.QuadPart,
			safeBuffer
		);

		// 释放缓冲区
		ExFreePool(safeBuffer);

		if (NT_SUCCESS(status)) {
			DbgPrint("[EFCHKMD] WriteDisk Successful\n");
		}
		else {
			DbgPrint("[EFCHKMD] WriteDisk Failed: 0x%X\n", status);
		}
		break;
	}
	case IOCTL_FORCEWRITEDISK:
	{
		DbgPrint("Enter the IO ForceWriteDisk\n");
		PUCHAR inputBuffer = (PUCHAR)pIrp->AssociatedIrp.SystemBuffer;
		ULONG inputLength = irps->Parameters.DeviceIoControl.InputBufferLength;

		if (inputLength < 17) {
			DbgPrint("WriteDisk Failed: InBuffer Error\n");
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		LARGE_INTEGER startSector = *(PLARGE_INTEGER)inputBuffer;
		LARGE_INTEGER sectorCount = *(PLARGE_INTEGER)(inputBuffer + 8);
		ULONG dataLength = (ULONG)(sectorCount.QuadPart * 512);

		// 关键修改：创建新的缓冲区副本
		PVOID safeBuffer = ExAllocatePoolWithTag(NonPagedPoolNx, dataLength, 'mbr0');
		if (!safeBuffer) {
			DbgPrint("内存分配失败\n");
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		// 复制用户传入的数据
		RtlCopyMemory(safeBuffer, inputBuffer + 17, dataLength);

		DbgPrint("WriteDisk Params: StartSector=%lld, SectorCount=%lld, DataLen=%d\n",
			startSector.QuadPart, sectorCount.QuadPart, dataLength);

		// 使用安全缓冲区写入
		status = IrpWriteToDiskEx(
			startSector,
			(ULONG)sectorCount.QuadPart,
			safeBuffer
		);

		// 释放缓冲区
		ExFreePool(safeBuffer);

		if (NT_SUCCESS(status)) {
			DbgPrint("[EFCHKMD] ForceWriteDisk Successful\n");
		}
		else {
			DbgPrint("[EFCHKMD] ForceWriteDisk Failed: 0x%X\n", status);
		}
		break;
	}
	case IOCTL_FORCEWRITEDISKBYPASSDISKHOOK:
	{
		DbgPrint("Enter the IO ForceWriteDisk\n");
		PUCHAR inputBuffer = (PUCHAR)pIrp->AssociatedIrp.SystemBuffer;
		ULONG inputLength = irps->Parameters.DeviceIoControl.InputBufferLength;

		if (inputLength < 17) {
			DbgPrint("WriteDisk Failed: InBuffer Error\n");
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		LARGE_INTEGER startSector = *(PLARGE_INTEGER)inputBuffer;
		LARGE_INTEGER sectorCount = *(PLARGE_INTEGER)(inputBuffer + 8);
		ULONG dataLength = (ULONG)(sectorCount.QuadPart * 512);

		// 关键修改：创建新的缓冲区副本
		PVOID safeBuffer = ExAllocatePoolWithTag(NonPagedPoolNx, dataLength, 'mbr0');
		if (!safeBuffer) {
			DbgPrint("内存分配失败\n");
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		// 复制用户传入的数据
		RtlCopyMemory(safeBuffer, inputBuffer + 17, dataLength);

		DbgPrint("WriteDisk Params: StartSector=%lld, SectorCount=%lld, DataLen=%d\n",
			startSector.QuadPart, sectorCount.QuadPart, dataLength);

		// 使用安全缓冲区写入
		if (EnableDiskFreeze)
		{
			status = WriteOriginalSectorEx(
				startSector,
				(ULONG)sectorCount.QuadPart,
				safeBuffer
			);
		}
		else
		{
			status = IrpWriteToDiskEx(
				startSector,
				(ULONG)sectorCount.QuadPart,
				safeBuffer
			);
		}

		// 释放缓冲区
		ExFreePool(safeBuffer);

		if (NT_SUCCESS(status)) {
			DbgPrint("[EFCHKMD] ForceWriteDisk Successful\n");
		}
		else {
			DbgPrint("[EFCHKMD] ForceWriteDisk Failed: 0x%X\n", status);
		}
		break;
	}
	case IOCTL_FORCEDELETEFILE:
	{
		DbgPrint("Enter the IO ForceDeleteFile\n");
		WCHAR* filePatch = (WCHAR*)pIrp->AssociatedIrp.SystemBuffer;
		UNICODE_STRING uniPath;
		RtlInitUnicodeString(&uniPath, filePatch);
		status = ForceDeleteFile(uniPath);
		if (NT_SUCCESS(status))
		{
			DbgPrint("[EFCHKMD] ForceDeleteFile Successful\n");
		}
		else
		{
			DbgPrint("[EFCHKMD] ForceDeleteFile Failed\n");
		}
		break;
	}
	case IOCTL_FORCEOCCUPYFILE:
	{
		DbgPrint("Enter the IO ForceOuuupyFile\n");
		WCHAR* filePatch = (WCHAR*)pIrp->AssociatedIrp.SystemBuffer;
		UNICODE_STRING uniPath;
		RtlInitUnicodeString(&uniPath, filePatch);
		Irp_OpenFile_Unicode_string(&uniPath);
		DbgPrint("[EFCHKMD] ForceOccupyFile Done\n");
		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_FORCEWRITEFILE:
	{
		DbgPrint("Enter the IO ForceWriteFile\n");
		PUCHAR inputBuffer = (PUCHAR)pIrp->AssociatedIrp.SystemBuffer;
		ULONG inputLength = irps->Parameters.DeviceIoControl.InputBufferLength;

		// 输入缓冲区必须包含至少512字节路径 + 至少1字节数据
		if (inputLength < 513) {
			DbgPrint("WriteFile Failed: InputBuffer too small\n");
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		// 提取文件路径（前512字节）
		WCHAR* filePathBuffer = (WCHAR*)inputBuffer;
		ULONG pathMaxChars = 512 / sizeof(WCHAR); // 最多256个字符

		// 验证Unicode路径是否以NULL结尾
		BOOLEAN nullTerminated = FALSE;
		for (ULONG i = 0; i < pathMaxChars; i++) {
			if (filePathBuffer[i] == L'\0') {
				nullTerminated = TRUE;
				break;
			}
		}

		if (!nullTerminated) {
			DbgPrint("WriteFile Failed: File path not null-terminated in 512 bytes\n");
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		// 初始化UNICODE_STRING路径
		UNICODE_STRING targetFilePath;
		targetFilePath.Buffer = filePathBuffer;
		targetFilePath.Length = (USHORT)(wcslen(filePathBuffer) * sizeof(WCHAR));
		targetFilePath.MaximumLength = 512; // 最大512字节

		// 计算数据部分长度和起始位置
		ULONG dataLength = inputLength - 512;
		PUCHAR dataStart = inputBuffer + 512;

		// 分配安全内存复制用户数据
		PVOID safeBuffer = ExAllocatePoolWithTag(NonPagedPoolNx, dataLength, 'wfle');
		if (!safeBuffer) {
			DbgPrint("Memory allocation failed for data buffer\n");
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		// 复制用户数据到安全缓冲区
		RtlCopyMemory(safeBuffer, dataStart, dataLength);

		// 调用写入函数
		status = WriteFile_IRP(&targetFilePath, safeBuffer, dataLength);

		// 释放安全缓冲区
		ExFreePool(safeBuffer);

		if (NT_SUCCESS(status)) {
			DbgPrint("[EFCHKMD] ForceWriteFile Successful\n");
			info = dataLength; // 返回写入的数据长度
		}
		else {
			DbgPrint("[EFCHKMD] ForceWriteFile Failed: 0x%X\n", status);
		}
		break;
	}
	case IOCTL_IRPQUERYFILEANDFOLDERS:
	{
		DbgPrint("Enter the IO IOCTL_IRPENUMFILE\n");

		// 获取输入缓冲区（路径字符串）
		WCHAR* filePath = (WCHAR*)pIrp->AssociatedIrp.SystemBuffer;
		ULONG inputLength = irps->Parameters.DeviceIoControl.InputBufferLength;
		ULONG outputLength = irps->Parameters.DeviceIoControl.OutputBufferLength;

		// 验证输入参数
		if (filePath == NULL || inputLength == 0)
		{
			DbgPrint("IOCTL_IRPENUMFILE: Invalid input buffer\n");
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		DbgPrint("DATA_INFO:%u", sizeof(DATA_INFO));
		DbgPrint("IOCTL_IRPENUMFILE: sizeof(DATA_INFO) = %lu bytes\n", sizeof(DATA_INFO));
		DbgPrint("IOCTL_IRPENUMFILE: Output buffer size = %lu bytes, can hold %lu entries\n",
			outputLength, outputLength / sizeof(DATA_INFO));
		// 确保路径以null结尾
		ULONG pathLength = min(inputLength, 1024 * sizeof(WCHAR));
		WCHAR* safePath = (WCHAR*)ExAllocatePoolWithTag(NonPagedPool, pathLength + sizeof(WCHAR), 'PATH');
		if (safePath == NULL)
		{
			DbgPrint("IOCTL_IRPENUMFILE: Memory allocation failed\n");
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		RtlZeroMemory(safePath, pathLength + sizeof(WCHAR));
		RtlCopyMemory(safePath, filePath, pathLength);

		// 初始化UNICODE_STRING
		UNICODE_STRING uniPath;
		RtlInitUnicodeString(&uniPath, safePath);

		DbgPrint("IOCTL_IRPENUMFILE: Enumerating path: %wZ\n", &uniPath);

		// 先获取文件数量
		ULONG itemCount = Fs_GetFileAndFolderQuantity_UNICODE_Irp(&uniPath);
		DbgPrint("IOCTL_IRPENUMFILE: Found %lu items total\n", itemCount);

		if (itemCount == 0)
		{
			DbgPrint("IOCTL_IRPENUMFILE: No files found\n");
			ExFreePoolWithTag(safePath, 'PATH');
			status = STATUS_NO_MORE_FILES;
			break;
		}

		// 动态分配DATA_INFO数组
		ULONG dataSize = itemCount * sizeof(DATA_INFO);
		PDATA_INFO pDynamicData = (PDATA_INFO)ExAllocatePoolWithTag(NonPagedPool, dataSize, 'DATA');
		if (pDynamicData == NULL)
		{
			DbgPrint("IOCTL_IRPENUMFILE: Dynamic data allocation failed\n");
			ExFreePoolWithTag(safePath, 'PATH');
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		// 清零动态数组
		RtlZeroMemory(pDynamicData, dataSize);

		// 调用文件枚举函数
		ULONG actualCount = Fs_QueryFileAndFileFolder_UNICODE_Irp(&uniPath, pDynamicData);
		DbgPrint("IOCTL_IRPENUMFILE: Actually enumerated %lu items\n", actualCount);

		// 计算可以复制到输出缓冲区的最大条目数
		ULONG maxEntries = 0;
		PDATA_INFO pOutputBuffer = NULL;

		if (outputLength >= sizeof(DATA_INFO))
		{
			maxEntries = outputLength / sizeof(DATA_INFO);
			pOutputBuffer = (PDATA_INFO)pIrp->AssociatedIrp.SystemBuffer;

			// 清零输出缓冲区
			RtlZeroMemory(pOutputBuffer, outputLength);

			// 复制数据到输出缓冲区
			ULONG entriesToCopy = min(actualCount, maxEntries);
			ULONG copySize = entriesToCopy * sizeof(DATA_INFO);

			if (copySize > 0)
			{
				RtlCopyMemory(pOutputBuffer, pDynamicData, copySize);
				info = copySize;
				DbgPrint("IOCTL_IRPENUMFILE: Copied %lu entries to output buffer\n", entriesToCopy);
			}
		}
		else
		{
			DbgPrint("IOCTL_IRPENUMFILE: Output buffer too small, no data copied\n");
		}
		DbgPrint("IOCTL_IRPENUMFILE: Output buffer can hold %lu entries, trying to copy %lu entries\n",
			maxEntries, actualCount);
		DbgPrint("DATA_INFO:%u", sizeof(pDynamicData));
		// 释放动态分配的内存
		ExFreePoolWithTag(pDynamicData, 'DATA');
		ExFreePoolWithTag(safePath, 'PATH');

		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_IRPSETINFORMATIONFILE:
	{
		DbgPrint("Enter the IO IrpSetInformationFile\n");
		PUCHAR inputBuffer = (PUCHAR)pIrp->AssociatedIrp.SystemBuffer;
		ULONG inputLength = irps->Parameters.DeviceIoControl.InputBufferLength;

		NTSTATUS status = STATUS_SUCCESS;
		PFILE_OBJECT pFileObject = NULL;
		IO_STATUS_BLOCK iosb = { 0 };
		FILE_BASIC_INFORMATION fileBaseInfo = { 0 };

		// 输入缓冲区检查：8字节属性+至少2字节路径+2字节unicode终止符
		if (inputLength < 10) {
			DbgPrint("IrpSetInformationFile Failed: InputBuffer too small\n");
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		// 解析属性（取前8字节作为ULONG属性）
		ULONG fileAttributes = *(ULONG*)inputBuffer; // 实际只需要4字节
		PWCHAR filePath = (PWCHAR)(inputBuffer + 8); // 跳过8字节获取路径

		// 检查路径是否以空字符结尾
		ULONG pathBytes = inputLength - 8;
		if (pathBytes < 2 || filePath[(pathBytes / 2) - 1] != L'\0') {
			DbgPrint("IrpSetInformationFile Failed: Path not null-terminated\n");
			status = STATUS_INVALID_PARAMETER;
			break;
		}


		UNICODE_STRING FileName;
		RtlInitUnicodeString(&FileName, filePath);

		status = IrpCreateFile(&pFileObject, GENERIC_READ | GENERIC_WRITE, &FileName,
			&iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

		if (!NT_SUCCESS(status)) {
			DbgPrint("[EFCHKMD] IrpCreateFile Error[0x%X]\n", status);
			break;
		}

		RtlZeroMemory(&fileBaseInfo, sizeof(fileBaseInfo));
		fileBaseInfo.FileAttributes = fileAttributes;

		status = _IrpSetInformationFile(
			pFileObject,
			&iosb,
			&fileBaseInfo,
			sizeof(fileBaseInfo),
			FileBasicInformation);

		if (NT_SUCCESS(status)) {
			DbgPrint("[EFCHKMD] IrpSetInformationFile Successful\n");
		}
		else {
			DbgPrint("[EFCHKMD] IrpSetInformationFile Failed: 0x%X\n", status);
		}

		// 清理资源
		if (pFileObject) {
			ObDereferenceObject(pFileObject);
			pFileObject = NULL;
		}
		break;
	}
	case IOCTL_IRPRENAMEFILE:
	{
		DbgPrint("Enter the IO IrpRenameFile\n");
		PUCHAR inputBuffer = (PUCHAR)pIrp->AssociatedIrp.SystemBuffer;
		ULONG inputLength = irps->Parameters.DeviceIoControl.InputBufferLength;
		const ULONG REQUIRED_SIZE = 4096 + 4096;  // 8192 bytes

		// 验证输入缓冲区大小
		if (inputLength < REQUIRED_SIZE) {
			DbgPrint("[EFCHKMD] Buffer too small (%u < %u)\n", inputLength, REQUIRED_SIZE);
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		// 提取OldPath
		WCHAR* OldPath = (WCHAR*)inputBuffer;
		ULONG OldPathMaxChars = 4096 / sizeof(WCHAR);  // 4096个字符

		// 验证KeyPath是否以NULL结尾
		if (OldPath[OldPathMaxChars - 1] != L'\0') {
			// 确保在缓冲区边界添加终止符
			OldPath[OldPathMaxChars - 1] = L'\0';
			DbgPrint("[EFCHKMD] Warning: KeyPath not null-terminated, forced termination\n");
		}

		// 提取NewPath
		WCHAR* NewPath = (WCHAR*)(inputBuffer + 4096);
		ULONG NewPathMaxChars = 4096 / sizeof(WCHAR);

		if (NewPath[NewPathMaxChars - 1] != L'\0') {
			NewPath[NewPathMaxChars - 1] = L'\0';
			DbgPrint("[EFCHKMD] Warning: KeyName not null-terminated, forced termination\n");
		}

		UNICODE_STRING OldPathUs, NewPathUs;

		// 初始化KeyPath
		OldPathUs.Buffer = OldPath;
		OldPathUs.Length = (USHORT)(wcsnlen(OldPath, OldPathMaxChars) * sizeof(WCHAR));
		OldPathUs.MaximumLength = 4096;

		// 初始化KeyName
		NewPathUs.Buffer = NewPath;
		NewPathUs.Length = (USHORT)(wcsnlen(NewPath, NewPathMaxChars) * sizeof(WCHAR));
		NewPathUs.MaximumLength = 4096;

		DbgPrint("OldPath: %.*S", OldPathUs.Length / sizeof(WCHAR), OldPathUs.Buffer);
		DbgPrint("NewPath: %.*S", NewPathUs.Length / sizeof(WCHAR), NewPathUs.Buffer);

		status = IrpRenameFile(&OldPathUs, &NewPathUs);

		if (NT_SUCCESS(status)) {
			DbgPrint("[EFCHKMD] IrpRenameFile Successful\n");
		}
		else {
			DbgPrint("[EFCHKMD] IrpRenameFile Failed: 0x%X\n", status);
		}
		break;
	}
	case IOCTL_ZWWRITEFILE:
	{
		DbgPrint("Enter the IO ZwWriteFile\n");
		PUCHAR inputBuffer = (PUCHAR)pIrp->AssociatedIrp.SystemBuffer;
		ULONG inputLength = irps->Parameters.DeviceIoControl.InputBufferLength;

		// 输入缓冲区必须包含至少512字节路径 + 至少1字节数据
		if (inputLength < 513) {
			DbgPrint("WriteFile Failed: InputBuffer too small\n");
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		// 提取文件路径（前512字节）
		WCHAR* filePathBuffer = (WCHAR*)inputBuffer;
		ULONG pathMaxChars = 512 / sizeof(WCHAR); // 最多256个字符

		// 验证Unicode路径是否以NULL结尾
		BOOLEAN nullTerminated = FALSE;
		for (ULONG i = 0; i < pathMaxChars; i++) {
			if (filePathBuffer[i] == L'\0') {
				nullTerminated = TRUE;
				break;
			}
		}

		if (!nullTerminated) {
			DbgPrint("WriteFile Failed: File path not null-terminated in 512 bytes\n");
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		// 初始化UNICODE_STRING路径
		UNICODE_STRING targetFilePath;
		targetFilePath.Buffer = filePathBuffer;
		targetFilePath.Length = (USHORT)(wcslen(filePathBuffer) * sizeof(WCHAR));
		targetFilePath.MaximumLength = 512; // 最大512字节

		// 计算数据部分长度和起始位置
		ULONG dataLength = inputLength - 512;
		PUCHAR dataStart = inputBuffer + 512;

		// 分配安全内存复制用户数据
		PVOID safeBuffer = ExAllocatePoolWithTag(NonPagedPoolNx, dataLength, 'wfle');
		if (!safeBuffer) {
			DbgPrint("Memory allocation failed for data buffer\n");
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		// 复制用户数据到安全缓冲区
		RtlCopyMemory(safeBuffer, dataStart, dataLength);

		HANDLE hFile = NULL;
		IO_STATUS_BLOCK iosb = { 0 };
		OBJECT_ATTRIBUTES oa = { 0 };
		InitializeObjectAttributes(
			&oa,
			&targetFilePath,
			OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
			NULL,
			NULL
		);
		status = ZwCreateFile(&hFile, GENERIC_WRITE, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("ZwCreateFile Failed 0x%X\n", status);
			break;
		}
		status = ZwWriteFile(hFile, NULL, NULL, NULL, &iosb, safeBuffer, dataLength, NULL, NULL);
		// 释放安全缓冲区
		ExFreePool(safeBuffer);
		ZwClose(hFile);
		if (NT_SUCCESS(status)) {
			DbgPrint("[EFCHKMD] ZwWriteFile Successful\n");
		}
		else {
			DbgPrint("[EFCHKMD] ZwWriteFile Failed: 0x%X\n", status);
		}
		break;
	}
	case IOCTL_IRPREADFILE:
	{
		DbgPrint("Enter the IO IrpReadFile\n");

		IO_STATUS_BLOCK iosb = { 0 };
		OBJECT_ATTRIBUTES oa = { 0 };
		WCHAR* filePatch = (WCHAR*)pIrp->AssociatedIrp.SystemBuffer;
		UNICODE_STRING uniPath;
		ULONGLONG dataLength = 0;
		PFILE_OBJECT rfFileObject = NULL;

		//PIO_STACK_LOCATION irps = IoGetCurrentIrpStackLocation(pIrp);
		ULONG outputLength = irps->Parameters.DeviceIoControl.OutputBufferLength;

		RtlInitUnicodeString(&uniPath, filePatch);
		InitializeObjectAttributes(
			&oa,
			&uniPath,
			OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
			NULL,
			NULL
		);

		status = IrpGetFileSize(uniPath, &dataLength);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("IrpGetFileSize Failed: 0x%X\n", status);
			break;
		}

		if (dataLength == 0)
		{
			DbgPrint("Empty File\n");
			info = 0;
			status = STATUS_SUCCESS;
			break;
		}

		DbgPrint("File size: %u, Output buffer: %u\n", dataLength, outputLength);

		status = IrpCreateFile(
			&rfFileObject,
			FILE_READ_DATA | SYNCHRONIZE,
			&uniPath,
			&iosb,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ,
			FILE_OPEN,
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("IrpCreateFile Failed(READ ACCESS): 0x%X\n", status);
			status = IrpCreateFile(
				&rfFileObject,
				0,
				&uniPath,
				&iosb,
				NULL,
				FILE_ATTRIBUTE_NORMAL,
				FILE_SHARE_READ,
				FILE_OPEN,
				FILE_SYNCHRONOUS_IO_NONALERT | IO_IGNORE_SHARE_ACCESS_CHECK,
				NULL,
				0);
			if (!NT_SUCCESS(status))
			{
				DbgPrint("IrpCreateFile Failed(0 ACCESS): 0x%X\n", status);
				break;
			}
		}

		status = IrpReadFile(
			rfFileObject,
			&iosb,
			pIrp->AssociatedIrp.SystemBuffer,
			min(dataLength, outputLength),
			NULL);
		DbgPrint("IrpReadFile status: 0x%X, Information: %I64u\n", status, iosb.Information);
		ObDereferenceObject(rfFileObject);
		if (NT_SUCCESS(status))
		{
			info = (ULONG)iosb.Information;
			DbgPrint("Successfully read %u bytes\n", (ULONG)iosb.Information);

			if (iosb.Information > 0) {
				DbgPrint("Content: ");
				PUCHAR content = (PUCHAR)pIrp->AssociatedIrp.SystemBuffer;
				for (int i = 0; i < min(20, (ULONG)iosb.Information); i++) {
					DbgPrint("%c", (content[i] >= 0x20 && content[i] <= 0x7E) ? content[i] : '.');
				}
				DbgPrint("\n");
			}
		}
		else
		{
			DbgPrint("IrpReadFile Failed: 0x%X\n", status);
			info = 0;
		}

		break;
	}
	case IOCTL_IRPGETFILESIZE:
	{
		DbgPrint("Enter the IO IrpGetFileSize\n");

		WCHAR* filePatch = (WCHAR*)pIrp->AssociatedIrp.SystemBuffer;
		UNICODE_STRING uniPath;
		ULONGLONG dataLength = 0;
		ULONG outputLength = irps->Parameters.DeviceIoControl.OutputBufferLength;

		RtlInitUnicodeString(&uniPath, filePatch);

		status = IrpGetFileSize(uniPath, &dataLength);
		if (NT_SUCCESS(status))
		{
			DbgPrint("[EFCHKMD] IrpGetFileSize Successful, size:%I64u\n", dataLength);

			// 关键调试：检查实际写入的数据
			ULONGLONG* outputBuffer = (ULONGLONG*)pIrp->AssociatedIrp.SystemBuffer;
			DbgPrint("[EFCHKMD] Before copy - dataLength: %I64u, outputBuffer: 0x%p\n",
				dataLength, outputBuffer);

			// 确保正确复制数据
			*outputBuffer = dataLength;

			// 验证写入后的数据
			DbgPrint("[EFCHKMD] After copy - *outputBuffer: %I64u\n", *outputBuffer);

			info = sizeof(ULONGLONG);
			DbgPrint("[EFCHKMD] Set Information: %u\n", info);
		}
		else
		{
			DbgPrint("[EFCHKMD] IrpGetFileSize Failed : 0x%X\n", status);
			info = 0;
		}

		break;
	}
	case IOCTL_IRPREADDISK:
	{
		DbgPrint("Enter the IO ForceReadDisk\n");
		PUCHAR inputBuffer = (PUCHAR)pIrp->AssociatedIrp.SystemBuffer;
		ULONG inputLength = irps->Parameters.DeviceIoControl.InputBufferLength;

		PUCHAR outputBuffer = (PUCHAR)pIrp->AssociatedIrp.SystemBuffer;
		ULONG outputLength = irps->Parameters.DeviceIoControl.OutputBufferLength;

		if (inputLength < 16) { //8+8
			DbgPrint("ReadDisk Failed: InputBuffer too small\n");
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		LARGE_INTEGER startSector = *(PLARGE_INTEGER)inputBuffer;
		LARGE_INTEGER sectorCount = *(PLARGE_INTEGER)(inputBuffer + 8);
		ULONG dataLength = (ULONG)(sectorCount.QuadPart * 512);

		if (outputLength < dataLength) {
			DbgPrint("[EFCHKMD] IrpReadDisk Failed: OutputBuffer too small, need %lu bytes, got %lu bytes\n",
				dataLength, outputLength);
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		DbgPrint("[EFCHKMD] ReadDisk Params: StartSector=%lld, SectorCount=%lld, DataLen=%lu\n",
			startSector.QuadPart, sectorCount.QuadPart, dataLength);

		PVOID readBuffer = ExAllocatePoolWithTag(NonPagedPoolNx, dataLength, 'radd');
		if (!readBuffer) {
			DbgPrint("ExAllocatePoolWithTag Failed\n");
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		RtlZeroMemory(readBuffer, dataLength);

		status = IrpReadDiskEx(
			startSector,
			(ULONG)sectorCount.QuadPart,
			readBuffer
		);

		if (NT_SUCCESS(status)) {
			DbgPrint("[EFCHKMD] IrpReadDisk Successful\n");
			RtlCopyMemory(outputBuffer, readBuffer, dataLength);

			// 设置返回的数据长度
			info = dataLength;
		}
		else {
			DbgPrint("[EFCHKMD] IrpReadDisk Failed: 0x%X\n", status);
			info = 0;
		}

		// 释放缓冲区
		ExFreePool(readBuffer);
		break;
	}
	case IOCTL_FORCEREADDISKBYPASSDISKHOOK:
	{
		DbgPrint("Enter the IO ForceReadDisk\n");
		PUCHAR inputBuffer = (PUCHAR)pIrp->AssociatedIrp.SystemBuffer;
		ULONG inputLength = irps->Parameters.DeviceIoControl.InputBufferLength;

		PUCHAR outputBuffer = (PUCHAR)pIrp->AssociatedIrp.SystemBuffer;
		ULONG outputLength = irps->Parameters.DeviceIoControl.OutputBufferLength;

		if (inputLength < 16) { //8+8
			DbgPrint("ReadDisk Failed: InputBuffer too small\n");
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		LARGE_INTEGER startSector = *(PLARGE_INTEGER)inputBuffer;
		LARGE_INTEGER sectorCount = *(PLARGE_INTEGER)(inputBuffer + 8);
		ULONG dataLength = (ULONG)(sectorCount.QuadPart * 512);

		if (outputLength < dataLength) {
			DbgPrint("[EFCHKMD] IrpReadDisk Failed: OutputBuffer too small, need %lu bytes, got %lu bytes\n",
				dataLength, outputLength);
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		DbgPrint("[EFCHKMD] ReadDisk Params: StartSector=%lld, SectorCount=%lld, DataLen=%lu\n",
			startSector.QuadPart, sectorCount.QuadPart, dataLength);

		PVOID readBuffer = ExAllocatePoolWithTag(NonPagedPoolNx, dataLength, 'radd');
		if (!readBuffer) {
			DbgPrint("ExAllocatePoolWithTag Failed\n");
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		RtlZeroMemory(readBuffer, dataLength);

		if (EnableDiskFreeze)
		{
			status = ReadOriginalSectorEx(
				startSector,
				(ULONG)sectorCount.QuadPart,
				readBuffer
			);
		}
		else
		{
			status = IrpReadDiskEx(
				startSector,
				(ULONG)sectorCount.QuadPart,
				readBuffer
			);
		}

		if (NT_SUCCESS(status)) {
			DbgPrint("[EFCHKMD] IrpReadDisk Successful\n");
			RtlCopyMemory(outputBuffer, readBuffer, dataLength);

			// 设置返回的数据长度
			info = dataLength;
		}
		else {
			DbgPrint("[EFCHKMD] IrpReadDisk Failed: 0x%X\n", status);
			info = 0;
		}

		// 释放缓冲区
		ExFreePool(readBuffer);
		break;
	}
	case IOCTL_IRPGETFILEANDFOLDERQUANTITY:
	{
		DbgPrint("Enter the IO IrpGetFileAndFolderQuantity\n");

		WCHAR* filePatch = (WCHAR*)pIrp->AssociatedIrp.SystemBuffer;
		UNICODE_STRING uniPath;
		ULONG dataLength = 0;
		ULONG outputLength = irps->Parameters.DeviceIoControl.OutputBufferLength;

		RtlInitUnicodeString(&uniPath, filePatch);

		dataLength = Fs_GetFileAndFolderQuantity_UNICODE_Irp(&uniPath);
		if (dataLength != 0)
		{
			DbgPrint("[EFCHKMD] IrpGetFileAndFolderQuantity Successful, Quantity:%u\n", dataLength);

			ULONG* outputBuffer = (ULONG*)pIrp->AssociatedIrp.SystemBuffer;
			*outputBuffer = dataLength;
			info = sizeof(ULONG);
		}
		else
		{
			DbgPrint("[EFCHKMD] Quantity is 0 or Failed\n");
			info = 0;
		}
		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_POSIXFORCEDELETEFILE:
	{
		DbgPrint("Enter the IO POSIXForceDeleteFile\n");
		WCHAR* filePatch = (WCHAR*)pIrp->AssociatedIrp.SystemBuffer;
		UNICODE_STRING uniPath;
		RtlInitUnicodeString(&uniPath, filePatch);
		status = POSIXForceDeleteFile(uniPath);
		if (NT_SUCCESS(status))
		{
			DbgPrint("[EFCHKMD] POSIXForceDeleteFile Successful\n");
		}
		else
		{
			DbgPrint("[EFCHKMD] POSIXForceDeleteFile Failed\n");
		}
		break;
	}
	case IOCTL_KEBUGCHECK:
	{
		DbgPrint("Enter the IO KeBugCheck\n");
		ULONG code = *(PLONG)(pIrp->AssociatedIrp.SystemBuffer);
		KeBugCheckEx(code, 0x1, NULL, NULL, NULL);
		break;
	}
	case IOCTL_SYSTEMBSOD:
	{
		DbgPrint("Enter the IO BSOD!!!\n");
		SYSTEMBSOD();
	}
	case IOCTL_HALPOWERCONTROL:
	{
		DbgPrint("Enter the IO HalPowerControl!!!\n");
		LONG inputdata = *(PLONG)pIrp->AssociatedIrp.SystemBuffer;
		switch (inputdata)
		{
		case 0:
		{
			HalReturnToFirmware(HalHaltRoutine);
			break;
		}
		case 1:
		{
			HalReturnToFirmware(HalPowerDownRoutine);
			break;
		}
		case 2:
		{
			HalReturnToFirmware(HalRestartRoutine);
			break;
		}
		case 3:
		{
			HalReturnToFirmware(HalRebootRoutine);
			break;
		}
		case 4:
		{
			HalReturnToFirmware(HalInteractiveModeRoutine);
			break;
		}
		}
		status = STATUS_DEVICE_PAPER_EMPTY;
		break;
	}
	case IOCTL_HOOK_QUERYSTATUS:
	{
		LONG inputdata = *(PLONG)pIrp->AssociatedIrp.SystemBuffer;

		ULONG outputLength = irps->Parameters.DeviceIoControl.OutputBufferLength;
		BOOL userBoolValue = FALSE;
		if (outputLength < sizeof(BOOL))
		{
			DbgPrint("HOOK_QUERYSTATUS: Buffer too small");
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		switch (inputdata)
		{
		case 1: //Disable BSOD
		{
			userBoolValue = (KeBugCheckExIsHooked != FALSE) ? TRUE : FALSE;
			break;
		}
		case 2: //Disable LoadDriver
		{
			userBoolValue = (DisableLoadDriver_ != FALSE) ? TRUE : FALSE;
			break;
		}
		case 3: //Disable CreateProcess
		{
			userBoolValue = (DisableCreateProcess_ != FALSE) ? TRUE : FALSE;
			break;
		}
		case 4: //Disable RegisterControl
		{
			userBoolValue = (DisableRegisterControl_ != FALSE) ? TRUE : FALSE;
			break;
		}
		case 5: // Disk Freeze
		{
			userBoolValue = (EnableDiskFreeze != FALSE) ? TRUE : FALSE;
			break;
		}
		default:
			DbgPrint("Unknown Hook Query Request\n");
			break;
		}
		RtlCopyMemory(pIrp->AssociatedIrp.SystemBuffer,
			&userBoolValue,
			sizeof(BOOL));
		info = sizeof(BOOL);
		break;
	}
	case IOCTL_SENDDATA_TO_PORT:
	{
		DbgPrint("Enter the IO SendDataToPort\n");

		PUCHAR inputBuffer = (PUCHAR)pIrp->AssociatedIrp.SystemBuffer;
		ULONG inputBufferLength = irps->Parameters.DeviceIoControl.InputBufferLength;

		const SIZE_T minRequiredSize = sizeof(USHORT) * 2 + 1;

		if (inputBufferLength < minRequiredSize)
		{
			DbgPrint("Error: Input buffer too small. Need at least %zu bytes, got %lu bytes\n",
				minRequiredSize, inputBufferLength);
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		USHORT portNumber = *(USHORT*)inputBuffer;
		USHORT type = *(USHORT*)(inputBuffer + sizeof(USHORT));
		PUCHAR dataStart = inputBuffer + sizeof(USHORT) * 2;
		ULONG dataLength = inputBufferLength - sizeof(USHORT) * 2;

		DbgPrint("Port: 0x%04X, Type: %u, Data length: %lu bytes\n",
			portNumber, type, dataLength);

		if (type != 1 && type != 2 && type != 4)
		{
			DbgPrint("Error: Invalid Type %u. Must be 1, 2, or 4\n", type);
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		if (dataLength < type)
		{
			DbgPrint("Error: Data length %lu is less than required type size %u\n",
				dataLength, type);
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		switch (type)
		{
		case 1:  // 1byte(UCHAR)
		{
			UCHAR data = *dataStart;
			__outbyte(portNumber, data);
			DbgPrint("Wrote 1 byte: 0x%02X to port 0x%04X\n", data, portNumber);
			break;
		}

		case 2:  // 2bytes(USHORT)
		{
			if (portNumber % 2 != 0)
			{
				DbgPrint("Warning: Port 0x%04X may not be word-aligned\n", portNumber);
			}
			USHORT data;
			RtlCopyMemory(&data, dataStart, sizeof(USHORT));
			__outword(portNumber, data);
			DbgPrint("Wrote 2 bytes: 0x%04X to port 0x%04X\n", data, portNumber);
			break;
		}

		case 4:  // 4bytes(ULONG)
		{
			if (portNumber % 4 != 0)
			{
				DbgPrint("Warning: Port 0x%04X may not be dword-aligned\n", portNumber);
			}
			ULONG data;
			RtlCopyMemory(&data, dataStart, sizeof(ULONG));
			__outdword(portNumber, data);
			DbgPrint("Wrote 4 bytes: 0x%08X to port 0x%04X\n", data, portNumber);
			break;
		}
		}

		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_READDATA_IN_PORT:
	{
		DbgPrint("Enter the IO ReadDataInPort\n");
		if (irps->Parameters.DeviceIoControl.InputBufferLength < sizeof(USHORT) * 2)
		{
			DbgPrint("Error: Input buffer too small. Need at least %zu bytes, got %lu bytes\n",
				sizeof(USHORT) * 2, irps->Parameters.DeviceIoControl.InputBufferLength);
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		USHORT portNumber = *(USHORT*)pIrp->AssociatedIrp.SystemBuffer;
		USHORT type = *(USHORT*)((PUCHAR)pIrp->AssociatedIrp.SystemBuffer + sizeof(USHORT));

		DbgPrint("Reading from port 0x%04X, type: %u\n", portNumber, type);
		if (type != 1 && type != 2 && type != 4)
		{
			DbgPrint("Error: Invalid type %u. Must be 1, 2, or 4\n", type);
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		if (irps->Parameters.DeviceIoControl.OutputBufferLength < type)
		{
			DbgPrint("Error: Output buffer too small. Need at least %u bytes, got %lu bytes\n",
				type, irps->Parameters.DeviceIoControl.OutputBufferLength);
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		PUCHAR outputBuffer = (PUCHAR)pIrp->AssociatedIrp.SystemBuffer;

		switch (type)
		{
		case 1:  // 1byte(UCHAR)
		{
			UCHAR data = __inbyte(portNumber);
			*outputBuffer = data;
			info = 1;
			DbgPrint("Read 1 byte: 0x%02X from port 0x%04X\n", data, portNumber);
			break;
		}

		case 2:  // 2bytes(USHORT)
		{
			if (portNumber % 2 != 0)
			{
				DbgPrint("Warning: Port 0x%04X may not be word-aligned\n", portNumber);
			}

			USHORT data = __inword(portNumber);
			RtlCopyMemory(outputBuffer, &data, sizeof(USHORT));
			info = 2;
			DbgPrint("Read 2 bytes: 0x%04X from port 0x%04X\n", data, portNumber);
			break;
		}

		case 4:  // 4bytes(ULONG)
		{
			if (portNumber % 4 != 0)
			{
				DbgPrint("Warning: Port 0x%04X may not be dword-aligned\n", portNumber);
			}

			ULONG data = __indword(portNumber);
			RtlCopyMemory(outputBuffer, &data, sizeof(ULONG));
			info = 4;
			DbgPrint("Read 4 bytes: 0x%08X from port 0x%04X\n", data, portNumber);
			break;
		}
		}

		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_ENUMDRIVERS:
	{
		DbgPrint("Enter the IO IOCTL_ENUMDRIVERS\n");

		// 获取输出缓冲区和大小
		PLite_Driver_Info pDriverInfo = (PLite_Driver_Info)pIrp->AssociatedIrp.SystemBuffer;
		ULONG outputLength = irps->Parameters.DeviceIoControl.OutputBufferLength;

		DbgPrint("IOCTL_ENUMDRIVERS: sizeof(Lite_Driver_Info) = %lu bytes\n", sizeof(Lite_Driver_Info));
		DbgPrint("IOCTL_ENUMDRIVERS: Output buffer size = %lu bytes, can hold %lu entries\n",
			outputLength, outputLength / sizeof(Lite_Driver_Info));

		// 先获取驱动总数
		ULONG totalDrivers = 0;
		PLIST_ENTRY pListEntry = &PsLoadedModuleList;

		__try {
			PLIST_ENTRY firstEntry = pListEntry->Flink;
			while (firstEntry != pListEntry) {
				totalDrivers++;
				firstEntry = firstEntry->Flink;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrint("IOCTL_ENUMDRIVERS: Exception while counting drivers\n");
			totalDrivers = 0;
		}

		DbgPrint("IOCTL_ENUMDRIVERS: Found %lu drivers total\n", totalDrivers);

		if (totalDrivers == 0) {
			DbgPrint("IOCTL_ENUMDRIVERS: No drivers found\n");
			status = STATUS_NO_MORE_FILES;
			break;
		}

		// 动态分配足够的内存来存储所有驱动信息
		ULONG dataSize = totalDrivers * sizeof(Lite_Driver_Info);
		PLite_Driver_Info pDynamicData = (PLite_Driver_Info)ExAllocatePoolWithTag(NonPagedPool, dataSize, 'DRIV');
		if (pDynamicData == NULL) {
			DbgPrint("IOCTL_ENUMDRIVERS: Dynamic data allocation failed\n");
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		// 清零动态数组
		RtlZeroMemory(pDynamicData, dataSize);

		// 枚举所有驱动到动态数组中
		ULONG actualCount = EnumDriver(pDynamicData, dataSize);

		DbgPrint("IOCTL_ENUMDRIVERS: Actually enumerated %lu drivers\n", actualCount);

		// 计算可以复制到输出缓冲区的最大条目数
		ULONG maxEntries = 0;
		PLite_Driver_Info pOutputBuffer = NULL;

		if (outputLength >= sizeof(Lite_Driver_Info) && pDriverInfo != NULL) {
			maxEntries = outputLength / sizeof(Lite_Driver_Info);
			pOutputBuffer = (PLite_Driver_Info)pIrp->AssociatedIrp.SystemBuffer;

			// 清零输出缓冲区
			RtlZeroMemory(pOutputBuffer, outputLength);

			// 复制数据到输出缓冲区
			ULONG entriesToCopy = min(actualCount, maxEntries);
			ULONG copySize = entriesToCopy * sizeof(Lite_Driver_Info);

			if (copySize > 0 && copySize <= outputLength) {
				RtlCopyMemory(pOutputBuffer, pDynamicData, copySize);
				info = copySize;
				DbgPrint("IOCTL_ENUMDRIVERS: Copied %lu entries to output buffer\n", entriesToCopy);
			}
		}
		else {
			DbgPrint("IOCTL_ENUMDRIVERS: Output buffer too small or NULL, no data copied\n");
		}

		DbgPrint("IOCTL_ENUMDRIVERS: Output buffer can hold %lu entries, trying to copy %lu entries\n",
			maxEntries, actualCount);

		// 释放动态分配的内存
		ExFreePoolWithTag(pDynamicData, 'DRIV');

		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_ENUMDEVICES:
	{
		DbgPrint("Enter the IO IOCTL_ENUMDEVICES\n");

		// 先获取设备总数（不是驱动总数！）
		ULONG estimatedDeviceCount = 512; // 预分配512个设备

		// 使用正确的结构体大小！
		ULONG dataSize = estimatedDeviceCount * sizeof(Lite_Driver_Info2);
		PLite_Driver_Info2 pDynamicData = (PLite_Driver_Info2)ExAllocatePoolWithTag(
			NonPagedPoolNx, dataSize, 'DRIV');

		if (pDynamicData == NULL) {
			DbgPrint("IOCTL_ENUMDEVICES: Memory allocation failed\n");
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		// 清零内存
		RtlZeroMemory(pDynamicData, dataSize);

		// 枚举设备
		ULONG actualCount = EnumAllDevicePath(pDynamicData, estimatedDeviceCount);

		DbgPrint("IOCTL_ENUMDEVICES: Enumerated %lu devices\n", actualCount);

		// 现在处理用户缓冲区
		if (pIrp->AssociatedIrp.SystemBuffer &&
			irps->Parameters.DeviceIoControl.OutputBufferLength > 0) {

			// 计算可复制的条目数
			ULONG maxEntries = irps->Parameters.DeviceIoControl.OutputBufferLength /
				sizeof(Lite_Driver_Info2);
			ULONG entriesToCopy = min(actualCount, maxEntries);

			if (entriesToCopy > 0) {
				ULONG copySize = entriesToCopy * sizeof(Lite_Driver_Info2);

				// 安全复制
				__try {
					RtlCopyMemory(pIrp->AssociatedIrp.SystemBuffer,
						pDynamicData,
						copySize);
					info = copySize; // 返回复制的字节数
					DbgPrint("Copied %lu entries (%lu bytes)\n", entriesToCopy, copySize);
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					DbgPrint("Copy failed with exception: 0x%08X\n", GetExceptionCode());
					info = 0;
					status = STATUS_UNSUCCESSFUL;
				}
			}
			else {
				DbgPrint("No entries to copy or buffer too small\n");
				info = 0;
			}
		}

		// 释放内存
		ExFreePoolWithTag(pDynamicData, 'DRIV');

		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_ENUMDRIVERSPATH:
	{
		DbgPrint("Enter the IO IOCTL_ENUMDEVICES\n");

		// 先获取设备总数（不是驱动总数！）
		ULONG estimatedDeviceCount = 512; // 预分配512个设备

		// 使用正确的结构体大小！
		ULONG dataSize = estimatedDeviceCount * sizeof(Lite_Driver_Info2);
		PLite_Driver_Info2 pDynamicData = (PLite_Driver_Info2)ExAllocatePoolWithTag(
			NonPagedPoolNx, dataSize, 'DRIV');

		if (pDynamicData == NULL) {
			DbgPrint("IOCTL_ENUMDEVICES: Memory allocation failed\n");
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		// 清零内存
		RtlZeroMemory(pDynamicData, dataSize);

		// 枚举设备
		ULONG actualCount = EnumAllDriverPath(pDynamicData, estimatedDeviceCount);

		DbgPrint("IOCTL_ENUMDEVICES: Enumerated %lu devices\n", actualCount);

		// 现在处理用户缓冲区
		if (pIrp->AssociatedIrp.SystemBuffer &&
			irps->Parameters.DeviceIoControl.OutputBufferLength > 0) {

			// 计算可复制的条目数
			ULONG maxEntries = irps->Parameters.DeviceIoControl.OutputBufferLength /
				sizeof(Lite_Driver_Info2);
			ULONG entriesToCopy = min(actualCount, maxEntries);

			if (entriesToCopy > 0) {
				ULONG copySize = entriesToCopy * sizeof(Lite_Driver_Info2);

				// 安全复制
				__try {
					RtlCopyMemory(pIrp->AssociatedIrp.SystemBuffer,
						pDynamicData,
						copySize);
					info = copySize; // 返回复制的字节数
					DbgPrint("Copied %lu entries (%lu bytes)\n", entriesToCopy, copySize);
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					DbgPrint("Copy failed with exception: 0x%08X\n", GetExceptionCode());
					info = 0;
					status = STATUS_UNSUCCESSFUL;
				}
			}
			else {
				DbgPrint("No entries to copy or buffer too small\n");
				info = 0;
			}
		}

		// 释放内存
		ExFreePoolWithTag(pDynamicData, 'DRIV');

		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_EDISKPROTECT_SETPROTECTSECTORS:
	{
		PULONGLONG inputBuffer = (PULONGLONG)pIrp->AssociatedIrp.SystemBuffer;
		if (pIrp->AssociatedIrp.SystemBuffer == NULL ||
			irps->Parameters.DeviceIoControl.InputBufferLength < 16)
		{
			DbgPrint("[EFCHKMD] Invalid inputbuffer\n");
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		ULONGLONG startsector = inputBuffer[0];
		ULONGLONG endsector = inputBuffer[1];
		
		break;
	}
	case IOCTL_BUILDTEST:
	{
		//To_NtDeviceIoControlFile();
	}
	default:
		DbgPrint("[EFCHKMD] Unknown CODE!\n");
		status = STATUS_UNSUCCESSFUL;
		break;
	}

	// I/O请求处理完毕
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = info;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
InvalidPassword:
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS DispatchCreate(PDEVICE_OBJECT pDriverObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDriverObj);
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	PEPROCESS CurrentProc = PsGetCurrentProcess();
	PUCHAR filename = PsGetProcessImageFileName(CurrentProc);
	for (int i = 0; i < 20 && filename[i]; i++)
		DbgPrint("%02X ", filename[i]);
	if (_stricmp((const char*)filename, "EDiskFreezeS") == 0 ||
		_stricmp((const char*)filename, "EDiskFreezeS.exe") == 0 ||
		_stricmp((const char*)filename, "EDiskFreezeS.e") == 0)
	{
		DbgPrint("[DispatchCreate] Allowed: %s\n", filename);
	}
	else if (_stricmp((const char*)filename, "EDiskFreezeU") == 0 ||
		_stricmp((const char*)filename, "EDiskFreezeU.exe") == 0 ||
		_stricmp((const char*)filename, "EDiskFreezeU.e") == 0)
	{
		DbgPrint("[DispatchCreate] Allowed: %s\n", filename);
	}
	else
	{
		HANDLE pid = PsGetProcessId(CurrentProc);
		if (!Hook_IsProcessProtected(pid))
		{
			DbgPrint("[DispatchCreate] Ban Create Device (PID: %d, Name: %s)\n", pid, filename);
			pIrp->IoStatus.Status = STATUS_ACCESS_DENIED;
			IoCompleteRequest(pIrp, IO_NO_INCREMENT);
			return pIrp->IoStatus.Status;
		}
		DbgPrint("[DispatchCreate] Allowed protected process: %s\n", filename);
	}

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS DispatchClose(PDEVICE_OBJECT pDriverObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDriverObj);
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT driver) {
	// DriverUnload

	DbgPrint("Driver Unloading\n");
	if (!CanUnload)
	{
		DbgPrint("Cant Unload!");
		KeBugCheckEx(0xC0EFC001, -1, -1, -1, -1);
		return;
	}
	LARGE_INTEGER waitTime;
	waitTime.QuadPart = -1000 * 1000 * 10;
	KeDelayExecutionThread(KernelMode, FALSE, &waitTime);
	if (g_DiskProtectWorkItem) {
		IoFreeWorkItem(g_DiskProtectWorkItem);
		g_DiskProtectWorkItem = NULL;
	}
	DiskHook_Cleanup_Major();
	waitTime.QuadPart = -500 * 1000 * 10;
	KeDelayExecutionThread(KernelMode, FALSE, &waitTime);

	if (g_RegistrationHandle) {
		ObUnRegisterCallbacks(g_RegistrationHandle);
		g_RegistrationHandle = NULL;
		waitTime.QuadPart = -1000 * 1000 * 10;
		KeDelayExecutionThread(KernelMode, FALSE, &waitTime);
	}
	UNICODE_STRING symLinkName;
	RtlInitUnicodeString(&symLinkName, DOS_DEVICE_NAME);
	IoDeleteSymbolicLink(&symLinkName);
	waitTime.QuadPart = -1000 * 1000 * 10;
	KeDelayExecutionThread(KernelMode, FALSE, &waitTime);
	if (driver->DeviceObject) {
		IoDeleteDevice(driver->DeviceObject);
	}
	DbgPrint("Driver Unload\n");

}

EXTERN_C NTSTATUS DriverEntryMain(PDRIVER_OBJECT driver, PUNICODE_STRING reg_path) {
	ntoskrnl_PLDR = (PLDR_DATA_TABLE_ENTRY)PsLoadedModuleList.Flink;
	DbgPrint("EFCH Kernel Disk Driver\n");
	DbgPrint("[EFCHKMD] By RanShaoEFCH\n");
	DbgPrint("[EFCHKMD] Build 230\n");
	DbgPrint("[EFCHKMD] Driver Entry\n");
	
	NTSTATUS status;
	UNICODE_STRING ustrLinkName = { 0 };
	UNICODE_STRING ustrDevName = { 0 };
	UNICODE_STRING TempUnicode = { 0 };
	RTL_OSVERSIONINFOW osInfo = { 0 };
	osInfo.dwOSVersionInfoSize = sizeof(osInfo);
	// 注册驱动卸载函数
	driver->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	driver->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
	driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIoctl;  // 所有设备的 IOCTL 先到这里
	//driver->MajorFunction[IRP_MJ_WRITE] = DiskHook_DispatchWrite;
	//driver->MajorFunction[IRP_MJ_READ] = DiskHook_DispatchPassThrough;
	for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
		if (driver->MajorFunction[i] == NULL) {
			//driver->MajorFunction[i] = DiskHook_DispatchPassThrough;
		}
	}
	
	driver->DriverUnload = DriverUnload;
	PLDR_DATA ldr = (PLDR_DATA)driver->DriverSection;
	if (ldr) {
		ldr->Flags |= 0x20;
	}
	status = RtlGetVersion(&osInfo);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Get System Version Failed: 0x%X\n", status);
		return status;
	}

	switch (osInfo.dwBuildNumber) // Windows x64 Offset, Update on 2026.7.18
	{
	case 26300: // Windows 11 26H2
		Offset_hp = 0x1d8;
		ProtectionOffset = 0x5fa;
		BreakOnTerminationOffset = 0x1f4;
		UniqueProcessIdOffset = 0x1d0;
		Flags2Offset = 0x1f0;
		FlagsOffset = 0x1f4;
		TokenOffset = 0x248;
		PEBOffset = 0x2e0;
		ThreadListHandOffset = 0x370;
		ET_StartAddressOffset = 0x4e0;
		ET_ThreadListEntryOffset = 0x578;
		break;
	case 26200: // Windows 11 25H2
		Offset_hp = 0x1d8;
		ProtectionOffset = 0x5fa;
		BreakOnTerminationOffset = 0x1f4;
		UniqueProcessIdOffset = 0x1d0;
		Flags2Offset = 0x1f0;
		FlagsOffset = 0x1f4;
		TokenOffset = 0x248;
		PEBOffset = 0x2e0;
		ThreadListHandOffset = 0x370;
		ET_StartAddressOffset = 0x4e0;
		ET_ThreadListEntryOffset = 0x578;
		break;
	case 26100: // Windows 11 24H2 & Server 2025
		Offset_hp = 0x1d8;
		ProtectionOffset = 0x5fa;
		BreakOnTerminationOffset = 0x1f4;
		UniqueProcessIdOffset = 0x1d0;
		Flags2Offset = 0x1f0;
		FlagsOffset = 0x1f4;
		TokenOffset = 0x248;
		PEBOffset = 0x2e0;
		ThreadListHandOffset = 0x370;
		ET_StartAddressOffset = 0x4e0;
		ET_ThreadListEntryOffset = 0x578;
		break;
	case 22631: // Windows 11 23H2
		Offset_hp = 0x448;
		ProtectionOffset = 0x87a;
		BreakOnTerminationOffset = 0x464;
		UniqueProcessIdOffset = 0x440;
		Flags2Offset = 0x460;
		FlagsOffset = 0x464;
		TokenOffset = 0x4b8;
		PEBOffset = 0x550;
		ThreadListHandOffset = 0x5e0;
		ET_StartAddressOffset = 0x4a0;
		ET_ThreadListEntryOffset = 0x538;
		break;
	case 22621: // Windows 11 22H2
		Offset_hp = 0x448;
		ProtectionOffset = 0x87a;
		BreakOnTerminationOffset = 0x464;
		UniqueProcessIdOffset = 0x440;
		Flags2Offset = 0x460;
		FlagsOffset = 0x464;
		TokenOffset = 0x4b8;
		PEBOffset = 0x550;
		ThreadListHandOffset = 0x5e0;
		ET_StartAddressOffset = 0x4a0;
		ET_ThreadListEntryOffset = 0x538;
		break;
	case 22000: // Windows 11 21H2 or Insider Preview
		Offset_hp = 0x448;
		ProtectionOffset = 0x87a;
		BreakOnTerminationOffset = 0x464;
		UniqueProcessIdOffset = 0x440;
		Flags2Offset = 0x460;
		FlagsOffset = 0x464;
		TokenOffset = 0x4b8;
		PEBOffset = 0x550;
		ThreadListHandOffset = 0x5e0;
		ET_StartAddressOffset = 0x4a0;
		ET_ThreadListEntryOffset = 0x538;
		break;
	case 19045: // Windows 10 22H2
		Offset_hp = 0x448;
		ProtectionOffset = 0x87a;
		BreakOnTerminationOffset = 0x464;
		UniqueProcessIdOffset = 0x440;
		Flags2Offset = 0x460;
		FlagsOffset = 0x464;
		TokenOffset = 0x4b8;
		PEBOffset = 0x550;
		ThreadListHandOffset = 0x5e0;
		ET_StartAddressOffset = 0x450;
		ET_ThreadListEntryOffset = 0x4e8;
		break;
	case 19044: // Windows 10 21H2
		Offset_hp = 0x448;
		ProtectionOffset = 0x87a;
		BreakOnTerminationOffset = 0x464;
		UniqueProcessIdOffset = 0x440;
		Flags2Offset = 0x460;
		FlagsOffset = 0x464;
		TokenOffset = 0x4b8;
		PEBOffset = 0x550;
		ThreadListHandOffset = 0x5e0;
		ET_StartAddressOffset = 0x450;
		ET_ThreadListEntryOffset = 0x4e8;
		break;
	case 19043: // Windows 10 21H1
		Offset_hp = 0x448;
		ProtectionOffset = 0x87a;
		BreakOnTerminationOffset = 0x464;
		UniqueProcessIdOffset = 0x440;
		Flags2Offset = 0x460;
		FlagsOffset = 0x464;
		TokenOffset = 0x4b8;
		PEBOffset = 0x550;
		ThreadListHandOffset = 0x5e0;
		ET_StartAddressOffset = 0x450;
		ET_ThreadListEntryOffset = 0x4e8;
		break;
	case 19042: // Windows 10 20H2
		Offset_hp = 0x448;
		ProtectionOffset = 0x87a;
		BreakOnTerminationOffset = 0x464;
		UniqueProcessIdOffset = 0x440;
		Flags2Offset = 0x460;
		FlagsOffset = 0x464;
		TokenOffset = 0x4b8;
		PEBOffset = 0x550;
		ThreadListHandOffset = 0x5e0;
		ET_StartAddressOffset = 0x450;
		ET_ThreadListEntryOffset = 0x4e8;
		break;
	case 19041: // Windows 10 2004
		Offset_hp = 0x448; //ActiveProcessLinks
		ProtectionOffset = 0x87a;
		BreakOnTerminationOffset = 0x464;
		UniqueProcessIdOffset = 0x440;
		Flags2Offset = 0x460;
		FlagsOffset = 0x464;
		TokenOffset = 0x4b8;
		PEBOffset = 0x550;
		ThreadListHandOffset = 0x5e0;
		ET_StartAddressOffset = 0x450;
		ET_ThreadListEntryOffset = 0x4e8;
		break;
	case 18362: // Windows 10 1903 or 1909
		Offset_hp = 0x2f0;
		ProtectionOffset = 0x6fa;
		BreakOnTerminationOffset = 0x30c;
		UniqueProcessIdOffset = 0x2e8;
		Flags2Offset = 0x308;
		FlagsOffset = 0x30c;
		TokenOffset = 0x360;
		PEBOffset = 0x3f8;
		ThreadListHandOffset = 0x488;
		ET_StartAddressOffset = 0x620;
		ET_ThreadListEntryOffset = 0x6b8;
		break;
	case 17763: // Windows 10 1809 & Server 2019
		Offset_hp = 0x2e8;
		ProtectionOffset = 0x6ca;
		BreakOnTerminationOffset = 0x304;
		UniqueProcessIdOffset = 0x2e0;
		Flags2Offset = 0x300;
		FlagsOffset = 0x304;
		TokenOffset = 0x358;
		PEBOffset = 0x3f8;
		ThreadListHandOffset = 0x488;
		ET_StartAddressOffset = 0x610;
		ET_ThreadListEntryOffset = 0x6a8;
		break;
	case 17134: // Windows 10 1803
		Offset_hp = 0x2e8;
		ProtectionOffset = 0x6ca;
		BreakOnTerminationOffset = 0x304;
		UniqueProcessIdOffset = 0x2e0;
		Flags2Offset = 0x300;
		FlagsOffset = 0x304;
		TokenOffset = 0x358;
		PEBOffset = 0x3f8;
		ThreadListHandOffset = 0x488;
		ET_StartAddressOffset = 0x610;
		ET_ThreadListEntryOffset = 0x6a8;
		break;
	case 16299: // Windows 10 1709
		Offset_hp = 0x2e8;
		ProtectionOffset = 0x6ca;
		BreakOnTerminationOffset = 0x304;
		UniqueProcessIdOffset = 0x2e0;
		Flags2Offset = 0x300;
		FlagsOffset = 0x304;
		TokenOffset = 0x358;
		PEBOffset = 0x3f8;
		ThreadListHandOffset = 0x488;
		ET_StartAddressOffset = 0x610;
		ET_ThreadListEntryOffset = 0x6a8;
		break;
	case 15063: // Windows 10 1703
		Offset_hp = 0x2e8;
		ProtectionOffset = 0x6ca;
		BreakOnTerminationOffset = 0x304;
		UniqueProcessIdOffset = 0x2e0;
		Flags2Offset = 0x300;
		FlagsOffset = 0x304;
		TokenOffset = 0x358;
		PEBOffset = 0x3f8;
		ThreadListHandOffset = 0x488;
		ET_StartAddressOffset = 0x610;
		ET_ThreadListEntryOffset = 0x6a0;
		break;
	case 14393: // Windows 10 1607 & Server 2016
		Offset_hp = 0x2f0;
		ProtectionOffset = 0x6c2;
		BreakOnTerminationOffset = 0x304;
		UniqueProcessIdOffset = 0x2e8;
		Flags2Offset = 0x300;
		FlagsOffset = 0x304;
		TokenOffset = 0x358;
		PEBOffset = 0x3f8;
		ThreadListHandOffset = 0x488;
		ET_StartAddressOffset = 0x608;
		ET_ThreadListEntryOffset = 0x698;
		break;
	case 10586: // Windows 10 1511
		Offset_hp = 0x2f0;
		ProtectionOffset = 0x6b2;
		BreakOnTerminationOffset = 0x304;
		UniqueProcessIdOffset = 0x2e8;
		Flags2Offset = 0x300;
		FlagsOffset = 0x304;
		TokenOffset = 0x358;
		PEBOffset = 0x3f8;
		ThreadListHandOffset = 0x488;
		ET_StartAddressOffset = 0x600;
		ET_ThreadListEntryOffset = 0x690;
		break;
	case 10240: // Windows 10 1507
		Offset_hp = 0x2f0;
		ProtectionOffset = 0x6aa;
		BreakOnTerminationOffset = 0x304;
		UniqueProcessIdOffset = 0x2e8;
		Flags2Offset = 0x300;
		FlagsOffset = 0x304;
		TokenOffset = 0x358;
		PEBOffset = 0x3f8;
		ThreadListHandOffset = 0x480;
		ET_StartAddressOffset = 0x600;
		ET_ThreadListEntryOffset = 0x690;
		break;
	default:
		DbgPrint("[EFCHKMD] Your OS is not support! Offset warning!\n");
		break;
	}
	RtlInitUnicodeString(&ustrDevName, DEVICE_NAME);
	status = IoCreateDevice(driver, 0, &ustrDevName, FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("Create Device Faild!\n");
		return STATUS_UNSUCCESSFUL;
	}
	g_ControlDeviceObject = deviceObject;
	ReadRegistryPassword();
	if (!DontFreezeDisk())
	{
		EnableDiskFreeze = TRUE;
		g_DiskProtectWorkItem = IoAllocateWorkItem(deviceObject);
		if (!g_DiskProtectWorkItem) {
			DbgPrint("Init DiskHook Failed (Item)!\n");
			return STATUS_UNSUCCESSFUL;
		}
		status = DiskHook_Initialize(DeviceIoctl);
		if (!NT_SUCCESS(status)) {
			DbgPrint("Init DiskHook Failed (Init)!\n");
			return STATUS_UNSUCCESSFUL;
		}
	}
	RtlInitUnicodeString(&ustrLinkName, DOS_DEVICE_NAME);
	status = IoCreateSymbolicLink(&ustrLinkName, &ustrDevName);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("Create SymLink Faild!\n");
		IoDeleteDevice(deviceObject);
		return STATUS_UNSUCCESSFUL;
	}

	ExInitializeFastMutex(&g_ProtectLock);
	status = InitProcessProtection();
	if (!NT_SUCCESS(status)) {
		DbgPrint("ObRegisterCallbacks failed: 0x%X\n", status);
	}
	DbgPrintEx(0, 0, "[EFCHKMD] INIT:Done!\n");
	return STATUS_SUCCESS;
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING reg_path) {
	NTSTATUS status;
	status = DriverEntryMain(driver,reg_path);
	if (!NT_SUCCESS(status))
	{
		KeBugCheckEx(0xC0EFC002, (ULONG_PTR)driver, status, -1, -1);
	}
	return status;
}