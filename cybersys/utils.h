#ifndef __UTILS123__
#define __UTILS123__


//////////////////////////////////////////////////////////////////////////

#define Windows_2K	2000
#define Windows_XP	2001
#define Windows_2k3	2003
#define Windows_Vista	2004
#define Windows_7	2005
//////////////////////////////////////////////////////////////////////////

typedef struct __WorkItemContext__
{
	PIO_WORKITEM	pWorkItem;
	PVOID			pBuffer;
	ULONG			uBufferLen;

}WorkItemContext, *PWorkItemContext;


typedef struct _DRIVER_INFO 
{
	ULONG   Unknown1;
	PVOID	BaseAddress;
	ULONG	Size;
	ULONG   Unknown3;
	ULONG	Index;
	ULONG   Unknown4;
	CHAR	PathName[0x104];
}DRIVER_INFO,*PDRIVER_INFO;

typedef struct _SYSTEM_INFO_DRIVERS 
{
	ULONG	NumberOfDrivers;
	ULONG	Reserved;
	DRIVER_INFO Drivers[0x100];
}SYSTEM_INFO_DRIVERS,*PSYSTEM_INFO_DRIVERS;

typedef struct _SYSTEM_MODULE {


	ULONG                  Reserved1;
	ULONG                  Reserved2;
	PVOID                  ImageBaseAddress;
	ULONG                  ImageSize;
	ULONG                  Flags;
	USHORT                 Id;
	USHORT                 Rank;
	USHORT                 w018;
	USHORT                 NameOffset;
	UCHAR                  Name[MAXIMUM_FILENAME_LENGTH];

} SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION {

	ULONG                ModulesCount;
	SYSTEM_MODULE        Modules[0];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;



typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,             // obsolete...delete
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemSpare3Information,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSpare6Information,
	SystemNextEventIdInformation,
	SystemEventIdsInformation,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemPlugPlayBusInformation,
	SystemDockInformation,
	SystemPowersInformation,
	SystemProcessorSpeedInformation
} SYSTEM_INFORMATION_CLASS;


//////////////////////////////////////////////////////////////////////////




// #define SetFlag(x,fg)	((x) = ((x)|(fg)))
// 
// #define ClearFlag(x,fg)	((x) = ((x)&(~fg)))
//////////////////////////////////////////////////////////////////////////

extern POBJECT_TYPE *IoDriverObjectType; 

NTSTATUS  EnumKernelModules(PCHAR ModuleName, PSYSTEM_MODULE *PModule);
NTKERNELAPI 
NTSTATUS 
ObReferenceObjectByName( 
						IN PUNICODE_STRING ObjectName, 
						IN ULONG Attributes, 
						IN PACCESS_STATE PassedAccessState OPTIONAL, 
						IN ACCESS_MASK DesiredAccess OPTIONAL, 
						IN POBJECT_TYPE ObjectType, 
						IN KPROCESSOR_MODE AccessMode, 
						IN OUT PVOID ParseContext OPTIONAL, 
						OUT PVOID *Object 
						);
NTSYSAPI
NTSTATUS
NTAPI ZwQuerySystemInformation(
							   IN ULONG SystemInformationClass,
							   IN PVOID SystemInformation,
							   IN ULONG SystemInformationLength,
							   OUT PULONG ReturnLength);



// NTSTATUS PsLookupProcessByProcessId(
// 									IN ULONG ulProcId, 
// 									OUT PEPROCESS * pEProcess
// 									);

NTKERNELAPI
NTSTATUS
ObOpenObjectByPointer(
					  __in PVOID Object,
					  __in ULONG HandleAttributes,
					  __in_opt PACCESS_STATE PassedAccessState OPTIONAL,
					  __in ACCESS_MASK DesiredAccess OPTIONAL,
					  __in_opt POBJECT_TYPE ObjectType OPTIONAL,
					  __in KPROCESSOR_MODE AccessMode,
					  __out PHANDLE Handle
					  );

typedef NTSTATUS (*QUERY_INFO_PROCESS) (
										__in HANDLE ProcessHandle,
										__in PROCESSINFOCLASS ProcessInformationClass,
										__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
										__in ULONG ProcessInformationLength,
										__out_opt PULONG ReturnLength
										);


ULONG GetMoudleBase(char* ModuleName ,PULONG	ModuleSize);

ULONG GetWindowsVersion();


void LockResource(PERESOURCE pLock, BOOLEAN bLockForWrite);

void UnlockResource(PERESOURCE pLock);

NTSTATUS	KKGetKeyValue(PWSTR path, PWSTR pKeyName, PVOID pBuffer, ULONG *pBufferLen);

NTSTATUS  QueryRegistryValue(PWSTR Path, PWSTR KeyName, PVOID KeyValue, ULONG ValueType, ULONG ValueLen);

void dumphex(  void *pBuffer2, ULONG LEN);

NTSTATUS   
GetProcessImagePath(   
					ULONG    dwProcessId,   
					PWCHAR   ProcessImagePath,
					ULONG	 *uPathLen)   ;
PVOID
RtlImageDirectoryEntryToData (
							  IN PVOID Base,
							  IN BOOLEAN MappedAsImage,
							  IN USHORT DirectoryEntry,
							  OUT PULONG Size
							  );

PIMAGE_NT_HEADERS
RtlImageNtHeader (
				  IN PVOID Base
				  );

PVOID FindExportedRoutineAddrByName (PVOID DllBase,PCHAR AnsiImageRoutineName);

NTSTATUS
IoQueryFileDosDeviceName(
						 __in  PFILE_OBJECT FileObject,
						 __out POBJECT_NAME_INFORMATION *ObjectNameInformation
						 );
//////////////////////////////////////////////////////////////////////////


#define OutPutProjectName "[CyberSys]:"
__inline void  kprintf(char *fmt,...)
{
	char mybuffer[2048]={0};
	va_list	val;
	int icount;
	int len =strlen(OutPutProjectName);

	if (KeGetCurrentIrql()>=2)
	{
		//DbgPrint("\r\nwarning.Irql>=Dispatch_lever....\r\n");
	}
	RtlCopyMemory(mybuffer, OutPutProjectName, len);
	va_start(val, fmt);
	icount=_vsnprintf(&mybuffer[len],2048-len,fmt, val);
	if (icount>2000)
	{
		DbgPrint("warning...buffer overflow....\r\n");
		va_end(val);
		return ;
	}

	KdPrint((mybuffer));
	va_end(val);

}
void WPOFF();

VOID WPON();


#endif