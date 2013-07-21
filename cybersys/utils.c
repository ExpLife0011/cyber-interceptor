#include "precomp.h"
#include "all_header.h"
//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////


void dumphex(  void *pBuffer2, ULONG LEN)
{
	ULONG i=0,j=0,space=0;
	unsigned char *pBuffer=(unsigned char *)pBuffer2;
	ULONG	uoffset=0;
	DbgPrint("\r\nBegin dumpping=========================\r\n");
	DbgPrint("size: 0x%x\n", LEN);
	DbgPrint("offset: ");
	for (; i<16; i++)
	{
		DbgPrint("%X  ", i);
		if ((i+1)%8==0)
		{
			DbgPrint(" ");
		}
	}
	DbgPrint("\r\n%x\t ", (uoffset++)*0x10);

	for (i=0; i<LEN; i++)
	{
		DbgPrint("%02x ", pBuffer[i]);
		if ((i+1)%8==0)
		{
			DbgPrint(" ");
		}
		if ((i+1)%16==0)
		{
			DbgPrint(" |   ");
			for (j= i-0xf; j!=i; j++)
			{
				if(pBuffer[j]==0xc || pBuffer[j]==0x0d)
				{
					DbgPrint(" ");
					continue;
				}
				DbgPrint("%c", pBuffer[j]);
			}
			DbgPrint("\r\n%x\t ", (uoffset++)*0x10);
		}
	}
	if (LEN%16!=0)
	{

		i =LEN%16;
		space = 16-i;
		space = space*2+space+1;
		for (i=0; i<space; i++)
		{
			DbgPrint(" ");
		}
		DbgPrint(" |   ");
		i =LEN%16;
		for (j= LEN-i; j<LEN; j++)
		{
			if(pBuffer[j]==0xc || pBuffer[j]==0x0d)
			{
				DbgPrint(" ");
				continue;
			}
			DbgPrint("%c", pBuffer[j]);
		}
	}
	DbgPrint("\r\n");
	DbgPrint("End dumpping=========================\r\n");
}

//////////////////////////////////////////////////////////////////////////


void LockResource(PERESOURCE pLock, BOOLEAN bLockForWrite)
{

	ASSERT(KeGetCurrentIrql()<=APC_LEVEL);
	KeEnterCriticalRegion();
	if (bLockForWrite) {
		ExAcquireResourceExclusiveLite(pLock, TRUE);
	} else {
		ExAcquireResourceSharedLite(pLock, TRUE);
	}
}

void UnlockResource(PERESOURCE pLock)
{

	ASSERT(KeGetCurrentIrql()<=APC_LEVEL);
	ExReleaseResourceLite(pLock);
	KeLeaveCriticalRegion();
}

ULONG  GetWindowsVersion()
{

	ULONG	dwMajorVersion;
	ULONG	dwMinorVersion;
	PsGetVersion(&dwMajorVersion, &dwMinorVersion, NULL, NULL);
	if (dwMajorVersion == 5 && dwMinorVersion == 0) 
	{

		//DbgPrint("Window 2K \n");
		return Windows_2K;

	} else if (dwMajorVersion == 5 && dwMinorVersion == 1) {
		//DbgPrint("Window XP \n");
		return Windows_XP;
	} else if (dwMajorVersion == 5 && dwMinorVersion == 2) {
		// DbgPrint("Window 2003 \n");
		return Windows_2k3;	
	} else if (dwMajorVersion == 6 && dwMinorVersion == 0) 
	{
		//DbgPrint("Window Vista \n");
		return Windows_Vista;
	}
	else if (dwMajorVersion == 6 && dwMinorVersion == 1) {
		//DbgPrint("Window 7 \n");
		return Windows_7;
	}

	return 0;
}

//////////////////////////////////////////////////////////////////////////
//如果返回STATUS_BUFFER_TOO_SMALL，pBufferLen参数返回真正的长度

NTSTATUS	KKGetKeyValue(PWSTR path, PWSTR pKeyName, PVOID pBuffer, ULONG *pBufferLen)
{

	UNICODE_STRING		uniPath,uniKeyName;
	OBJECT_ATTRIBUTES        ObjAttrib;
	ULONG                    nSize;
	ULONG                    nIndex;
	HANDLE				hKey=NULL;
	NTSTATUS			status =STATUS_SUCCESS;
	ULONG				utmp=0;
	PKEY_VALUE_PARTIAL_INFORMATION	pValueInfp=NULL;


	do 
	{
		RtlInitUnicodeString(&uniPath, path);

		RtlInitUnicodeString(&uniKeyName, pKeyName);

		InitializeObjectAttributes(&ObjAttrib, &uniPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
		status = ZwOpenKey(&hKey, KEY_READ, &ObjAttrib);
		if (!NT_SUCCESS(status))
		{
			break;
		}
		utmp	=	0;
		status = ZwQueryValueKey(hKey, &uniKeyName, KeyValuePartialInformation, NULL, 0, &utmp);
		if (status!=STATUS_BUFFER_TOO_SMALL)
		{

			break;
		}


		pValueInfp	=	kmalloc(utmp);

		status = ZwQueryValueKey(hKey, &uniKeyName, KeyValuePartialInformation, pValueInfp, utmp, &utmp);
		if (!NT_SUCCESS(status))
		{
			break;
		}
		//buffer不够大
		if (*pBufferLen<pValueInfp->DataLength)
		{
			status	=	STATUS_BUFFER_TOO_SMALL;
			*pBufferLen = utmp;
			break;
		}
		RtlCopyMemory(pBuffer, pValueInfp->Data, pValueInfp->DataLength);

	} while (0);

	if (hKey)
	{
		ZwClose(hKey);
	}
	if (pValueInfp)
	{
		kfree(pValueInfp);
	}
	kprintf(" KKGetKeyValue( %S\\%S ) return 0x%X\n", path, pKeyName, status);
	return status;

}
//////////////////////////////////////////////////////////////////////////

NTSTATUS
QueryRegistryValueDummyRoutine(
							   IN PWSTR ValueName,
							   IN ULONG ValueType,
							   IN PVOID ValueData,
							   IN ULONG ValueLength,
							   IN PVOID Context,
							   IN PVOID EntryContext
							   )
{
	UNREFERENCED_PARAMETER(ValueType);
	UNREFERENCED_PARAMETER(ValueLength);
	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(EntryContext);

	return STATUS_SUCCESS;
}
//////////////////////////////////////////////////////////////////////////
NTSTATUS  QueryRegistryValue(PWSTR Path, PWSTR KeyName, PVOID KeyValue, ULONG ValueType, ULONG ValueLen)
{
	NTSTATUS status;

	RTL_QUERY_REGISTRY_TABLE  paramTable[2];

	RtlZeroMemory(paramTable, sizeof(paramTable));

	paramTable[0].QueryRoutine	=	QueryRegistryValueDummyRoutine;
	paramTable[0].Flags        = RTL_QUERY_REGISTRY_DIRECT;
	paramTable[0].Name          = KeyName;
	paramTable[0].EntryContext  = KeyValue;

	paramTable[0].DefaultType = ValueType ;
	paramTable[0].DefaultData = NULL;
	paramTable[0].DefaultLength = ValueLen;

	status = RtlQueryRegistryValues(
		RTL_REGISTRY_ABSOLUTE, 
		Path, 
		paramTable, 
		NULL, 
		NULL);

	return status;

}
//////////////////////////////////////////////////////////////////////////

ULONG g_uCr0 = 0;
void WPOFF()
{

	ULONG uAttr;

	_asm
	{
		push eax;
		mov eax, cr0;
		mov uAttr, eax;
		and eax, 0FFFEFFFFh; // CR0 16 BIT = 0
		mov cr0, eax;
		pop eax;
		cli
	};

	g_uCr0 = uAttr; //保存原有的 CRO 屬性

}

VOID WPON()
{

	_asm
	{
		sti
			push eax;
		mov eax, g_uCr0; //恢復原有 CR0 屬性
		mov cr0, eax;
		pop eax;
	};

}
//////////////////////////////////////////////////////////////////////////

ULONG GetMoudleBase(char* ModuleName , PULONG ModuleSize)
{
	PSYSTEM_INFO_DRIVERS	pInfoBuff = NULL;
	ULONG					dwBuffSize;
	BOOLEAN					bNotenough;
	ULONG                   ModuleBase = 0;
	ULONG                   ModuleNameLength;
	ULONG					i=0;


	ModuleNameLength = (ULONG)strlen ( ModuleName );

	dwBuffSize  = 0x8000;	// Exactly as it is in NTDLL.DLL
	bNotenough  = TRUE;

	while( bNotenough )
	{
		if ( dwBuffSize > 0x8000 * 20 ) // Too much, hopeless :(
			return 0;
		pInfoBuff = kmalloc(dwBuffSize);
		if ( pInfoBuff )
		{
			if ( STATUS_INFO_LENGTH_MISMATCH == ZwQuerySystemInformation( (ULONG)0x0b, pInfoBuff, dwBuffSize, NULL ) ) 
			{
				dwBuffSize += 0x8000;
				kfree ( pInfoBuff );
			} 
			else
			{
				bNotenough = FALSE;
			}


		}
		else        
		{
			return 0;
		}
	}

	for (  i = 0; i < pInfoBuff->NumberOfDrivers; ++i ) 
	{
		ULONG   len = (ULONG)strlen ( pInfoBuff->Drivers[i].PathName );

		if (0== _strnicmp(pInfoBuff->Drivers[i].PathName + len - ModuleNameLength, ModuleName, ModuleNameLength ) )
		{
			ModuleBase = (ULONG)pInfoBuff->Drivers[i].BaseAddress;
			*ModuleSize	=	pInfoBuff->Drivers[i].Size;
			break; 
		}
	}	

	if ( pInfoBuff )
		kfree(pInfoBuff);
	return ModuleBase;
}
//////////////////////////////////////////////////////////////////////////

//枚举内核模块
NTSTATUS  EnumKernelModules(PCHAR ModuleName, PSYSTEM_MODULE *PModule)
{

	NTSTATUS status=STATUS_UNSUCCESSFUL; 
	PVOID buf=NULL; 
	ULONG MoudleCount=0;
	ULONG i;
	ULONG size=0;

	PSYSTEM_MODULE_INFORMATION PSysModuleInfomation=NULL;
	PSYSTEM_MODULE PTempModule=NULL;

	PUCHAR tempname=NULL;
	PUCHAR name=NULL;


	if ( ModuleName && PModule )
	{
		do
		{
			status = ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &size);  //得到要分配的内存大小
			if ( status != STATUS_INFO_LENGTH_MISMATCH )
				goto End;
			if ( buf )
			{
				ExFreePoolWithTag(buf, 0);
				buf = NULL;
			}

			buf = kmalloc(size);
			if ( buf==NULL)
			{
				status = STATUS_INSUFFICIENT_RESOURCES;
				goto End;
			}
			status = ZwQuerySystemInformation(SystemModuleInformation, (PVOID)buf, size, &size);
		}
		while ( status == STATUS_INFO_LENGTH_MISMATCH );

		PSysModuleInfomation=(PSYSTEM_MODULE_INFORMATION)buf;
		MoudleCount=PSysModuleInfomation->ModulesCount;
		PTempModule=(PSYSTEM_MODULE)&PSysModuleInfomation->Modules;

		for(i=0;i<MoudleCount;i++)
		{

			tempname = strrchr((PUCHAR)PTempModule->Name, '\\');
			if ( tempname )
				name = (PUCHAR)(tempname + 1);
			else
				name = (PUCHAR)PTempModule->Name;

			if ( strcmp(name, ModuleName)==0)
			{

				buf = kmalloc(sizeof(SYSTEM_MODULE));
				if(buf==NULL)
				{
					status = STATUS_INSUFFICIENT_RESOURCES;
					goto End;
				}

				RtlCopyMemory(buf,PTempModule,sizeof(SYSTEM_MODULE));
				*PModule=buf;
				status=STATUS_SUCCESS;
				break;
			}

			PTempModule++;

		}

		if(i==MoudleCount) //没有找到模块
			status=STATUS_UNSUCCESSFUL;


	}

End:
	if(PSysModuleInfomation)
		kfree(PSysModuleInfomation);

	return status;

}

//////////////////////////////////////////////////////////////////////////
VOID	CleanSeAuditProcessCreationInfo(PUCHAR	 pEprocess)
{


	ULONG	OffsetSeAuditProcessCreationInfo=0;
	ULONG	ulVersion	=0;
	ulVersion	=	GetWindowsVersion();
	if (ulVersion==Windows_XP)
	{
		OffsetSeAuditProcessCreationInfo=	0x1f4;

	}
	if (ulVersion==Windows_2k3)
	{
		OffsetSeAuditProcessCreationInfo=	0x1e4;

	}
	if (ulVersion==Windows_7)
	{
		OffsetSeAuditProcessCreationInfo=	0x1ec;

	}
	if (ulVersion==Windows_Vista)
	{
		OffsetSeAuditProcessCreationInfo=	0x1cc;
	}
	if (OffsetSeAuditProcessCreationInfo)
	{
		PULONG	p	=	(PULONG)(pEprocess+OffsetSeAuditProcessCreationInfo);
		if (*p)
		{
			PVOID	pNameInfp	=	(PVOID)*p;
			*p=0;
			ExFreePool(pNameInfp);
		}
	}


}
NTSTATUS   
GetProcessImagePath(   
					ULONG    dwProcessId,   
					PWCHAR   ProcessImagePath,
					ULONG	 *uPathLen)   
{   
	NTSTATUS Status;   
	HANDLE  hProcess=(HANDLE)-1;   
	PEPROCESS pEprocess=NULL;   
	ULONG returnedLength;   
	//ULONG bufferLength;   
	PVOID buffer=NULL;   
	PUNICODE_STRING imageName;   

	HANDLE LinkHandle;
	WCHAR NameBuffer[64];
	OBJECT_ATTRIBUTES ObjectAttributes;
	UNICODE_STRING DeviceString, VolumeString;
	WCHAR    vol_syb[] = { L"\\DosDevices\\X:" };
	WCHAR    c; 
	ULONG	dwRealPid=0;
	ULONG	dwtmp=0;

	static QUERY_INFO_PROCESS ZwQueryInformationProcess;

	PAGED_CODE(); // this eliminates the possibility of the IDLE Thread/Process   

	if (NULL == ZwQueryInformationProcess) {   

		UNICODE_STRING routineName;   

		RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");   

		ZwQueryInformationProcess =   
			(QUERY_INFO_PROCESS) MmGetSystemRoutineAddress(&routineName);   

		if (NULL == ZwQueryInformationProcess) {   
			DbgPrint("Cannot resolve ZwQueryInformationProcess\n");   
			return STATUS_UNSUCCESSFUL;
		}   
	}   
	dwRealPid	=	dwProcessId&(~3);
	Status = PsLookupProcessByProcessId((HANDLE)dwRealPid, &pEprocess);   
	if (!NT_SUCCESS(Status))
	{
		goto _end;
	}

	Status = ObOpenObjectByPointer(pEprocess,          // Object   
		OBJ_KERNEL_HANDLE,  // HandleAttributes   
		NULL,               // PassedAccessState OPTIONAL   
		GENERIC_READ,       // DesiredAccess   
		*PsProcessType,     // ObjectType   
		KernelMode,         // AccessMode   
		&hProcess);   
	if (!NT_SUCCESS(Status))
	{
		goto _end;

	}

	CleanSeAuditProcessCreationInfo((PUCHAR)pEprocess);

	//means need to get the buffer size firstly
	if (*uPathLen==0)
	{
		// Step one - get the size we need   
		//   
		Status = ZwQueryInformationProcess( hProcess,   
			ProcessImageFileName,   
			NULL, // buffer   
			0, // buffer size   
			&returnedLength);   


		if (STATUS_INFO_LENGTH_MISMATCH != Status) {   

			goto _end;

		}
		*uPathLen	=	returnedLength+0x64;
		goto _end;

	}

	returnedLength	=	*uPathLen;
	//   
	// If we get here, the buffer IS going to be big enough for us, so   
	// let's allocate some storage.   
	//   
	buffer = ExAllocatePoolWithTag(PagedPool, returnedLength, 'uf');   

	if (NULL == buffer) {   

		Status	=STATUS_INSUFFICIENT_RESOURCES;
		goto _end;

	}   
	RtlZeroMemory(buffer, returnedLength);

	//   
	// Now lets go get the data   
	//   
	Status = ZwQueryInformationProcess( hProcess,   
		ProcessImageFileName,   
		buffer,   
		returnedLength,   
		&returnedLength);   

	if (NT_SUCCESS(Status)) {   
		//   
		// Ah, we got what we needed   
		//   
		HANDLE	hFileHandle=NULL;
		IO_STATUS_BLOCK ioStatusBlock;
		imageName = (PUNICODE_STRING) buffer;  

		DeviceString.Buffer = NameBuffer;

		DeviceString.MaximumLength = sizeof(NameBuffer);

		InitializeObjectAttributes(&ObjectAttributes, imageName, OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE, NULL, NULL);

		Status = ZwCreateFile (
			(PHANDLE)&hFileHandle,
			GENERIC_READ ,
			&ObjectAttributes,     // object attributes.
			&ioStatusBlock,        // returned status information.
			NULL,                  // block size (unused).
			FILE_ATTRIBUTE_NORMAL, // file attributes.
			FILE_SHARE_READ,				//share access
			FILE_OPEN,
			0,                     // create options.
			NULL,                  // EA buffer.
			0); // Ea length
		if (NT_SUCCESS(Status))
		{
			PVOID	pObj=NULL;
			POBJECT_NAME_INFORMATION pNameInfo=NULL;


			Status = ObReferenceObjectByHandle(hFileHandle, 0, *IoFileObjectType, KernelMode, &pObj, NULL );
			ZwClose(hFileHandle);
			if (!NT_SUCCESS(Status))
			{

				kprintf("ObReferenceObjectByHandle fail, %d\n", Status);
				goto _retry;
			}

			pNameInfo = (POBJECT_NAME_INFORMATION)kmalloc(*uPathLen);
			RtlZeroMemory(ProcessImagePath, *uPathLen);
			Status = IoQueryFileDosDeviceName(pObj, ( POBJECT_NAME_INFORMATION *)&pNameInfo);
			if (!NT_SUCCESS(Status))
			{
				kprintf("IoQueryFileDosDeviceName fail, %d\n", Status);
				kfree(pNameInfo);
				ObDereferenceObject(pObj);
				goto _retry;
			}
			ObDereferenceObject(pObj);
			RtlMoveMemory(ProcessImagePath, pNameInfo->Name.Buffer, pNameInfo->Name.Length );
			*uPathLen=pNameInfo->Name.Length;
			kfree(pNameInfo);
			goto _end;
		}
_retry:		
		for(c = L'A';c <= L'Z';++c)
		{

			vol_syb[12] = c;

			RtlInitUnicodeString(&VolumeString,vol_syb);

			InitializeObjectAttributes(&ObjectAttributes, &VolumeString, OBJ_KERNEL_HANDLE, NULL, NULL);



			RtlZeroMemory(NameBuffer, sizeof(NameBuffer));

			ZwOpenSymbolicLinkObject(&LinkHandle, SYMBOLIC_LINK_QUERY, &ObjectAttributes);

			ZwQuerySymbolicLinkObject(LinkHandle, &DeviceString, &returnedLength);

			ZwClose(LinkHandle);

			//DbgPrint("%ws",DeviceString.Buffer);



			if(RtlCompareMemory(imageName->Buffer, DeviceString.Buffer, DeviceString.Length ) == DeviceString.Length)
			{
				//为了区分"\Device\HarddiskVolume1"和"\Device\HarddiskVolume11"的情况
				if (imageName->Length>DeviceString.Length && imageName->Buffer[DeviceString.Length/2]==L'\\')
				{

					RtlZeroMemory(ProcessImagePath, *uPathLen);

					RtlCopyMemory(ProcessImagePath, &VolumeString.Buffer[12], sizeof(WCHAR) * 2);

					if(imageName->Length - DeviceString.Length > 2)
						RtlCopyMemory(&ProcessImagePath[2], &imageName->Buffer[DeviceString.Length/2], imageName->Length - DeviceString.Length);

				}

				if (1)
				{
					// 					PUCHAR	pp;
					// 					pp=kmalloc(*uPathLen);
					// 					RtlZeroMemory(pp, *uPathLen);
					// 					wcstombs(pp, ProcessImagePath, *uPathLen);
					// 					RtlZeroMemory(ProcessImagePath, *uPathLen);
					// 					RtlCopyMemory(ProcessImagePath, pp, *uPathLen);
					// 					kfree(pp);
				}
				break;

			}

		}


		// wcscpy(ProcessImagePath, imageName->Buffer);   

	}   //if ZwQueryInformationProcess success
	else{
		kprintf("ZwQueryInformationProcess fail() Return 0x%x, bufferlen %x", Status, returnedLength);
	}
_end:
	if (hProcess!=(HANDLE)-1)
	{
		ZwClose(hProcess);   
	}
	if (pEprocess)
	{
		ObfDereferenceObject(pEprocess);
	}

	//   
	// free our buffer   
	//   
	if (buffer)
	{
		ExFreePool(buffer); 
	}

	//   
	// And tell the caller what happened.   
	//      
	return Status;   

}   
//////////////////////////////////////////////////////////////////////////

PVOID FindExportedRoutineAddrByName (PVOID DllBase,PCHAR AnsiImageRoutineName)
{
	USHORT OrdinalNumber;
	PULONG NameTableBase;
	PUSHORT NameOrdinalTableBase;
	PULONG Addr;
	LONG High;
	LONG Low;
	LONG Middle;
	LONG Result;
	ULONG ExportSize;
	PVOID FunctionAddress;
	PIMAGE_EXPORT_DIRECTORY ExportDirectory=NULL;

	ExportDirectory = (PIMAGE_EXPORT_DIRECTORY) RtlImageDirectoryEntryToData (
		DllBase,
		TRUE,
		IMAGE_DIRECTORY_ENTRY_EXPORT,
		&ExportSize);

	if (ExportDirectory == NULL) {
		return NULL;
	}

	//
	// Initialize the pointer to the array of RVA-based ansi export strings.
	//

	NameTableBase = (PULONG)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfNames);

	//
	// Initialize the pointer to the array of USHORT ordinal numbers.
	//

	NameOrdinalTableBase = (PUSHORT)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfNameOrdinals);

	//
	// Lookup the desired name in the name table using a binary search.
	//

	Low = 0;
	Middle = 0;
	High = ExportDirectory->NumberOfNames - 1;

	while (High >= Low) {

		//
		// Compute the next probe index and compare the import name
		// with the export name entry.
		//

		Middle = (Low + High) >> 1;

		Result = strcmp (AnsiImageRoutineName,
			(PCHAR)DllBase + NameTableBase[Middle]);

		if (Result < 0) {
			High = Middle - 1;
		}
		else if (Result > 0) {
			Low = Middle + 1;
		}
		else {
			break;
		}
	}

	//
	// If the high index is less than the low index, then a matching
	// table entry was not found. Otherwise, get the ordinal number
	// from the ordinal table.
	//

	if (High < Low) {
		return NULL;
	}

	OrdinalNumber = NameOrdinalTableBase[Middle];

	//
	// If the OrdinalNumber is not within the Export Address Table,
	// then this image does not implement the function.  Return not found.
	//

	if ((ULONG)OrdinalNumber >= ExportDirectory->NumberOfFunctions) {
		return NULL;
	}

	//
	// Index into the array of RVA export addresses by ordinal number.
	//

	Addr = (PULONG)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfFunctions);

	FunctionAddress = (PVOID)((PCHAR)DllBase + Addr[OrdinalNumber]);

	//
	// Forwarders are not used by the kernel and HAL to each other.
	//

	ASSERT ((FunctionAddress <= (PVOID)ExportDirectory) ||
		(FunctionAddress >= (PVOID)((PCHAR)ExportDirectory + ExportSize)));

	return FunctionAddress;
}

