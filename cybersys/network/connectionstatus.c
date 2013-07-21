
/********************************************************************

	filename: 	e:\dev\CyberInterceptor\sys\udptraffic\udpTraffic.c
	file path:	e:\dev\CyberInterceptor\sys\udptraffic
	file base:	udpTraffic
	file ext:	c
	author:		kindof
	
	purpose:	
*********************************************************************/
#include "precomp.h"
#include "..\all_header.h"

//////////////////////////////////////////////////////////////////////////
ULONG g_Tcpip_TCPQueryInformationEx_FunAddr=0;
ULONG	g_Tcpip_DispatchFunAddr	=0;
//////////////////////////////////////////////////////////////////////////
NTSTATUS	GetConnectInfo(ULONG	tei_entity, PVOID	pInfoBuffer, ULONG	uBufferLen)
{
	
	NTSTATUS			status = STATUS_SUCCESS;
	PIO_STACK_LOCATION	irpStack;
	PDEVICE_EXTENSION	deviceExtension;
	PVOID				ioBuf;
	ULONG				inBufLength, outBufLength;
	ULONG				ioControlCode;
	ULONG_PTR			 num=0;
	KEVENT				Event;
	ULONG				ulTmp=0;
	ULONG				ulTmp2=0;

	WCHAR   *tcpdevname = L"\\Device\\Tcp" ;
	WCHAR   *udpdevname = L"\\Device\\UDP" ;
	UNICODE_STRING utcpdevname ;
	OBJECT_ATTRIBUTES  objectattributes;
	TCP_REQUEST_QUERY_INFORMATION_EX querybuf ;
	UCHAR   context [CONTEXT_SIZE] ;


	PIRP            pIrp;
	ULONG           index ;
	ULONG           size ;
	PFILE_OBJECT    FileObject;
	PDEVICE_OBJECT  tcpDeviceObject;
	HANDLE          FileHandle ;
	IO_STATUS_BLOCK ioStatusBlock;
	IP_MIB_STATS	ipStatus;


	KeInitializeEvent(&Event,NotificationEvent, FALSE);
	if (tei_entity==CO_TL_ENTITY)
	{
		RtlInitUnicodeString (&utcpdevname, tcpdevname);
		
	}
	else
	{
		RtlInitUnicodeString (&utcpdevname, udpdevname);

	}
	

	InitializeObjectAttributes (
		&objectattributes,
		&utcpdevname,
		0,
		NULL,
		NULL);

	status = ZwCreateFile (
		(PHANDLE)&FileHandle,
		GENERIC_READ | GENERIC_WRITE,
		&objectattributes,     // object attributes.
		&ioStatusBlock,        // returned status information.
		NULL,                  // block size (unused).
		FILE_ATTRIBUTE_NORMAL, // file attributes.
		0,
		FILE_CREATE,
		0,                     // create options.
		NULL,                  // EA buffer.
		0); // Ea length

	if (status != STATUS_SUCCESS) {

		return status ;
	}
	// get a reference to the file object
	//
	status = ObReferenceObjectByHandle (FileHandle,
		0L,
		NULL,
		KernelMode,
		(PVOID *)&FileObject,
		NULL);

	if (status != STATUS_SUCCESS) {
		ZwClose(FileHandle);

		return status ;
	} 
	else
	{
		tcpDeviceObject = IoGetRelatedDeviceObject(FileObject);
	}


	querybuf.ID.toi_entity.tei_entity   = tei_entity;
	querybuf.ID.toi_entity.tei_instance = 0;
	querybuf.ID.toi_class = INFO_CLASS_PROTOCOL;
	querybuf.ID.toi_type  = INFO_TYPE_PROVIDER;
	querybuf.ID.toi_id    = TCP_MIB_ADDRTABLE_ENTRY_EX_ID;
	memset (&(querybuf.Context), 0, CONTEXT_SIZE) ;

	pIrp = IoBuildDeviceIoControlRequest(IOCTL_TCP_QUERY_INFORMATION_EX,
		tcpDeviceObject,
		(PVOID)&querybuf,
		sizeof(querybuf),
		pInfoBuffer,	//output buffer
		uBufferLen,		//output size
		FALSE,
		&Event,
		&ioStatusBlock);
	if (pIrp == NULL) {
		ObDereferenceObject(FileObject);
		// Close the file handle
		//
		ZwClose (FileHandle) ;
		return ioStatusBlock.Status ;
	}
	//
	// stuff in file object
	//
	irpStack = IoGetNextIrpStackLocation(pIrp) ;

	irpStack->FileObject = FileObject ;
	irpStack->DeviceObject	=	tcpDeviceObject;
	//
	// Submit the request to the forwarder
	//
	ulTmp	=	(ULONG)tcpDeviceObject->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
	ulTmp2	=	(ULONG)tcpDeviceObject->DriverObject->MajorFunction[IRP_MJ_POWER];

// 	_asm
// 	{ 
// 		push tcpDeviceObject
// 		push pIrp
// 		call ulTmp2
// 		mov status, eax
// 	}
	*(ULONG*)&tcpDeviceObject->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]=ulTmp2;
	status = IoCallDriver(tcpDeviceObject, pIrp);
	*(ULONG*)&tcpDeviceObject->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]=ulTmp;

	if(status != STATUS_SUCCESS) {

		if (status==STATUS_PENDING)
		{
			KeWaitForSingleObject(&Event, Executive,KernelMode,TRUE, 0);
			status	=STATUS_SUCCESS;
		}

	}

	ObDereferenceObject(FileObject);
	// Close the file handle
	//
	ZwClose (FileHandle) ;
	return status ;
}
NTSTATUS	GetTcpConnectCount(PULONG puCount)
{

	NTSTATUS			status = STATUS_SUCCESS;
	PIO_STACK_LOCATION	irpStack;
	PDEVICE_EXTENSION	deviceExtension;
	PVOID				ioBuf;
	ULONG				inBufLength, outBufLength;
	ULONG				ioControlCode;
	ULONG_PTR			 num=0;
	KEVENT				Event;
	ULONG				ulTmp=0;
	ULONG				ulTmp2=0;

	WCHAR   *tcpdevname = L"\\Device\\Tcp" ;
	UNICODE_STRING utcpdevname ;
	OBJECT_ATTRIBUTES  objectattributes;
	TCP_REQUEST_QUERY_INFORMATION_EX querybuf ;
	UCHAR   context [CONTEXT_SIZE] ;


	PIRP            pIrp;
	ULONG           index ;
	ULONG           size ;
	PFILE_OBJECT    FileObject;
	PDEVICE_OBJECT  tcpDeviceObject;
	HANDLE          FileHandle ;
	IO_STATUS_BLOCK ioStatusBlock;
	IP_MIB_STATS	ipStatus;


	KeInitializeEvent(&Event,NotificationEvent, FALSE);
	RtlInitUnicodeString (&utcpdevname, tcpdevname);

	InitializeObjectAttributes (
		&objectattributes,
		&utcpdevname,
		0,
		NULL,
		NULL);

	status = ZwCreateFile (
		(PHANDLE)&FileHandle,
		GENERIC_READ | GENERIC_WRITE,
		&objectattributes,     // object attributes.
		&ioStatusBlock,        // returned status information.
		NULL,                  // block size (unused).
		FILE_ATTRIBUTE_NORMAL, // file attributes.
		0,
		FILE_CREATE,
		0,                     // create options.
		NULL,                  // EA buffer.
		0); // Ea length

	if (status != STATUS_SUCCESS) {

		return status ;
	}
	// get a reference to the file object
	//
	status = ObReferenceObjectByHandle (FileHandle,
		0L,
		NULL,
		KernelMode,
		(PVOID *)&FileObject,
		NULL);

	if (status != STATUS_SUCCESS) {
		ZwClose(FileHandle);

		return status ;
	} 
	else
	{
		tcpDeviceObject = IoGetRelatedDeviceObject(FileObject);
	}


	querybuf.ID.toi_entity.tei_entity   = CO_TL_ENTITY;
	querybuf.ID.toi_entity.tei_instance = 0;
	querybuf.ID.toi_class = INFO_CLASS_PROTOCOL;
	querybuf.ID.toi_type  = INFO_TYPE_PROVIDER;
	querybuf.ID.toi_id    = IP_MIB_STATS_ID;
	memset (&(querybuf.Context), 0, CONTEXT_SIZE) ;

	pIrp = IoBuildDeviceIoControlRequest(IOCTL_TCP_QUERY_INFORMATION_EX,
		tcpDeviceObject,
		(PVOID)&querybuf,
		sizeof(querybuf),
		&ipStatus,	//output buffer
		sizeof(ipStatus),		//output size
		FALSE,
		&Event,
		&ioStatusBlock);
	if (pIrp == NULL) {
		ObDereferenceObject(FileObject);
		// Close the file handle
		//
		ZwClose (FileHandle) ;
		return ioStatusBlock.Status ;
	}
	//
	// stuff in file object
	//
	irpStack = IoGetNextIrpStackLocation(pIrp) ;

	irpStack->FileObject = FileObject ;
	irpStack->DeviceObject	=	tcpDeviceObject;
	//
	// Submit the request to the forwarder
	//


	ulTmp	=	(ULONG)tcpDeviceObject->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
	ulTmp2	=	(ULONG)tcpDeviceObject->DriverObject->MajorFunction[IRP_MJ_POWER];

// 	_asm
// 	{
// 		push tcpDeviceObject
// 		push pIrp
// 		call ulTmp2
// 		mov status, eax
// 	}
	*(ULONG*)&tcpDeviceObject->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]=ulTmp2;
	status = IoCallDriver(tcpDeviceObject, pIrp);
	*(ULONG*)&tcpDeviceObject->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]=ulTmp;
	if(status != STATUS_SUCCESS) {

		if (status==STATUS_PENDING)
		{
			KeWaitForSingleObject(&Event, Executive,KernelMode,TRUE, 0);
			status	=STATUS_SUCCESS;
		}

	}
	
	*puCount=	ipStatus.uConnectionNumber;
	ObDereferenceObject(FileObject);
	// Close the file handle
	//
	ZwClose (FileHandle) ;
	return status ;

}
NTSTATUS	GetUDPConnectCount(PULONG puCount)
{

	NTSTATUS			status = STATUS_SUCCESS;
	PIO_STACK_LOCATION	irpStack;
	PDEVICE_EXTENSION	deviceExtension;
	PVOID				ioBuf;
	ULONG				inBufLength, outBufLength;
	ULONG				ioControlCode;
	ULONG_PTR			 num=0;
	KEVENT				Event;
	ULONG				ulTmp=0;
	ULONG				ulTmp2=0;

	WCHAR   *tcpdevname = L"\\Device\\UDP" ;
	UNICODE_STRING utcpdevname ;
	OBJECT_ATTRIBUTES  objectattributes;
	TCP_REQUEST_QUERY_INFORMATION_EX querybuf ;
	UCHAR   context [CONTEXT_SIZE] ;


	PIRP            pIrp;
	ULONG           index ;
	ULONG           size ;
	PFILE_OBJECT    FileObject;
	PDEVICE_OBJECT  tcpDeviceObject;
	HANDLE          FileHandle ;
	IO_STATUS_BLOCK ioStatusBlock;
	UDPStats		UdpStats;


	KeInitializeEvent(&Event,NotificationEvent, FALSE);
	RtlInitUnicodeString (&utcpdevname, tcpdevname);

	InitializeObjectAttributes (
		&objectattributes,
		&utcpdevname,
		0,
		NULL,
		NULL);

	status = ZwCreateFile (
		(PHANDLE)&FileHandle,
		GENERIC_READ | GENERIC_WRITE,
		&objectattributes,     // object attributes.
		&ioStatusBlock,        // returned status information.
		NULL,                  // block size (unused).
		FILE_ATTRIBUTE_NORMAL, // file attributes.
		0,
		FILE_CREATE,
		0,                     // create options.
		NULL,                  // EA buffer.
		0); // Ea length

	if (status != STATUS_SUCCESS) {

		return status ;
	}
	// get a reference to the file object
	//
	status = ObReferenceObjectByHandle (FileHandle,
		0L,
		NULL,
		KernelMode,
		(PVOID *)&FileObject,
		NULL);

	if (status != STATUS_SUCCESS) {
		ZwClose(FileHandle);

		return status ;
	} 
	else
	{
		tcpDeviceObject = IoGetRelatedDeviceObject(FileObject);
	}


	querybuf.ID.toi_entity.tei_entity   = CL_TL_ENTITY;
	querybuf.ID.toi_entity.tei_instance = 0;
	querybuf.ID.toi_class = INFO_CLASS_PROTOCOL;
	querybuf.ID.toi_type  = INFO_TYPE_PROVIDER;
	querybuf.ID.toi_id    = IP_MIB_STATS_ID;
	memset (&(querybuf.Context), 0, CONTEXT_SIZE) ;

	pIrp = IoBuildDeviceIoControlRequest(IOCTL_TCP_QUERY_INFORMATION_EX,
		tcpDeviceObject,
		(PVOID)&querybuf,
		sizeof(querybuf),
		&UdpStats,	//output buffer
		sizeof(UdpStats),		//output size
		FALSE,
		&Event,
		&ioStatusBlock);
	if (pIrp == NULL) {

		ObDereferenceObject(FileObject);
		// Close the file handle
		//
		ZwClose (FileHandle) ;
		return ioStatusBlock.Status ;
	}
	//
	// stuff in file object
	//
	irpStack = IoGetNextIrpStackLocation(pIrp) ;
	
	irpStack->FileObject = FileObject ;
	irpStack->DeviceObject	=	tcpDeviceObject;
	//
	// Submit the request to the forwarder
	//

	ulTmp	=	(ULONG)tcpDeviceObject->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
	ulTmp2	=	(ULONG)tcpDeviceObject->DriverObject->MajorFunction[IRP_MJ_POWER];

// 	_asm
// 	{
// 		push tcpDeviceObject
// 		push pIrp
// 		call ulTmp2
// 		mov status, eax
// 	}
	*(ULONG*)&tcpDeviceObject->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]=ulTmp2;
	status = IoCallDriver(tcpDeviceObject, pIrp);
	*(ULONG*)&tcpDeviceObject->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]=ulTmp;


	if(status != STATUS_SUCCESS) {

		if (status==STATUS_PENDING)
		{
			KeWaitForSingleObject(&Event, Executive,KernelMode,TRUE, 0);
			status	=STATUS_SUCCESS;
		}

	}

	*puCount=	UdpStats.uNumber;

	ObDereferenceObject(FileObject);
	// Close the file handle
	//
	ZwClose (FileHandle) ;
	return status ;
}

//////////////////////////////////////////////////////////////////////////
#define		APPENDNUMBER	(0x10)	//补多几个，防止突然增加了链接，导致buffer不够

NTSTATUS	GetNetworkInfoXP(
							   IN PDEVICE_OBJECT		DeviceObject,
							   IN PIRP					Irp
							   )
{


	NTSTATUS			status = STATUS_SUCCESS;
	PIO_STACK_LOCATION	irpStack;
	PDEVICE_EXTENSION	deviceExtension;
	PVOID				ioBuf;
	ULONG				inBufLength, outBufLength;
	ULONG				ioControlCode;
	ULONG_PTR			 num=0;
	ULONG				ulTmp=0;
	ULONG	uNumber=0;


	irpStack = IoGetCurrentIrpStackLocation(Irp);
	deviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

	Irp->IoStatus.Information = 0;

	//
	// Get the pointer to the input/output buffer and it's length
	//
	ioBuf = Irp->AssociatedIrp.SystemBuffer;
	inBufLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
	outBufLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
	ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;

	do 
	{
		if (ioControlCode==IOCTL_GET_TCPINFO)
		{
			if (outBufLength==0)
			{
				if (NT_SUCCESS(GetTcpConnectCount(&uNumber)))
				{

					Irp->IoStatus.Information = (uNumber+ APPENDNUMBER)* sizeof(MIB_TCPROW_OWNER_PID);
					status	=	STATUS_SUCCESS;
					
				}
				else
				{
					status	=	STATUS_UNSUCCESSFUL;
					
				}
				break;
			}
			if (!NT_SUCCESS(GetTcpConnectCount(&uNumber)))
			{

				*(PULONG)ioBuf=0;
				break;
			}
			*(PULONG)ioBuf=uNumber;
			status	=	GetConnectInfo(CO_TL_ENTITY, (PULONG)ioBuf+1, outBufLength);
			Irp->IoStatus.Information	=	outBufLength-sizeof(uNumber);
			


		}// end if (ioControlCode==IOCTL_GET_TCPINFO)

		else if (ioControlCode==IOCTL_GET_UDPINFO)
		{
			if (outBufLength==0)
			{
				if (NT_SUCCESS(GetUDPConnectCount(&uNumber)))
				{
					Irp->IoStatus.Information = (uNumber+ APPENDNUMBER)* sizeof(MIB_UDPROW_OWNER_PID);
					status	=	STATUS_SUCCESS;
					
				}
				else
				{
					status	=	STATUS_UNSUCCESSFUL;
					
				}
				break;

			}
			else
			{
				if (!NT_SUCCESS(GetUDPConnectCount(&uNumber)))
				{

					*(PULONG)ioBuf=0;
					break;
				}
				*(PULONG)ioBuf=uNumber;
				status	=	GetConnectInfo(CL_TL_ENTITY, (PULONG)ioBuf+1, outBufLength);
				Irp->IoStatus.Information	=	outBufLength-sizeof(uNumber);
			}

		}//else if (ioControlCode==IOCTL_GET_UDPINFO)


	} while (0);

	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}
//////////////////////////////////////////////////////////////////////////

NTSTATUS	GetNetworkInfoWin7(
						   IN PDEVICE_OBJECT		DeviceObject,
						   IN PIRP					Irp
						   )
{

	NTSTATUS			Status = STATUS_SUCCESS;
	PIO_STACK_LOCATION	irpStack;
	PDEVICE_EXTENSION	deviceExtension;
	PVOID				ioBuf;
	ULONG				inBufLength, outBufLength;
	ULONG				ioControlCode;
	ULONG_PTR			 num=0;
	ULONG				ulCopiedLen=0;
	irpStack = IoGetCurrentIrpStackLocation(Irp);
	deviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

	Irp->IoStatus.Information = 0;

	//
	// Get the pointer to the input/output buffer and it's length
	//

	ioBuf = Irp->AssociatedIrp.SystemBuffer;
	inBufLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
	outBufLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
	ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
	// Irp->UserBuffer;		// If METHOD_NEITHER, This is Output Buffer


		if (ioControlCode==IOCTL_GET_TCPINFO)
			{
				PMIB_TCPROW_OWNER_PID tcpRow=0;
				PUF_TCPROW_PID        pTcpBuf;


				Status=EnumTcpPortInformationExWin7(&tcpRow, &num);

				if(NT_SUCCESS(Status))
				{

					if(outBufLength <num*sizeof(MIB_TCPROW_OWNER_PID))
					{
						Status=STATUS_SUCCESS;
						Irp->IoStatus.Information =(num+APPENDNUMBER)*sizeof(MIB_TCPROW_OWNER_PID);
						Irp->IoStatus.Status = Status;
						ExFreePool(tcpRow);

						IofCompleteRequest(
							Irp,
							IO_NO_INCREMENT
							);
						return Status;
					}

					ulCopiedLen	=	min(outBufLength, num*sizeof(MIB_TCPROW_OWNER_PID));
					*(PULONG)ioBuf=ulCopiedLen/sizeof(MIB_TCPROW_OWNER_PID);
					RtlCopyMemory((PULONG)ioBuf+1,tcpRow, ulCopiedLen);
					ExFreePool(tcpRow);


					Irp->IoStatus.Information =ulCopiedLen;
					Irp->IoStatus.Status = Status;

					IofCompleteRequest(
						Irp,
						IO_NO_INCREMENT
						);
					return Status;
				}

			}
		if (ioControlCode==IOCTL_GET_UDPINFO)
			{

				PMIB_UDPROW_OWNER_PID  udpRow=0;
				PUF_UDPROW_PID  pUdpBuf;

				Status=EnumUdpPortInformationExWin7(&udpRow, &num);

				if(NT_SUCCESS(Status))
				{

					if(outBufLength <num*sizeof(MIB_UDPROW_OWNER_PID))
					{
						Status=STATUS_SUCCESS;
						Irp->IoStatus.Information =(num+APPENDNUMBER)*sizeof(MIB_UDPROW_OWNER_PID);
						Irp->IoStatus.Status = Status;
						ExFreePool(udpRow);

						IofCompleteRequest(
							Irp,
							IO_NO_INCREMENT
							);
						return Status;
					}



// 					FormatUdpStruct(udpRow,pUdpBuf,num);
// 					RtlCopyMemory(ioBuf,pUdpBuf,num*sizeof(UF_UDPROW_PID));
					ulCopiedLen	=	min(outBufLength, num*sizeof(MIB_UDPROW_OWNER_PID));
					*(PULONG)ioBuf=ulCopiedLen/(sizeof(MIB_UDPROW_OWNER_PID));
					RtlCopyMemory((PULONG)ioBuf+1,udpRow,ulCopiedLen);
					ExFreePool(udpRow);


					Irp->IoStatus.Information =ulCopiedLen;
					Irp->IoStatus.Status = Status;

					IofCompleteRequest(
						Irp,
						IO_NO_INCREMENT
						);
					return Status;
				}//if(NT_SUCCESS(Status))
			}


		Status=STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = Status;

		IofCompleteRequest(
			Irp,
			IO_NO_INCREMENT
			);
		return Status;
}


//下面好几个函数是来自网络
//////////////////////////////////////////////////////////////////////////


NTSTATUS __stdcall GetTcpipDispatchAddress()
{


	NTSTATUS status=STATUS_UNSUCCESSFUL;
	//PCSTR OutString;
	PDRIVER_OBJECT Tcpip_DriverObject;
	UNICODE_STRING TcpipDriverNameString; 

	RtlInitUnicodeString(&TcpipDriverNameString, L"\\Driver\\Tcpip");

	status = ObReferenceObjectByName(&TcpipDriverNameString, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType,KernelMode, 0, &Tcpip_DriverObject);
	if ( !NT_SUCCESS(status) )
	{
		goto End;
	}
	ObDereferenceObject(Tcpip_DriverObject);
	//使用IRP_MJ_SET_QUOTA是避免IRP_MJ_DEVICE_CONTROL被HOOK替换了
	g_Tcpip_DispatchFunAddr = *(ULONG*)(&Tcpip_DriverObject->MajorFunction[IRP_MJ_SET_QUOTA]);	//


End:

	return status;
}

//////////////////////////////////////////////////////////////////////////

NTSTATUS	EnumConnections(
						   IN PDEVICE_OBJECT		DeviceObject,
						   IN PIRP					Irp
						   )
{
	NTSTATUS	status	=	STATUS_SUCCESS;
	ULONG		ulVer	=	0;


	ulVer	=	GetWindowsVersion();

	switch (ulVer)
	{
	case Windows_XP:
	case Windows_2k3:
			status = GetNetworkInfoXP(DeviceObject, Irp);
		break;

	case Windows_7:
	case Windows_Vista:
			status = GetNetworkInfoWin7(DeviceObject, Irp);
		break;
	default:
		status	=	STATUS_NOT_SUPPORTED;

	}
	
	return status;


}
//////////////////////////////////////////////////////////////////////////

NTSTATUS __stdcall Get_TCPQueryInformationEx_Addr()
{
	ULONG v0;
	ULONG i; 
	NTSTATUS status; 
	ULONG TCPDispatchDeviceControl_Addr; 
	ULONG TCPQueryInformationEx_Addr;

	ULONG	g_Tcpip_DispatchFunAddr=0;
	//这里注意啊。。。。。。。。。。。
	if ( !g_Tcpip_DispatchFunAddr )
	{
       
		goto End;
	}

	//找到00015E4E E8 0D 00 00 00 call    _TCPDispatchDeviceControl@8
	/*
	.text:000173BE 81 7F 0C 03 02 21 00                          cmp     dword ptr [edi+0Ch], 210203h
	.text:000173C5 0F 84 E9 9B 00 00                             jz      loc_20FB4
	.text:000173CB FF 76 60                                      push    dword ptr [esi+60h]
	.text:000173CE 56                                            push    esi
	.text:000173CF E8 10 D9 FF FF                                call    _TCPDispatchDeviceControl@8 
   */

	i = 0;
	v0=g_Tcpip_DispatchFunAddr;
	while ( *(ULONG *)v0 != 0x566076FF || *(ULONG *)(v0 - 10) != 0x210203 )
	{
		++i;
		++v0;
		if ( i >= (ULONG)0x300u )
		{
			 DbgPrint("Get_TCPQueryInformationEx_Addr  Find call  _TCPDispatchDeviceControl@8 Failed \n ");
			 goto End;
		}
	}

	v0 += 4;  //使v0指向E8 CALL
	if ( *(UCHAR *)v0 != 0xE8 )     
	{
		DbgPrint("Get_TCPQueryInformationEx_Addr  Find call  _TCPDispatchDeviceControl@8  E8 Failed \n ");
		goto End;
	}

	//计算得到TCPDispatchDeviceControl地址
	TCPDispatchDeviceControl_Addr = v0 + *(ULONG *)(v0 + 1) + 5;  
	i = 0;
	do
	{
		if ( *(ULONG *)(TCPDispatchDeviceControl_Addr - 12) == 0x120003 && *(UCHAR *)(TCPDispatchDeviceControl_Addr - 1) == 0x56 && *(UCHAR *)(TCPDispatchDeviceControl_Addr - 2) == 0x52 )
			break;
		++i;
		++TCPDispatchDeviceControl_Addr;
	}
	while ( i < (ULONG)0x300u );

	if ( *(UCHAR *)TCPDispatchDeviceControl_Addr == 0xE8 && i != 0x300 )
	{
		//DbgPrint("Get_TCPQueryInformationEx_Addr Init Success! \n");

		TCPQueryInformationEx_Addr = *(ULONG *)(TCPDispatchDeviceControl_Addr + 1) + TCPDispatchDeviceControl_Addr + 5;

		g_Tcpip_TCPQueryInformationEx_FunAddr = TCPQueryInformationEx_Addr;


		status = STATUS_SUCCESS;
		return status;
	}
	
End:
	status = STATUS_UNSUCCESSFUL;
	return status;
}

//////////////////////////////////////////////////////////////////////////

typedef enum _NPI_MODULEID_TYPE {
	MIT_GUID = 1,
	MIT_IF_LUID,
} NPI_MODULEID_TYPE;


//
// Network Module Identifier.
// This type is persistable.
//
typedef struct _NPI_MODULEID {
	USHORT Length;

	NPI_MODULEID_TYPE Type;
#ifdef __midl 
	[switch_type(NPI_MODULEID_TYPE), switch_is(Type)] 
#endif
	union
	{
		//
		// Valid for MIT_GUID
		//
#ifdef __midl
		[case(MIT_GUID)]
#endif
		GUID Guid;

		//
		// Valid for MIT_IF_LUID
		// TODO: NET_IFLUID is not an "RPC'able" define yet.
		//

#ifdef __midl
		[case(MIT_IF_LUID)]
#endif
		LUID IfLuid;
#ifdef __midl
		[default];
#endif
	};
} NPI_MODULEID;
typedef CONST NPI_MODULEID *PNPI_MODULEID;


NTSTATUS  
EnumTcpPortInformationWin7(
					     PMIB_TCPROW_OWNER_PID  *TcpRow,
						 ULONG_PTR  *Number
									)
{
    PINTERNAL_TCP_TABLE_ENTRY  pBuf1;
    PNSI_STATUS_ENTRY  pBuf2;
	PNSI_PROCESSID_INFO  pBuf3;
	PMIB_TCPROW_OWNER_PID pOutputBuff;
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE FileHandle =	(HANDLE)-1;
    PFILE_OBJECT pFileObject;
    PDEVICE_OBJECT pDeviceObject;
    KEVENT    Event;
    IO_STATUS_BLOCK  StatusBlock;
    PIRP        pIrp;
    PIO_STACK_LOCATION StackLocation;
	ULONG_PTR  retLen=0;
    ULONG   i;

	NSI_PARAM   nsiStruct={0};
	

	NPI_MODULEID NPI_MS_TCP_MODULEID = {
                      sizeof(NPI_MODULEID),
                      MIT_GUID,
                     {0xEB004A03, 0x9B1A, 0x11D4,
                     {0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xBC}}
                     };

   // UNICODE_STRING DeviceName;

   // RtlInitUnicodeString(&DeviceName, DD_TCP_DEVICE_NAME);
    



     nsiStruct.UnknownParam3=&NPI_MS_TCP_MODULEID;
     nsiStruct.UnknownParam4=3;
     nsiStruct.UnknownParam5=1;
	 nsiStruct.UnknownParam6=1;
	// nsiStruct.ConnCount=retLen;

    
   

    status = GetObjectByName(&FileHandle, &pFileObject,  L"\\device\\nsi");

    if (!NT_SUCCESS(status))
    {
        DbgPrint("获取设备名失败！\n");
        goto __end;
    }
   
    pDeviceObject = IoGetRelatedDeviceObject(pFileObject);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("获取设备对象或文件对象失败！\n");
        goto __end;
    }
    KeInitializeEvent(&Event,NotificationEvent, FALSE);
   
    pIrp = IoBuildDeviceIoControlRequest(IOCTL_NSI_GETALLPARAM, 
                            pDeviceObject,&nsiStruct,sizeof(NSI_PARAM), 
                            &nsiStruct,sizeof(NSI_PARAM), FALSE, &Event, &StatusBlock);
    if (NULL == pIrp)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        DbgPrint("IRP生成失败！\n");
    }
   
   
    StackLocation = IoGetNextIrpStackLocation(pIrp);
    StackLocation->FileObject = pFileObject; 
   // pIrp->Tail.Overlay.Thread = PsGetCurrentThread();
    StackLocation->DeviceObject = pDeviceObject;
	pIrp->RequestorMode = KernelMode;
	//StackLocation->MinorFunction = IRP_MN_USER_FS_REQUEST;





    status  = IoCallDriver(pDeviceObject, pIrp);

    DbgPrint("STATUS:%08lX\n", status);
   
   
    if (STATUS_PENDING == status)
    {
        status = KeWaitForSingleObject(&Event, Executive,KernelMode,TRUE, 0);

    }

     retLen=nsiStruct.ConnCount;
	 retLen+=2;

	pBuf1 =(PINTERNAL_TCP_TABLE_ENTRY)ExAllocatePool(PagedPool,56*retLen);
    if (NULL == pBuf1)
    {
        DbgPrint("输出缓冲区内存分配失败！\n");
        goto __end;
    }
    RtlZeroMemory(pBuf1, 56*retLen);

	pBuf2 =(PNSI_STATUS_ENTRY)ExAllocatePool(PagedPool,12*retLen);
    if (NULL == pBuf1)
    {
        DbgPrint("输出缓冲区内存分配失败！\n");
        goto __end;
    }
    RtlZeroMemory(pBuf2, 12*retLen);

	pBuf3= (PNSI_PROCESSID_INFO)ExAllocatePool(PagedPool,32*retLen);
    if (NULL == pBuf1)
    {
        DbgPrint("输出缓冲区内存分配失败！\n");
        goto __end;
    }
     RtlZeroMemory(pBuf3, 32*retLen);

	 pOutputBuff =(PMIB_TCPROW_OWNER_PID)ExAllocatePoolWithTag(NonPagedPool,retLen*sizeof(MIB_TCPROW_OWNER_PID),'uf');
    if (NULL == pOutputBuff)
    {
        DbgPrint("输出缓冲区内存分配失败！\n");
        goto __end;
    }
    RtlZeroMemory(pOutputBuff, retLen*sizeof(MIB_TCPROW_OWNER_PID));


	 nsiStruct.UnknownParam7=pBuf1;
     nsiStruct.UnknownParam8=56;
     nsiStruct.UnknownParam11=pBuf2;
     nsiStruct.UnknownParam12=12;
     nsiStruct.UnknownParam13=pBuf3;
     nsiStruct.UnknownParam14=32;

	pIrp = IoBuildDeviceIoControlRequest(IOCTL_NSI_GETALLPARAM, 
                            pDeviceObject,&nsiStruct,sizeof(NSI_PARAM), 
                            &nsiStruct,sizeof(NSI_PARAM), FALSE, &Event, &StatusBlock);
    if (NULL == pIrp)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        DbgPrint("IRP生成失败！\n");
    }
   
   
    StackLocation = IoGetNextIrpStackLocation(pIrp);
    StackLocation->FileObject = pFileObject; 
   // pIrp->Tail.Overlay.Thread = PsGetCurrentThread();
    StackLocation->DeviceObject = pDeviceObject;
	pIrp->RequestorMode = KernelMode;
	//StackLocation->MinorFunction = IRP_MN_USER_FS_REQUEST;





    status = IoCallDriver(pDeviceObject, pIrp);

   
   
    if (STATUS_PENDING == status)
    {
        status = KeWaitForSingleObject(&Event, Executive,KernelMode,TRUE, 0);

    }

	*Number	=	nsiStruct.ConnCount;
    for(i=0; i<nsiStruct.ConnCount; i++)
	{
            
             pOutputBuff[i].dwState=pBuf2[i].dwState;

             pOutputBuff[i].dwLocalAddr =pBuf1[i].localEntry.dwIP;
             pOutputBuff[i].dwLocalPort =pBuf1[i].localEntry.Port;
            pOutputBuff[i].dwRemoteAddr =pBuf1[i].remoteEntry.dwIP;

		  pOutputBuff[i].dwRemotePort=pBuf1[i].remoteEntry.Port;

          pOutputBuff[i].dwOwningPid=pBuf3[i].dwProcessId;

	}


	     *TcpRow=pOutputBuff;

	    


__end:
     if(NULL != pBuf1)
            ExFreePool(pBuf1);

	 if(NULL != pBuf2)
            ExFreePool(pBuf2);

	 if(NULL != pBuf3)
            ExFreePool(pBuf3);

   
    
   
     if (NULL != pFileObject)
            ObDereferenceObject(pFileObject);

	 if ((HANDLE)-1 != FileHandle)
        {
              ZwClose(FileHandle);
        }




    return status;
}
//////////////////////////////////////////////////////////////////////////


NTSTATUS  
EnumUdpPortInformationWin7(
					     PMIB_UDPROW_OWNER_PID  *udpRow,
						 ULONG_PTR  *Number
									)
{
    PINTERNAL_UDP_TABLE_ENTRY  pBuf1;
	PNSI_PROCESSID_INFO  pBuf2;
	PMIB_UDPROW_OWNER_PID pOutputBuff;
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE FileHandle;
    PFILE_OBJECT pFileObject;
    PDEVICE_OBJECT pDeviceObject;
    KEVENT    Event;
    IO_STATUS_BLOCK  StatusBlock;
    PIRP        pIrp;
    PIO_STACK_LOCATION StackLocation;
	ULONG_PTR  retLen=0;
	NSI_PARAM   nsiStruct={0};
	ULONG i;

	NPI_MODULEID NPI_MS_UDP_MODULEID = {
                      sizeof(NPI_MODULEID),
                      MIT_GUID,
                    {0xEB004A02, 0x9B1A, 0x11D4,
                    {0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xBC}}
                     };

   // UNICODE_STRING DeviceName;

   // RtlInitUnicodeString(&DeviceName, DD_TCP_DEVICE_NAME);
    



     nsiStruct.UnknownParam3=&NPI_MS_UDP_MODULEID;
     nsiStruct.UnknownParam4=1;
     nsiStruct.UnknownParam5=1;
	 nsiStruct.UnknownParam6=1;
	// nsiStruct.ConnCount=retLen;

    
   

    status = GetObjectByName(&FileHandle, &pFileObject,  L"\\device\\nsi");

    if (!NT_SUCCESS(status))
    {
        DbgPrint("获取设备名失败！\n");
        goto __end;
    }
   
    pDeviceObject = IoGetRelatedDeviceObject(pFileObject);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("获取设备对象或文件对象失败！\n");
        goto __end;
    }
   
    KeInitializeEvent(&Event,NotificationEvent, FALSE);
   
    pIrp = IoBuildDeviceIoControlRequest(IOCTL_NSI_GETALLPARAM, 
                            pDeviceObject,&nsiStruct,sizeof(NSI_PARAM), 
                            &nsiStruct,sizeof(NSI_PARAM), FALSE, &Event, &StatusBlock);
    if (NULL == pIrp)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        DbgPrint("IRP生成失败！\n");
    }
   
   
    StackLocation = IoGetNextIrpStackLocation(pIrp);
    StackLocation->FileObject = pFileObject; 
    //pIrp->Tail.Overlay.Thread = PsGetCurrentThread();
    StackLocation->DeviceObject = pDeviceObject;
	pIrp->RequestorMode = KernelMode;

	//StackLocation->MinorFunction = IRP_MN_USER_FS_REQUEST;





    status  = IoCallDriver(pDeviceObject, pIrp);

    DbgPrint("STATUS:%08lX\n", status);
   
   
    if (STATUS_PENDING == status)
    {
        status = KeWaitForSingleObject(&Event, Executive,KernelMode,TRUE, 0);

    }

     retLen=nsiStruct.ConnCount;
	 retLen+=2;

	pBuf1 =(PINTERNAL_UDP_TABLE_ENTRY)ExAllocatePool(PagedPool,28*retLen);
    if (NULL == pBuf1)
    {
        DbgPrint("输出缓冲区内存分配失败！\n");
        goto __end;
    }
    RtlZeroMemory(pBuf1, 28*retLen);

	
	pBuf2= (PNSI_PROCESSID_INFO)ExAllocatePool(PagedPool,32*retLen);
    if (NULL == pBuf1)
    {
        DbgPrint("输出缓冲区内存分配失败！\n");
        goto __end;
    }
     RtlZeroMemory(pBuf2, 32*retLen);

	 pOutputBuff =(PMIB_UDPROW_OWNER_PID)ExAllocatePoolWithTag(NonPagedPool,retLen*sizeof(MIB_UDPROW_OWNER_PID),'uf');
    if (NULL == pOutputBuff)
    {
        DbgPrint("输出缓冲区内存分配失败！\n");
        goto __end;
    }
    RtlZeroMemory(pOutputBuff, retLen*sizeof(MIB_UDPROW_OWNER_PID));


	 nsiStruct.UnknownParam7=pBuf1;
     nsiStruct.UnknownParam8=28;
     nsiStruct.UnknownParam13=pBuf2;
     nsiStruct.UnknownParam14=32;

	pIrp = IoBuildDeviceIoControlRequest(IOCTL_NSI_GETALLPARAM, 
                            pDeviceObject,&nsiStruct,sizeof(NSI_PARAM), 
                            &nsiStruct,sizeof(NSI_PARAM), FALSE, &Event, &StatusBlock);
    if (NULL == pIrp)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        DbgPrint("IRP生成失败！\n");
    }
   
   
    StackLocation = IoGetNextIrpStackLocation(pIrp);
    StackLocation->FileObject = pFileObject; 
    // pIrp->Tail.Overlay.Thread = PsGetCurrentThread();
    StackLocation->DeviceObject = pDeviceObject;
	pIrp->RequestorMode = KernelMode;
	//StackLocation->MinorFunction = IRP_MN_USER_FS_REQUEST;





    status = IoCallDriver(pDeviceObject, pIrp);

   
   
    if (STATUS_PENDING == status)
    {
        status = KeWaitForSingleObject(&Event, Executive,KernelMode,TRUE, 0);

    }

	*Number=nsiStruct.ConnCount;
    for(i=0; i<nsiStruct.ConnCount; i++)
	{
            
           
		//if ( pBuf1[i].localEntry.bytesfill0 == 2 )
        //{
             pOutputBuff[i].dwLocalAddr =pBuf1[i].dwIP;
             pOutputBuff[i].dwLocalPort =pBuf1[i].Port;
            
       // }
      //  else
       /* {
             pOutputBuff[i].dwLocalAddr = 0;
             pOutputBuff[i].dwLocalPort=pBuf1[i].localEntry.Port;
             pOutputBuff[i].dwRemoteAddr= 0;
           
        }*/
		

          pOutputBuff[i].dwOwningPid=pBuf2[i].dwUdpProId;

	}


	     *udpRow=pOutputBuff;
         

	    


__end:
     if(NULL != pBuf1)
            ExFreePool(pBuf1);

	 if(NULL != pBuf2)
            ExFreePool(pBuf2);

    
   
     if (NULL != pFileObject)
            ObDereferenceObject(pFileObject);

	 if ((HANDLE)-1 != FileHandle)
        {
              ZwClose(FileHandle);
        }




    return status;
}


//////////////////////////////////////////////////////////////////////////

NTSTATUS    GetObjectByName(PHANDLE pFileHandle, PVOID *pFileObject, PCWSTR szObjectName)
{
	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES oa;
	NTSTATUS status;
	IO_STATUS_BLOCK io_status_block;

	RtlInitUnicodeString(&ObjectName, szObjectName);
	InitializeObjectAttributes(&oa, &ObjectName,OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = ZwCreateFile(pFileHandle, GENERIC_READ | GENERIC_WRITE, 
		&oa, &io_status_block, NULL, FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF , 0, 0, 0);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("TCP设备打开失败！\n");
		goto __end;
	}

	status = ObReferenceObjectByHandle(*pFileHandle, GENERIC_READ | GENERIC_WRITE,  NULL, KernelMode, pFileObject, NULL);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("引用对象失败！\n");

		if ((HANDLE)-1 != (*pFileHandle))
		{
			ZwClose(*pFileHandle);
		}


		goto __end;
	}

__end:


	return status;

}
//////////////////////////////////////////////////////////////////////////
NTSTATUS	KKNsiEnumerateObjectsAllParametersEx(PVOID	par)
{
	PSYSTEM_MODULE PsysModule=NULL;
	ULONG netio_Sys_BaseAddr;
	NTSTATUS status=STATUS_SUCCESS;
	PVOID	AddrNsiEnumerateObjectsAllParametersEx=0;
	do 
	{
		status=EnumKernelModules("NETIO.SYS",&PsysModule);
		if (!NT_SUCCESS(status))
		{
			
			DbgPrint("EnumKernelModules失败！\n");
			break;
		}
		 netio_Sys_BaseAddr=(ULONG)PsysModule->ImageBaseAddress;
		AddrNsiEnumerateObjectsAllParametersEx	=	FindExportedRoutineAddrByName((PVOID)netio_Sys_BaseAddr,"NsiEnumerateObjectsAllParametersEx");
		if (AddrNsiEnumerateObjectsAllParametersEx==NULL)
		{
			
			status	=	STATUS_UNSUCCESSFUL;
			break;
		}
		_asm{
			push par
			call AddrNsiEnumerateObjectsAllParametersEx
			mov status,eax
		}


	} while (0);


	if(PsysModule)
		ExFreePoolWithTag(PsysModule,0);
	return status;
}
//////////////////////////////////////////////////////////////////////////

NTSTATUS  
EnumTcpPortInformationExWin7(
						   PMIB_TCPROW_OWNER_PID  *TcpRow,
						   ULONG_PTR  *Number
									)
{
	PINTERNAL_TCP_TABLE_ENTRY  pBuf1=NULL;
	PNSI_STATUS_ENTRY  pBuf2=NULL;
	PNSI_PROCESSID_INFO  pBuf3=NULL;
	PMIB_TCPROW_OWNER_PID pOutputBuff=NULL;
	NTSTATUS status = STATUS_SUCCESS;


	KEVENT    Event;
	IO_STATUS_BLOCK  StatusBlock;
	PIRP        pIrp;
	PIO_STACK_LOCATION StackLocation;
	ULONG_PTR  retLen=0;
	ULONG   i;
	PSYSTEM_MODULE PsysModule=NULL;
	NSI_PARAM   nsiStruct={0};
	ULONG netio_Sys_BaseAddr;


	NPI_MODULEID NPI_MS_TCP_MODULEID = {
		sizeof(NPI_MODULEID),
		MIT_GUID,
		{0xEB004A03, 0x9B1A, 0x11D4,
		{0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xBC}}
	};

	// UNICODE_STRING DeviceName;

	// RtlInitUnicodeString(&DeviceName, DD_TCP_DEVICE_NAME);

	nsiStruct.UnknownParam3=&NPI_MS_TCP_MODULEID;
	nsiStruct.UnknownParam4=3;
	nsiStruct.UnknownParam5=1;
	nsiStruct.UnknownParam6=1;
	// nsiStruct.ConnCount=retLen;

	do 
	{
		status =KKNsiEnumerateObjectsAllParametersEx((PVOID)&nsiStruct);
		if (!NT_SUCCESS(status))
		{
			break;
		}

		retLen=nsiStruct.ConnCount;
		retLen+=2;

		pBuf1 =(PINTERNAL_TCP_TABLE_ENTRY)ExAllocatePool(PagedPool,56*retLen);
		if (NULL == pBuf1)
		{
			DbgPrint("输出缓冲区内存分配失败！\n");
			break;
		}
		RtlZeroMemory(pBuf1, 56*retLen);

		pBuf2 =(PNSI_STATUS_ENTRY)ExAllocatePool(PagedPool,12*retLen);
		if (NULL == pBuf1)
		{
			DbgPrint("输出缓冲区内存分配失败！\n");
			break;
		}
		RtlZeroMemory(pBuf2, 12*retLen);

		pBuf3= (PNSI_PROCESSID_INFO)ExAllocatePool(PagedPool,32*retLen);
		if (NULL == pBuf1)
		{
			DbgPrint("输出缓冲区内存分配失败！\n");
			break;
		}
		RtlZeroMemory(pBuf3, 32*retLen);

		pOutputBuff =(PMIB_TCPROW_OWNER_PID)ExAllocatePool(NonPagedPool,retLen*sizeof(MIB_TCPROW_OWNER_PID));
		if (NULL == pOutputBuff)
		{
			DbgPrint("输出缓冲区内存分配失败！\n");
			break;
		}
		RtlZeroMemory(pOutputBuff, retLen*sizeof(MIB_TCPROW_OWNER_PID));


		nsiStruct.UnknownParam7=pBuf1;
		nsiStruct.UnknownParam8=56;
		nsiStruct.UnknownParam11=pBuf2;
		nsiStruct.UnknownParam12=12;
		nsiStruct.UnknownParam13=pBuf3;
		nsiStruct.UnknownParam14=32;

		status =KKNsiEnumerateObjectsAllParametersEx((PVOID)&nsiStruct);
		if (!NT_SUCCESS(status))
		{
			break;
		}

		*Number	=	nsiStruct.ConnCount;
		for(i=0; i<nsiStruct.ConnCount; i++)
		{
			PNSI_PROCESSID_INFO  pid=NULL;
			PNSI_STATUS_ENTRY	pS	=NULL;
			PINTERNAL_TCP_TABLE_ENTRY	pT=NULL;
			pS	=	&pBuf2[i];
			pT	=	&pBuf1[i];
			pid	=	&pBuf3[i];
// 			if (pBuf2[i].dwState!=0)
// 			{
// 				DbgPrint("%d\n",ntohs(pBuf1[i].localEntry.Port));
// 			}

			pOutputBuff[i].dwState=pBuf2[i].dwState;
			pOutputBuff[i].dwLocalAddr =pBuf1[i].localEntry.dwIP;
			pOutputBuff[i].dwLocalPort =pBuf1[i].localEntry.Port;
			pOutputBuff[i].dwRemoteAddr =pBuf1[i].remoteEntry.dwIP;
			pOutputBuff[i].dwRemotePort=pBuf1[i].remoteEntry.Port;
			pOutputBuff[i].dwOwningPid=pBuf3[i].dwProcessId;

		}


		*TcpRow=pOutputBuff;
		pOutputBuff=NULL;

	} while (0);


	if(NULL != pBuf1)
		ExFreePool(pBuf1);

	if(NULL != pBuf2)
		ExFreePool(pBuf2);

	if(NULL != pBuf3)
		ExFreePool(pBuf3);

	if(NULL != pOutputBuff)
		ExFreePool(pOutputBuff);



	return status;
}


//////////////////////////////////////////////////////////////////////////
NTSTATUS  
EnumUdpPortInformationExWin7(
					     PMIB_UDPROW_OWNER_PID  *udpRow,
						 ULONG_PTR  *Number
									)
{
    PINTERNAL_UDP_TABLE_ENTRY  pBuf1=NULL;
	PNSI_PROCESSID_INFO  pBuf2=NULL;
	PMIB_UDPROW_OWNER_PID pOutputBuff=NULL;
    NTSTATUS status = STATUS_SUCCESS;

    KEVENT    Event;
    IO_STATUS_BLOCK  StatusBlock;
    PIRP        pIrp;
    PIO_STACK_LOCATION StackLocation;
	ULONG_PTR  retLen=0;
	NSI_PARAM   nsiStruct={0};
	ULONG i;

	NPI_MODULEID NPI_MS_UDP_MODULEID = {
                      sizeof(NPI_MODULEID),
                      MIT_GUID,
                    {0xEB004A02, 0x9B1A, 0x11D4,
                    {0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xBC}}
                     };

   // UNICODE_STRING DeviceName;

   // RtlInitUnicodeString(&DeviceName, DD_TCP_DEVICE_NAME);
    



     nsiStruct.UnknownParam3=&NPI_MS_UDP_MODULEID;
     nsiStruct.UnknownParam4=1;
     nsiStruct.UnknownParam5=1;
	 nsiStruct.UnknownParam6=1;
    
   do 
   {
		status =KKNsiEnumerateObjectsAllParametersEx((PVOID)&nsiStruct);
		 if (!NT_SUCCESS(status))
		 {
			break;
		 }

		 retLen=nsiStruct.ConnCount;
		 retLen+=2;

		pBuf1 =(PINTERNAL_UDP_TABLE_ENTRY)ExAllocatePool(PagedPool,28*retLen);
		if (NULL == pBuf1)
		{
			DbgPrint("输出缓冲区内存分配失败！\n");
			break;
		}
		RtlZeroMemory(pBuf1, 28*retLen);

		
		pBuf2= (PNSI_PROCESSID_INFO)ExAllocatePool(PagedPool,32*retLen);
		if (NULL == pBuf2)
		{
			DbgPrint("输出缓冲区内存分配失败！\n");
			break;
		}
		 RtlZeroMemory(pBuf2, 32*retLen);

		 pOutputBuff =(PMIB_UDPROW_OWNER_PID)ExAllocatePool(NonPagedPool,retLen*sizeof(MIB_UDPROW_OWNER_PID));
		if (NULL == pOutputBuff)
		{
			DbgPrint("输出缓冲区内存分配失败！\n");
			break;
		}
		RtlZeroMemory(pOutputBuff, retLen*sizeof(MIB_UDPROW_OWNER_PID));


		 nsiStruct.UnknownParam7=pBuf1;
		 nsiStruct.UnknownParam8=28;
		 nsiStruct.UnknownParam13=pBuf2;
		 nsiStruct.UnknownParam14=32;

		 status =KKNsiEnumerateObjectsAllParametersEx((PVOID)&nsiStruct);
		 if (!NT_SUCCESS(status))
		 {
			 break;
		 }

		*Number=nsiStruct.ConnCount;
		for(i=0; i<nsiStruct.ConnCount; i++)
		{
	            
	           
			//if ( pBuf1[i].localEntry.bytesfill0 == 2 )
			//{
				 pOutputBuff[i].dwLocalAddr =pBuf1[i].dwIP;
				 pOutputBuff[i].dwLocalPort =pBuf1[i].Port;
	            
		   // }
		  //  else
		   /* {
				 pOutputBuff[i].dwLocalAddr = 0;
				 pOutputBuff[i].dwLocalPort=pBuf1[i].localEntry.Port;
				 pOutputBuff[i].dwRemoteAddr= 0;
	           
			}*/
			

			  pOutputBuff[i].dwOwningPid=pBuf2[i].dwUdpProId;

		}
		
		 *udpRow=pOutputBuff;
		 pOutputBuff	=	NULL;
         
   } while (0);

	

	    
     if(NULL != pBuf1)
            ExFreePool(pBuf1);

	 if(NULL != pBuf2)
            ExFreePool(pBuf2);

	 if (NULL!=pOutputBuff)
	 {
		ExFreePool(pOutputBuff);
	 }


    return status;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

 




typedef unsigned long ulong;
typedef unsigned short ushort;
typedef unsigned char uchar;
typedef unsigned int uint;

typedef  struct _in_addr
{
	union
	{
		struct { uchar s_b1,s_b2,s_b3,s_b4; } S_un_b;
		struct { ushort s_w1,s_w2; } S_un_w;
		ulong S_addr;
	} S_un;
#define s_addr  S_un.S_addr
#define s_host  S_un.S_un_b.s_b2
#define s_net   S_un.S_un_b.s_b1
#define s_imp   S_un.S_un_w.s_w2
#define s_impno S_un.S_un_b.s_b4
#define s_lh    S_un.S_un_b.s_b3
}in_addr;

VOID
FormatTcpStruct(PMIB_TCPROW_OWNER_PID tcpTable,PVOID pBuf,ULONG_PTR num)
{
	CHAR szLocalAddr[128]={0};
	CHAR szRemoteAddr[128]={0};
	WCHAR szProcessName[260]={0};
	in_addr inadLocal, inadRemote;
	CHAR   strState[128]={0};
	ULONG   dwRemotePort = 0;
	ULONG   i;
	CHAR *remote;
	CHAR *local;
    NTSTATUS status;
	PUF_TCPROW_PID pTcpStruct;




    pTcpStruct= (PUF_TCPROW_PID)pBuf;
	for( i= 0; i < num; i++)
	{
		// 状态
		switch (tcpTable[i].dwState)
		{
		case MIB_TCP_STATE_CLOSED:
			strcpy(strState, "CLOSED");
			break;
		case MIB_TCP_STATE_TIME_WAIT:
			strcpy(strState, "TIME_WAIT");
			break;
		case MIB_TCP_STATE_LAST_ACK:
			strcpy(strState, "LAST_ACK");
			break;
		case MIB_TCP_STATE_CLOSING:
			strcpy(strState, "CLOSING");
			break;
		case MIB_TCP_STATE_CLOSE_WAIT:
			strcpy(strState, "CLOSE_WAIT");
			break;
		case MIB_TCP_STATE_FIN_WAIT1:
			strcpy(strState, "FIN_WAIT1");
			break;
		case MIB_TCP_STATE_ESTAB:
			strcpy(strState, "ESTAB");
			break;
		case MIB_TCP_STATE_SYN_RCVD:
			strcpy(strState, "SYN_RCVD");
			break;
		case MIB_TCP_STATE_SYN_SENT:
			strcpy(strState, "SYN_SENT");
			break;
		case MIB_TCP_STATE_LISTEN:
			strcpy(strState, "LISTEN");
			break;
		case MIB_TCP_STATE_DELETE_TCB:
			strcpy(strState, "DELETE");
			break;
		default:
			break;
		}



        strcpy(pTcpStruct[i].State,strState);

		// 本地IP地址
		inadLocal.s_addr = tcpTable[i].dwLocalAddr;
		
		// 远程端口
		if(strcmp(strState, "LISTEN") != 0)
		{
			dwRemotePort = tcpTable[i].dwRemotePort;
		}
		else{
			dwRemotePort = 0;

		}



		pTcpStruct[i].RemoteIP	=	tcpTable[i].dwRemoteAddr;
		pTcpStruct[i].RemotePort=	(USHORT)tcpTable[i].dwRemotePort;
		pTcpStruct[i].LocalIP	=	tcpTable[i].dwLocalAddr;
		pTcpStruct[i].localPort	=	(USHORT)tcpTable[i].dwLocalPort;
		pTcpStruct[i].dwPid=tcpTable[i].dwOwningPid;
	

// 		if(tcpTable[i].dwOwningPid==4||tcpTable[i].dwOwningPid==0)
// 		{
//                  wcscpy(szProcessName, L"system.exe"); 
// 
// 		}else{
// 
//         
//               status=GetProcessImagePath(tcpTable[i].dwOwningPid,szProcessName);
// 	          if (!NT_SUCCESS(status))
//               {
//                   DbgPrint("获取进程名失败！\n");
//                   return;
//               }
// 
// 		}
// 
// 		wcscpy(pTcpStruct[i].ProcessPath, szProcessName);
// 
// 		//DbgPrint(" TCP PID is %d  ProcessName is %ws   LocalAddr is %s    RemoteAddr is %s   State is %s  \n", tcpTable[i].dwOwningPid,szProcessName, szLocalAddr,szRemoteAddr,strState);
// 
// 		memset(szProcessName,0,sizeof(szProcessName));

	}

}

VOID
FormatUdpStruct(PMIB_UDPROW_OWNER_PID udpTable,PUF_UDPROW_PID  pUdpStruct, ULONG_PTR num)
{
	    
	CHAR szLocalAddr[128]={0};
	WCHAR szProcessName[260]={0};
	in_addr inadLocal;
	char *local;
	ULONG i;
	NTSTATUS status;


	for( i = 0; i < num; i++)
	{
		
		// 本地IP地址
// 		inadLocal.s_addr = udpTable[i].dwLocalAddr;
// 		local=inet_ntoa(inadLocal);
// 		
// 
// 		sprintf(szLocalAddr, "%s:%u", local, 
// 					ntohs((unsigned short)(0x0000FFFF & udpTable[i].dwLocalPort)));
// 
// 		strcpy(pUdpStruct[i].LocalAddr,szLocalAddr);
        pUdpStruct[i].dwPid=udpTable[i].dwOwningPid;
		pUdpStruct[i].localPort	=	(USHORT)udpTable[i].dwLocalPort;
		pUdpStruct[i].LocalIP	=	udpTable[i].dwLocalAddr;
		pUdpStruct[i].RemoteIP=0;
		pUdpStruct[i].RemotePort	=	0;





// 		//WCHAR processInfo[256];
// 		//PidToName(hProcessSnap, udpTable[i].dwOwningPid, szProcessName);
// 		//wsprintf(processInfo,L"%s:%d",szProcessName,udpTable[i].dwOwningPid);
// 
// 		if(udpTable[i].dwOwningPid==4||udpTable[i].dwOwningPid==0)
// 		{
//                  wcscpy(szProcessName, L"C:\\WINDOWS\\system32\\ntoskrnl.exe"); 
// 
// 		}else{
// 
// 
// 		   status=GetProcessImagePath(udpTable[i].dwOwningPid, szProcessName);
// 	       if (!NT_SUCCESS(status))
//            {
//              DbgPrint("获取进程名失败！\n");
//              return;
//            }
// 		}
// 		wcscpy(pUdpStruct[i].ProcessPath, szProcessName);
// 		strcpy(pUdpStruct[i].RemoteAddr,"*:*");
// 
// 		
// 
// 
//         DbgPrint(" UDP PID is %d  ProcessName is %ws  LocalAddr is %s  RemoteAddr is %s  \n", udpTable[i].dwOwningPid,szProcessName, szLocalAddr ,"*.*.*.*:*");
// 
// 		memset(szProcessName,0,sizeof(szProcessName));


	}

}



