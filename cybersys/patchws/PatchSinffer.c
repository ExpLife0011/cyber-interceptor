
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

NTSTATUS	UnInitPatch()
{

	UnDoPatchWS2(NULL, 0);
	ReleaseNetBufferListPool();
	PatchRestoreDontLoopbackForXp();

	return STATUS_SUCCESS;
}
//////////////////////////////////////////////////////////////////////////

NTSTATUS
PatchDispatch(IN PDEVICE_OBJECT		DeviceObject, IN PIRP	Irp)
{
	NTSTATUS			Status = STATUS_SUCCESS;
	PIO_STACK_LOCATION	irpStack;
	PDEVICE_EXTENSION	deviceExtension;
	PVOID				ioBuf;
	ULONG				inBufLength, outBufLength;
	ULONG				ioControlCode;
	ULONG_PTR			 num=0;


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
	switch (ioControlCode)
	{
	case IOCTL_PATCHWS:
		{
			Status = DoPatchWS2((char*)ioBuf, inBufLength);
			break;
		}
	case IOCTL_CHECKNPFSYS:
		{
			Status		=	CheckProtocolExist((char*)ioBuf, inBufLength);
			break;
		}
	case IOCTL_UNPATCHWS:
		{
			Status		=	UnDoPatchWS2((char*)ioBuf, inBufLength);
			break;
		}
	case IOCTL_PATCH_NOSENTLOOPBACK:
		{
			Status		=	PatchDontLoopbackForXp();
			break;
		}
	case IOCTL_PATCH_RESTORE_NOSENTLOOPBACK:
		{
			Status		=	PatchRestoreDontLoopbackForXp();
			break;
		}
	case IOCTL_GETPROTOCOLLIST:
		{
			Status		=	GetProtocolList((char*)ioBuf, &outBufLength);
			if (NT_SUCCESS(Status))
			{
				Irp->IoStatus.Information = outBufLength;
			}

			break;
		}
	}
	Irp->IoStatus.Status = Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;

}
//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////
PVOID	g_pOriNdisSendX=NULL;	//address for restore
PVOID	g_pOriNdisSendXHandler=NULL;//real ori handler

ULONG	myNdisSendXForDontLoopback(PVOID par1, PNDIS_PACKET pPacket)
{


	ULONG	ulRet=0;

	NdisSetPacketFlags(pPacket, NDIS_FLAGS_DONT_LOOPBACK);
	pPacket->Private.NdisPacketFlags	|=0x20;
	_asm
	{
		push pPacket
		push par1
		call g_pOriNdisSendXHandler
		mov ulRet,eax
		
	}
	return ulRet;

}
//////////////////////////////////////////////////////////////////////////
NTSTATUS	PatchRestoreDontLoopbackForXp()
{
	NTSTATUS	status=STATUS_SUCCESS;
	if (g_pOriNdisSendX==NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	*(PVOID**)g_pOriNdisSendX	=	g_pOriNdisSendXHandler;
	g_pOriNdisSendX=NULL;
	return status;

}

//另外一种方法是直接把miniport flag中的Check_for_loopback标志去掉，这个在XP，2003，WIN7下都有效
//PS：有可能要处理所有启用的miniport
//////////////////////////////////////////////////////////////////////////
NTSTATUS	PatchDontLoopbackForXp()
{

	struct my_NDIS_PROTOCOL_BLOCK *pTcpProtoclBlock=NULL;
	NTSTATUS	status=STATUS_SUCCESS;
	PNDIS_COMMON_OPEN_BLOCK_2k3_early	pOpenBlock=NULL;

	pTcpProtoclBlock	=	(struct my_NDIS_PROTOCOL_BLOCK *)GetProtocolBlockXP("Tcpip", 5);
	do 
	{
		if (pTcpProtoclBlock==NULL)
		{
			status	=	STATUS_UNSUCCESSFUL;
			break;
		}
		pOpenBlock	=	pTcpProtoclBlock->OpenQueue;
		if (pOpenBlock==NULL)
		{
			status	=	STATUS_UNSUCCESSFUL;
			break;
		}
		g_pOriNdisSendX	=	&(pOpenBlock->WanSendHandler);

		//back up
		g_pOriNdisSendXHandler	=	pOpenBlock->WanSendHandler;
		//patch it
		pOpenBlock->WanSendHandler	=	(WAN_SEND_HANDLER)myNdisSendXForDontLoopback;

	} while (0);

	return status;

}
//////////////////////////////////////////////////////////////////////////

NTSTATUS	GetProtocolListWin7(char *pbuffer, DWORD *dwlen)
{

	UNICODE_STRING	uniNPF;
	ULONG			uHeader=0;
	NTSTATUS		status = STATUS_SUCCESS;
	PNDIS_PROTOCOL_BLOCKWin7	pProtoBLock=NULL;
	BOOLEAN			bFound	=	FALSE;
	PNDIS_PROTOCOL_BLOCKWin7	pNpfProtocolBlock=NULL;
	char szBuffer[1024];
	ANSI_STRING	aniStr1;
	DWORD		dwNumber=0;
	DWORD		dwTmp=0;
	PProtocol_Lists	pProListInfo=(PProtocol_Lists)pbuffer;

	dwNumber	=	*dwlen/(sizeof(Protocol_Lists));


	RtlZeroMemory(pProListInfo, *dwlen);

	do 
	{

		uHeader	=	GetProtocolHeader();
		if (uHeader==0)
		{
			status	=	STATUS_UNSUCCESSFUL;
			break;
		}
		pProtoBLock	=	(PNDIS_PROTOCOL_BLOCKWin7)uHeader;
		while(pProtoBLock)
		{
			RtlUnicodeStringToAnsiString(&aniStr1, &pProtoBLock->Name, TRUE);
			RtlMoveMemory(pProListInfo[dwTmp].szName, aniStr1.Buffer, min(aniStr1.Length, ProtocolNameSize-1));
			RtlFreeAnsiString(&aniStr1);

			if (dwTmp++>dwNumber)
			{
				break;;
			}
			pProtoBLock	=	(PNDIS_PROTOCOL_BLOCKWin7)pProtoBLock->NextProtocol;
		}

		//NdisDeregisterProtocol(&status, (NDIS_HANDLE)uHeader);	// deregister it

	} while (0);

	*dwlen	=	dwTmp*sizeof(Protocol_Lists);

	return status;

}
//////////////////////////////////////////////////////////////////////////

NTSTATUS	GetProtocolList(char *pbuffer, DWORD *dwlen)
{


	ULONG			uHeader=0;
	NTSTATUS		status = STATUS_SUCCESS;
	struct my_NDIS_PROTOCOL_BLOCK	*pProtoBLock=NULL;
	BOOLEAN			bFound	=	FALSE;
	struct my_NDIS_PROTOCOL_BLOCK	*pNpfProtocolBlock=NULL;

	char szBuffer[1024];
	ANSI_STRING	aniStr1;
	DWORD		dwNumber=0;

	DWORD		dwTmp=0;
	PProtocol_Lists	pProListInfo=(PProtocol_Lists)pbuffer;


	dwNumber	=	(*dwlen)/(sizeof(Protocol_Lists));
	if (GetWindowsVersion()==Windows_7)
	{
		return GetProtocolListWin7(pbuffer, dwlen);
	}

	RtlZeroMemory(pbuffer, *dwlen);

	do 
	{
		uHeader	=	GetProtocolHeader();
		if (uHeader==0)
		{
			status	=	STATUS_UNSUCCESSFUL;
			break;
		}
		pProtoBLock	=	(struct my_NDIS_PROTOCOL_BLOCK	*)uHeader;
		while(pProtoBLock)
		{
			RtlUnicodeStringToAnsiString(&aniStr1, &pProtoBLock->ProtocolCharacteristics.Ndis40Chars.Name, TRUE);
			RtlMoveMemory(pProListInfo[dwTmp].szName, aniStr1.Buffer, min(aniStr1.Length, ProtocolNameSize-1));
			RtlFreeAnsiString(&aniStr1);

			if (dwTmp++>dwNumber)
			{
				break;;
			}
			pProtoBLock	=	pProtoBLock->NextProtocol;
		}


	} while (0);
	*dwlen	=	dwTmp*sizeof(Protocol_Lists);

	return	status;

}