
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
NDIS_HANDLE	g_SendPacketPoolHandle	=	NULL;
NDIS_HANDLE	g_RecvPacketPoolHandle	=	NULL;

KSPIN_LOCK	g_SendPacketListLock;
LIST_ENTRY	g_SendPacketListHeader;
KEVENT		g_SendPacketListEvent;
BOOLEAN		g_TerminateUdpWorkThread	=	FALSE;




//////////////////////////////////////////////////////////////////////////
VOID	UdpRecvCallback(PVOID packet)
{

	UCHAR	pMacAddress[MACADDRESSLEN];
	ULONG	uMacLen;
	uMacLen	=	sizeof(pMacAddress);
	

}
//////////////////////////////////////////////////////////////////////////

VOID	TerminateUdpWorkItemThread()
{
	g_TerminateUdpWorkThread	=	TRUE;
	KeSetEvent(&g_SendPacketListEvent, IO_NO_INCREMENT, FALSE );
}
//////////////////////////////////////////////////////////////////////////

NTSTATUS	HandleSendIRP(PVOID par)
{

	NTSTATUS			Status = STATUS_SUCCESS;
	PIO_STACK_LOCATION	irpStack;
	PVOID				ioBuf;
	ULONG				inBufLength, outBufLength;
	ULONG				ioControlCode;
	PIRP					Irp	=	par;

	irpStack = IoGetCurrentIrpStackLocation(Irp);

	Irp->IoStatus.Information = 0;

	//
	// Get the pointer to the input/output buffer and it's length
	//

	ioBuf = Irp->AssociatedIrp.SystemBuffer;
	inBufLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
	outBufLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
	ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;

	Status	=	MiniportSendUdp(ioBuf, inBufLength);
	
	Irp->IoStatus.Status = Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	//Status	=	STATUS_UNSUCCESSFUL;//这个返回值没用，决定应用层返回值的是Irp->IoStatus.Status
	return Status;




}
//////////////////////////////////////////////////////////////////////////

VOID	UdpWorkItemThread(PVOID par)
{

	PIRP		pIrp=NULL;
	PLIST_ENTRY	pListEntry=NULL;
	NTSTATUS			Status = STATUS_SUCCESS;

	while(1)
	{
#ifdef VMPROTECT
		VMProtectBeginVirtualization("UdpWorkItemThread");

#endif
		if (g_TerminateUdpWorkThread)
		{
			return ;	//不用psterminate
		}
		KeWaitForSingleObject(&g_SendPacketListEvent,Executive,KernelMode,0,0);
		while(!IsListEmpty(&g_SendPacketListHeader))
		{
			pListEntry	=	ExInterlockedRemoveHeadList(&g_SendPacketListHeader, &g_SendPacketListLock);
			pIrp = CONTAINING_RECORD(pListEntry, IRP, Tail.Overlay.ListEntry);
			HandleSendIRP(pIrp);
		}
#ifdef VMPROTECT
		VMProtectEnd();

#endif
	}

	
}
//////////////////////////////////////////////////////////////////////////

PVOID	MakePacketByMem(PVOID pBuffer,int len)
{
	NDIS_STATUS         Status;
	PNDIS_PACKET    Packet, MyPacket;
	PULONG	ptmp=NULL;
	PMDL	pMdl	=NULL;
	KIRQL	pIrql;
	PVOID pBuffer2;
	ULONG	_TotalPacketLength;

	if (pBuffer==NULL)
	{
		
		return NULL;

	}
	if (g_SendPacketPoolHandle==NULL)
	{
		if (!AllocatePacketPools())
		{
			return NULL;
		}

	}

	NdisAllocatePacket(&Status,
		&MyPacket,
		g_SendPacketPoolHandle);
	if (Status != NDIS_STATUS_SUCCESS)
	{
		return NULL;
	}

	SetPacketSign(MyPacket, MYPACKETFLAG);
//	MyPacket->Reserved[0]=MYPACKETFLAG;
	MyPacket->Private.Flags=2;
	MyPacket->Private.NdisPacketFlags	=	0x90;
// 	MyPacket->Private.NdisPacketFlags &=fPACKET_ALLOCATED_BY_NDIS;
// 	ClearFlag(MyPacket->Private.NdisPacketFlags, fPACKET_CONTAINS_MEDIA_SPECIFIC_INFO);

	NDIS_SET_PACKET_HEADER_SIZE(MyPacket, 14);	//MAC头大小
	NdisSetPacketFlags(MyPacket, NDIS_FLAGS_DONT_LOOPBACK);

	PacketCheckSum(pBuffer);
	ptmp	=	(PULONG)MyPacket;
	//ptmp[-1]=3;
	pBuffer2	=	kmalloc(len);
	if (pBuffer2==NULL)
	{
	}
	RtlCopyMemory(pBuffer2, pBuffer, len);
	pMdl	=	IoAllocateMdl(pBuffer2, len, FALSE, FALSE, NULL);
	//pMdl	=	NdisAllocateMdl(g_SendPacketPoolHandle, pBuffer, len);
	
	if (pMdl==NULL)
	{
		
		NdisFreePacket(MyPacket);
		kfree(pBuffer2);
		return NULL;
	}
	MmBuildMdlForNonPagedPool(pMdl);
	NdisChainBufferAtFront(MyPacket,pMdl);
	MyPacket->Private.Head->Next=NULL; 
	MyPacket->Private.Tail=NULL;
	copy_buffer_to_packet(MyPacket, pBuffer, len);
	NdisQueryPacket(MyPacket, NULL, NULL, NULL, &_TotalPacketLength);	//这个函数有更新packet包大小功能

	return MyPacket;

}
//////////////////////////////////////////////////////////////////////////
BOOLEAN	AllocatePacketPools()
{

	NDIS_STATUS	Status;
	NdisAllocatePacketPoolEx(&Status,
		&g_RecvPacketPoolHandle,
		MIN_PACKET_POOL_SIZE,
		MAX_PACKET_POOL_SIZE - MIN_PACKET_POOL_SIZE,
		PROTOCOL_RESERVED_SIZE_IN_PACKET*10 );

	if (Status != NDIS_STATUS_SUCCESS)
	{
		return FALSE;
	}

	//
	// Allocate a packet pool for receives. We need this to indicate receives.
	// Same consideration as sends (see also NDIS 5.1 packet stacking).
	//
	NdisAllocatePacketPoolEx(&Status,
		&g_SendPacketPoolHandle,
		MIN_PACKET_POOL_SIZE,
		MAX_PACKET_POOL_SIZE - MIN_PACKET_POOL_SIZE,
		PROTOCOL_RESERVED_SIZE_IN_PACKET*10);

	if (Status != NDIS_STATUS_SUCCESS)
	{
		g_SendPacketPoolHandle	=NULL;
		MPFreeAllPacketPools();
		return FALSE;
		
	}

	return TRUE;
}



/////////////////////////////////////////////////

VOID MPFreeAllPacketPools()
/*++

Routine Description:

    Free all packet pools on the specified adapter.
    
Return Value:

    None

--*/
{
    if (g_RecvPacketPoolHandle!= NULL)
    {
        //
        // Free the packet pool that is used to indicate receives
        //
        NdisFreePacketPool(g_RecvPacketPoolHandle);

        g_RecvPacketPoolHandle= NULL;
    }

    if (g_SendPacketPoolHandle != NULL)
    {

        //
        //  Free the packet pool that is used to send packets below
        //

        NdisFreePacketPool(g_SendPacketPoolHandle);

        g_SendPacketPoolHandle = NULL;

    }
}

//////////////////////////////////////////////////////////////////////////
//如果成功，将返回 pUdpPacket指针，否则返回0，返回值需用kfree释放掉
//
PVOID	MakeUdpBuffer(PVOID	pSendInfoIn, PULONG ulLen, PULONG uReserve)
{

	LIST_ENTRY		*pListEntry=NULL;
	NETCARDS_INFO		*pNI=NULL;
	BOOLEAN				bFound	=	FALSE;
	UCHAR				GatewayMac[MACADDRESSLEN];
	UCHAR				SrcMac[MACADDRESSLEN];
	ULONG				SrcIP,DestIP;
	ULONG				ulPacketSize=0;
	UDP_PACKET			*pUdpPacket=NULL;
	PSEND_UDP_INFO		pSendInfo		=	pSendInfoIn;
	USHORT				usIPpackSize	=	0;

	*uReserve	=	0;
	SrcIP	=	DestIP= 0;
	pListEntry =	g_NetCardsInfoHeader.Next.Flink;
	while (pListEntry &&(pListEntry != &g_NetCardsInfoHeader.Next))
	{

		pNI = CONTAINING_RECORD(pListEntry, NETCARDS_INFO, Next);
		//src为0，就随意了，拿一个是连接状态的即可即可
		if (
			(pSendInfo->srcIP==0 &&(pNI->flag&ISCONNECTED)) ||
			(pNI->IPAddr==pSendInfo->srcIP)
			
			)
		{
			bFound	=	TRUE;
			RtlCopyMemory(GatewayMac, pNI->GatewayMacAddr, MACADDRESSLEN);
			RtlCopyMemory(SrcMac, pNI->MacAddr, MACADDRESSLEN);
			SrcIP	=	pNI->IPAddr;
			DestIP	=	pSendInfo->dstIP;
			*uReserve	=	(ULONG)pNI->pMiniBlock;
			break;;
		}
		pListEntry	=	pListEntry->Flink;
		
	}
	if (!bFound)
	{
		return NULL;	//没网关的MAC是没法发包的
	}
	
	ulPacketSize	=	pSendInfo->dwSize + sizeof(Dlc_Header)+ sizeof(Ip_Header) +	sizeof(Udp_Header);
	pUdpPacket	=	kmalloc(ulPacketSize);

	if (pUdpPacket==NULL)
	{
		return 0;
	}
	RtlZeroMemory(pUdpPacket, ulPacketSize);
	RtlCopyMemory(pUdpPacket->MacHeader.desmac, GatewayMac, MACADDRESSLEN);
	RtlCopyMemory(pUdpPacket->MacHeader.srcmac, SrcMac, MACADDRESSLEN);
//	RtlCopyMemory(pUdpPacket->MacHeader.desmac, "\x00\x1a\x6b\x4a\xc2\x70", MACADDRESSLEN);
	pUdpPacket->MacHeader.ethertype	=	ntohs(0x0800);	//


	usIPpackSize	=	(USHORT)(ulPacketSize	-	sizeof(Dlc_Header));
	//init ip header
	pUdpPacket->IPHeader.ver_len	=	0x45;
	pUdpPacket->IPHeader.tos		=	0;
	pUdpPacket->IPHeader.total_len	=	ntohs(usIPpackSize);
	pUdpPacket->IPHeader.ident		=	0;
	pUdpPacket->IPHeader.frag_and_flags	=	0;
	pUdpPacket->IPHeader.ttl		=	64;
	pUdpPacket->IPHeader.proto		=	0x11;	//UDP协议
	pUdpPacket->IPHeader.checksum	=	0;
	pUdpPacket->IPHeader.sourceIP	=	SrcIP;
	pUdpPacket->IPHeader.destIP		=	DestIP;

	//init udp header
	pUdpPacket->UdpHeader.chksum	=	0;
	pUdpPacket->UdpHeader.dstport	=	ntohs(pSendInfo->dstPort);
	pUdpPacket->UdpHeader.srcport	=	ntohs(RESERVERUDPPORT);
	pUdpPacket->UdpHeader.total_len	=	ntohs(usIPpackSize-20);	//IP头一般都20字节
	RtlCopyMemory(pUdpPacket->Payload, pSendInfo->pbuffer, pSendInfo->dwSize);
	*ulLen	=	ulPacketSize;
	kprintf("\r\n MakeUdpBuffer() with：\r\nMAC : %02X:%02X:%02X:%02X:%02X:%02X   \nDstMAC : %02X:%02X:%02X:%02X:%02X:%02X   \nIP :0x%x   \n", pNI->MacAddr[0], pNI->MacAddr[1], pNI->MacAddr[2], pNI->MacAddr[3], pNI->MacAddr[4], pNI->MacAddr[5], GatewayMac[0], GatewayMac[1], GatewayMac[2], GatewayMac[3], GatewayMac[4], GatewayMac[5],pNI->IPAddr);

	return pUdpPacket;

}
//////////////////////////////////////////////////////////////////////////
NTSTATUS	MiniportSendUdp(PVOID pSendInfoIn, ULONG uLen)
{

	LIST_ENTRY			*pNextHook	=	NULL;
	PNDIS_HOOK_INFO		pHI			=	NULL;
	PNDIS_PACKET	pPacket			=	NULL;

	PSEND_UDP_INFO	pSendInfo		=	(PSEND_UDP_INFO)pSendInfoIn;
	PVOID			pSendHandler	=	NULL;
	PVOID			pAdaptContext	=	NULL;
	PVOID			pSendBuffer		=	NULL;
	ULONG			ulSendBufferLen	=	0;
	ULONG			uReserve1		=	0;

	BOOLEAN			bFoundSendHandler	=	FALSE;
	PNDIS_COMMON_OPEN_BLOCK_2k3_early	pOpenBlock=NULL;

	NTSTATUS		status	=	STATUS_SUCCESS;
#ifdef VMPROTECT
	VMProtectBeginVirtualization("MiniportSendUdp");

#endif
	
	//UCHAR pTmpBUffer[]="\x00\x50\x56\xc0\x00\x08\x00\x0c\x29\x63\xfc\xe2\x08\x00\x45\x00\x00\x3c\x00\x42\x00\x00\x80\x01\x2a\xab\xc0\xa8\xc7\x81\xc0\xa8\xc7\x01\x08\x00\x4a\x5c\x02\x00\x01\x00\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x61\x62\x63\x64\x65\x66\x67\x68\x69";

	if (uLen<sizeof(SEND_UDP_INFO))
	{
		kprintf("SEND_UDP_INFO buffer too small \n");
		return STATUS_INVALID_PARAMETER;
		
	}
	pSendBuffer	=	MakeUdpBuffer(pSendInfo, &ulSendBufferLen, &uReserve1);

	if (pSendBuffer==NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	kprintf("Enter MiniportSendUdp()  dstIP 0x%x  dstPort:%d   Send Size %d\n", pSendInfo->dstIP, pSendInfo->dstPort, ulSendBufferLen);


	if (pSendHandler==NULL)
	{
		STARTLOCK(&g_HookInfoLock2, KKRWLOCK_FOR_READ);

		pNextHook =	g_pHookInfoHeader.Next.Flink;
		while (pNextHook != &g_pHookInfoHeader.Next)
		{
			if (pNextHook)
			{
				pHI = CONTAINING_RECORD(pNextHook, NDIS_HOOK_INFO, Next);
				pOpenBlock	=	(PNDIS_COMMON_OPEN_BLOCK_2k3_early)pHI->pReserveContext1;
				//判断uReserve1，是为了使用相应的网卡
				if (pHI->HandlerSign	==	'sen1' && ((ULONG)pOpenBlock->MiniportHandle== uReserve1))
				{
					bFoundSendHandler	=	TRUE;
					break;
				}
				if (pHI->HandlerSign	==	'sens' && ((ULONG)pOpenBlock->MiniportHandle== uReserve1))
				{
					bFoundSendHandler	=	TRUE;
					break;
				}
			}
			pNextHook	=	pNextHook->Flink;
		}// end for while
		
		ENDLOCK(&g_HookInfoLock2);
	}

	if (!bFoundSendHandler)
	{

		kprintf("MiniportSendUdp Get pSendHandler fail....oh god, crash me!!\n");
		kfree(pSendBuffer); pSendBuffer=NULL;
		return STATUS_UNSUCCESSFUL;
	}
	if (1)
	{
		PNDIS_MINIPORT_BLOCK	pBlock	=	(PNDIS_MINIPORT_BLOCK)pHI->pMiniBlock;
		if (!(pBlock&&(pBlock->Flags&ISCONNECTED)))
		{
			kprintf("something went wrong . miniport is not connected!!\n");
			kfree(pSendBuffer); pSendBuffer=NULL;
			return STATUS_UNSUCCESSFUL;

		}
			
	}
	
	dumphex(pSendBuffer, ulSendBufferLen);
	pPacket	=	MakePacketByMem(pSendBuffer, ulSendBufferLen);
	kfree(pSendBuffer); pSendBuffer=NULL;
#ifdef VMPROTECT
	VMProtectEnd();

#endif
	if (!pPacket)
	{

		kprintf("what is going on ,fail from returning MakePacketByMem()\n");
		return STATUS_UNSUCCESSFUL;
	}

	pSendHandler	=	pHI->OldHandler;
	pAdaptContext	=	pHI->pSignContext;
	if (pHI->HandlerSign=='sen1')
	{
		NdisSend(&status, pOpenBlock, pPacket);

		//windbg看了下，发现在系统ndisMSendX调用完网卡的发送回调后，并不关心返回值，mov eax,xxx把eax覆盖了
		_asm
		{
			
// 				push 2		//即使不是使用SendPacketHandler，第3个参数虽然不是个数，但貌似这参数随意
// 				push pPacket
// 				push pAdaptContext
// 				call pSendHandler
		}
	}
	else
	{
		NdisSendPackets(pOpenBlock, &pPacket, 1);
		_asm
		{
			
// 				push 1		//即使不是使用SendPacketHandler，第3个参数虽然不是个数，但貌似这参数随意
// 				lea eax,pPacket
// 				push eax
// 				push pAdaptContext
// 				call pSendHandler
		}
	}
	

	return STATUS_SUCCESS;


}
