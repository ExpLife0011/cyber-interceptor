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
#pragma warning(disable:4276)
//////////////////////////////////////////////////////////////////////////



VOID	NetBufferListSinfferCallback(PNET_BUFFER_LIST_KK NetBufferLists, DWORD NumberOfNetBufferLists)
{


	ULONG             NumNbls=0;
	PNET_BUFFER_LIST_KK  Nbl;
	PNET_BUFFER_LIST_KK  NextNbl = NULL;
	PNET_BUFFER_KK NetBuffer;
	ULONG	uNetbuffertLen=0;
	PUCHAR 			 pbuffer=NULL;
	DWORD	dwTmp=0;
	PIO_WORKITEM	pWorkItem	=	NULL;
	PWorkItemContext	pWIC	=NULL;
	PNDIS_OPEN_BLOCKWIN7	OpenQueue=NULL;


	if (g_pNpfProtocolBlockWin7==NULL)
	{
		return ;
	}
	OpenQueue = (PNDIS_OPEN_BLOCKWIN7)g_pNpfProtocolBlockWin7->OpenQueue;
	if (OpenQueue == NULL)
	{
		return ;
		
	}

	if (g_PatchwsVersion==6)
	{
		NetBufferListSinfferCallbackWin7(NetBufferLists, NumberOfNetBufferLists);
		return ;

	}
	//loop over the nbls
	for ( Nbl = NetBufferLists; Nbl!= NULL; Nbl = NextNbl, ++NumNbls)
	{
		//loop over nbs
		for ( NetBuffer = NET_BUFFER_LIST_FIRST_NB(Nbl); NetBuffer != NULL; NetBuffer = NET_BUFFER_NEXT_NB(NetBuffer))
		{
			uNetbuffertLen	=	NET_BUFFER_DATA_LENGTH(NetBuffer);
			pbuffer = (PUCHAR)kmalloc(uNetbuffertLen);
			if(pbuffer==NULL)
			{
				DbgPrint("ExAllocatePoolWithTag for netbuffer memory fail \r\n");
				return;
			}
			NdisZeroMemory(pbuffer,uNetbuffertLen);//清空

			do 
			{
				dwTmp	=	uNetbuffertLen;
				CopyBytesFromNetBuffer(NetBuffer, &dwTmp, pbuffer);
				if (dwTmp!=uNetbuffertLen)
				{
					kprintf("CopyBytesFromNetBuffer() return dwTmp!=uNetbuffertLen dwtmp=%d, uNetbuffertLen=%d\n", dwTmp, uNetbuffertLen);
				}

				pWorkItem = IoAllocateWorkItem(g_CtlDevice);
				if (pWorkItem==NULL)
				{
					kprintf("IoAllocateWorkItem()==NULL\n");
					break;
				}
				pWIC	=	kmalloc(sizeof(WorkItemContext));
				if (pWIC==NULL)
				{
					kprintf("kmalloc(sizeof(WorkItemContext()==NULL\n");
					break;
				}
				pWIC->pBuffer	=	pbuffer;
				pWIC->pWorkItem	=	pWorkItem;
				pWIC->uBufferLen	=	uNetbuffertLen;
				//需要判断上层的协议驱动是什么版本号

				if (g_PatchwsVersion<=5)
				{
					IoQueueWorkItem(pWorkItem, WSWorkThreadWin7ForNdis5, DelayedWorkQueue, pWIC);
					pWorkItem	=NULL;
					pWIC	=	NULL;
				}
				else
				{
					kprintf("fucked\n");
				}
				
			} while (0);

			if (pWIC)
			{
				kfree(pWIC);
			}
			if (pWorkItem)
			{
				IoFreeWorkItem(pWorkItem);
			}
		
			
			//	uNetBuffer_length	=	NET_BUFFER_DATA_LENGTH(NetBuffer);
		}
		NextNbl = NET_BUFFER_LIST_NEXT_NBL(Nbl);
	}

	

}
//////////////////////////////////////////////////////////////////////////
typedef NDIS_STATUS  (*PNdisCopyFromNetBufferToNetBuffer)(
								   __in  PNET_BUFFER_KK         Destination,
								   __in  ULONG               DestinationOffset,
								   __in  ULONG               BytesToCopy,
								   __in  PNET_BUFFER_KK         Source,
								   __in  ULONG               SourceOffset,
								   __out PULONG              BytesCopied
								   );


NDIS_STATUS
MyNdisCopyFromNetBufferToNetBuffer(
								 __in  PNET_BUFFER_KK         Destination,
								 __in  ULONG               DestinationOffset,
								 __in  ULONG               BytesToCopy,
								 __in  PNET_BUFFER_KK         Source,
								 __in  ULONG               SourceOffset,
								 __out PULONG              BytesCopied
								 )
{

	PNET_BUFFER_LIST_KK	pNetList=NULL;
	static PNdisCopyFromNetBufferToNetBuffer	pHandler=NULL;
	UNICODE_STRING	uniRoutineName;
	NDIS_STATUS	ulret=0;

	if (pHandler==NULL)
	{
		RtlInitUnicodeString(&uniRoutineName, L"NdisCopyFromNetBufferToNetBuffer");
		pHandler = (PNdisCopyFromNetBufferToNetBuffer)g_pfnNdisCopyFromNetBufferToNetBuffer;//NdisGetRoutineAddress(&uniRoutineName);
	}
	if (pHandler==NULL)
	{
		kprintf("NdisCopyFromNetBufferToNetBuffer() ....this is fucked\n");
		return STATUS_UNSUCCESSFUL;
	}
	ulret	=pHandler(Destination, DestinationOffset, BytesToCopy, Source, SourceOffset, BytesCopied);


	return ulret ;
	
}

//////////////////////////////////////////////////////////////////////////

VOID	NetBufferListSinfferCallbackWin7(PNET_BUFFER_LIST_KK NetBufferLists, DWORD NumberOfNetBufferLists)
{


	ULONG             NumNbls=0;
	PMDL				pMdl=NULL;
	PNET_BUFFER_LIST_KK  Nbl;
	PNET_BUFFER_LIST_KK  NextNbl = NULL;
	PNET_BUFFER_KK NetBuffer;
	ULONG	uNetbuffertLen=0;
	DWORD	dwTmp=0;
	PIO_WORKITEM	pWorkItem	=	NULL;
	PWorkItemContext	pWIC	=NULL;
	PNET_BUFFER_LIST_KK        pCopyNetBufList;
	PUCHAR                  pCopyBuf;
	ULONG                   TotalLength;
	ULONG                   BytesCopied;
	NTSTATUS				NtStatus	=	STATUS_SUCCESS;
	PNET_BUFFER_LIST_KK	pTmpNetList=NULL;


	//loop over the nbls
	for ( Nbl = NetBufferLists; Nbl!= NULL; Nbl = NextNbl, ++NumNbls)
	{
		//loop over nbs
		for ( NetBuffer = NET_BUFFER_LIST_FIRST_NB(Nbl); NetBuffer != NULL; NetBuffer = NET_BUFFER_NEXT_NB(NetBuffer))
		{

			do 
			{
				pTmpNetList=NULL;

				pMdl = NET_BUFFER_CURRENT_MDL(NetBuffer);
				TotalLength = NET_BUFFER_DATA_LENGTH(NetBuffer);
// 				Offset = NET_BUFFER_CURRENT_MDL_OFFSET(NetBuffer);
// 				BufferLength = 0;

				pTmpNetList = AllocateNetBufferList(TotalLength, &pCopyBuf);

				if (pTmpNetList==NULL)
				{
					break;
				}
				pCopyNetBufList	=	pTmpNetList;
				NtStatus = MyNdisCopyFromNetBufferToNetBuffer(NET_BUFFER_LIST_FIRST_NB(pCopyNetBufList),
					0,
					TotalLength,
					NetBuffer,
					0,
					&BytesCopied);


				if (NtStatus != STATUS_SUCCESS)
				{
					kprintf("NdisCopyFromNetBufferToNetBuffer() fail\n");
					break;   
				}

				pWorkItem = IoAllocateWorkItem(g_CtlDevice);
				if (pWorkItem==NULL)
				{
					kprintf("IoAllocateWorkItem()==NULL\n");
					break;
				}
				pWIC	=	kmalloc(sizeof(WorkItemContext));
				if (pWIC==NULL)
				{
					kprintf("kmalloc(sizeof(WorkItemContext()==NULL\n");
					break;
				}
				pWIC->pBuffer	=	(PVOID)pCopyNetBufList;
				pWIC->pWorkItem	=	pWorkItem;
				pWIC->uBufferLen	=	uNetbuffertLen;

				IoQueueWorkItem(pWorkItem, WSWorkThreadWin7, DelayedWorkQueue, pWIC);
				pWorkItem	=NULL;
				pWIC	=	NULL;
				pTmpNetList=NULL;

			} while (0);
			if (pTmpNetList!=NULL)
			{
				FreeNetBufferList(pTmpNetList);
			}
			if (pWIC)
			{
				kfree(pWIC);
			}
			if (pWorkItem)
			{
				IoFreeWorkItem(pWorkItem);
			}

		}
		NextNbl = NET_BUFFER_LIST_NEXT_NBL(Nbl);
	}

}


//////////////////////////////////////////////////////////////////////////


//wireshark这个模块就不自己建线程了，就直接用系统的workitem就好了
VOID	WSWorkThreadWin7(PDEVICE_OBJECT  DeviceObject, PVOID	pContext)
{
	NTSTATUS	status=STATUS_SUCCESS;
	#define NDIS_RECEIVE_FLAGS_RESOURCES 0x00000002
	DWORD	dwRecvflags	=	NDIS_RECEIVE_FLAGS_RESOURCES;
	PWorkItemContext	pWIC	=NULL;
	PNDIS_PACKET		pPacket	=NULL;
	DWORD				ProtocolBindingContext=0;
	PNDIS_OPEN_BLOCKWIN7 OpenQueue=NULL;
	KIRQL				CIrql,CIrql2;


	CIrql=CIrql2=0;
	CIrql	=	KeGetCurrentIrql();
	pWIC		=(PWorkItemContext)pContext;

	do 
	{

		if (pWIC==NULL)
		{
			break;
		}

		if (OpenQueue = (PNDIS_OPEN_BLOCKWIN7)g_pNpfProtocolBlockWin7->OpenQueue)
		{
			ProtocolBindingContext	=	(DWORD)OpenQueue->ProtocolBindingContext;
		}
		else
		{
			break;
		}
		if (ProtocolBindingContext==0)
		{
			break;
		}

/*
VOID
NdisprotReceiveNetBufferLists(
IN NDIS_HANDLE                  ProtocolBindingContext,
IN PNET_BUFFER_LIST             pNetBufferLists,
IN NDIS_PORT_NUMBER             PortNumber,
IN ULONG                        NumberOfNetBufferLists,
IN ULONG                        ReceiveFlags
)
*/

		//向上提交
		NewReceiveNetBufferListsHandler(ProtocolBindingContext, (DWORD)pWIC->pBuffer, 0, 1, dwRecvflags);
		
		kprintf("after call NewReceiveNetBufferListsHandler(),irql=%d\n",KeGetCurrentIrql());
		break;

	}while(0);
	

	//恢复IRQL
	if (KeGetCurrentIrql()>CIrql)
	{
		KeLowerIrql(CIrql);
	}
	if (KeGetCurrentIrql()<CIrql)
	{
		KeRaiseIrql(CIrql, &CIrql2);
	}
	if (pWIC)
	{

		if (pWIC->pBuffer)
		{
			FreeNetBufferList(pWIC->pBuffer);
		}
		if (pWIC->pWorkItem)
		{
			IoFreeWorkItem(pWIC->pWorkItem);
		}
		kfree(pWIC);
	}
	return ;





}
//////////////////////////////////////////////////////////////////////////
//NDIS5的驱动跑在WIN7下
VOID	WSWorkThreadWin7ForNdis5(PDEVICE_OBJECT  DeviceObject, PVOID	pContext)
{
	NTSTATUS	status=STATUS_SUCCESS;
	ULONG		pHeaderBuffer, HeaderBufferSize, pLookaheadBuffer,LookaheadBufferSize,PacketSize;

	PWorkItemContext	pWIC	=NULL;
	PNDIS_PACKET		pPacket	=NULL;
	ULONG				ProtocolBindingContext=0;
	PNDIS_OPEN_BLOCKWIN7 OpenQueue=NULL;
	KIRQL				CIrql,CIrql2;

	CIrql=CIrql2=0;
	CIrql	=	KeGetCurrentIrql();
	pWIC		=(PWorkItemContext)pContext;
	do 
	{

		if (pWIC==NULL)
		{
			break;
		}

		if (OpenQueue = (PNDIS_OPEN_BLOCKWIN7)g_pNpfProtocolBlockWin7->OpenQueue)
		{
			ProtocolBindingContext	=	(ULONG)OpenQueue->ProtocolBindingContext;
		}
		else
		{
			break;
		}

		//Receive Packet Handler Available
		if (g_NPFReceivePacketHandler)
		{
			pPacket	=	MakePacketByMem(pWIC->pBuffer, pWIC->uBufferLen);
			if (pPacket==NULL)
			{
				break;
			}

			NDIS_SET_PACKET_STATUS(pPacket, NDIS_STATUS_RESOURCES);

			__asm
			{
				//提上去给wireshark
					push pPacket
					push ProtocolBindingContext
					call NewNPFReceivePacketHandler
			}

		}
		else//fuck
		{
			pHeaderBuffer	=	(ULONG)pWIC->pBuffer;
			HeaderBufferSize	=	sizeof(Dlc_Header);
			pLookaheadBuffer	=	pHeaderBuffer+HeaderBufferSize;
			LookaheadBufferSize	=	PacketSize	=	pWIC->uBufferLen-HeaderBufferSize;

			_asm
			{
					push PacketSize
					push LookaheadBufferSize
					push pLookaheadBuffer
					push HeaderBufferSize
					push pHeaderBuffer
					push 0	//mac context，用不上
					push ProtocolBindingContext
					mov  eax, NewNPFReceiveHandler
					call eax
			}

		}
	} while (0);

	if (pPacket)
	{
		FreePacket(pPacket);
	}
	if (pWIC)
	{
		if (pWIC->pBuffer)
		{
			kfree(pWIC->pBuffer);
		}
		if (pWIC->pWorkItem)
		{
			IoFreeWorkItem(pWIC->pWorkItem);
		}
		kfree(pWIC);
	}

	if (KeGetCurrentIrql()>CIrql)
	{
		KeLowerIrql(CIrql);
	}
	if (KeGetCurrentIrql()<CIrql)
	{
		KeRaiseIrql(CIrql, &CIrql2);
	}

	return ;


}