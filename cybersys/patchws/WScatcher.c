
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
//wireshark这个模块就不自己建线程了，就直接用系统的workitem就好了
//所以下面变量暂时不用
KSPIN_LOCK	g_WSPacketListLock;
WSPacketList	g_WSPacketList;//just a header,not a available node
KEVENT			g_WSPacketListEvent;


//////////////////////////////////////////////////////////////////////////

VOID	WSCatcherPacketCallback(PVOID pb)
{
	PNDIS_PACKET	pPacket	=	(PNDIS_PACKET)pb;
	ULONG			uPacketLen	=0, ulbytes_copied=0;
	PUCHAR			pBuffer	=	NULL;
	PIO_WORKITEM	pWorkItem	=	NULL;
	PWorkItemContext	pWIC	=NULL;


	if (!g_bAlreadyPatchWS)
	{
		return ;
	}
	if (g_pNpfProtocolBlock==NULL)
	{
		kprintf("g_pNpfProtocolBlock==NULL in WSCatcherPacketCallback()\n");
		return;
	}
	do 
	{
		
		NdisQueryPacketLength(pPacket, &uPacketLen);

		if (uPacketLen<sizeof(Dlc_Header))//
		{
			//less than eth header,bufer too small,ignore
			return ;
		}
		pBuffer	=	kmalloc(uPacketLen);
		GetPktPayload(pPacket, pBuffer, uPacketLen, &ulbytes_copied);
		if (g_CtlDevice==NULL)
		{
			kprintf("g_CtlDevice==NULL\n");
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
		pWIC->pBuffer	=	pBuffer;
		pWIC->pWorkItem	=	pWorkItem;
		pWIC->uBufferLen	=	uPacketLen;

		IoQueueWorkItem(pWorkItem, WSWorkThread, DelayedWorkQueue, pWIC);
		pBuffer	=NULL;//pBuffer在workitem中再释放
		pWorkItem	=NULL;
		pWIC	=	NULL;
	
	} while (0);
	if (pBuffer!=NULL)
	{
		kfree(pBuffer);
	}
	if (pWIC)
	{
		kfree(pWIC);
	}
	if (pWorkItem)
	{
		IoFreeWorkItem(pWorkItem);
	}
	return ;

}

//////////////////////////////////////////////////////////////////////////

//wireshark这个模块就不自己建线程了，就直接用系统的workitem就好了
VOID	WSWorkThread(PDEVICE_OBJECT  DeviceObject, PVOID	pContext)
{
	NTSTATUS	status=STATUS_SUCCESS;
	ULONG		pHeaderBuffer, HeaderBufferSize, pLookaheadBuffer,LookaheadBufferSize,PacketSize;

	PWorkItemContext	pWIC	=NULL;
	PNDIS_PACKET		pPacket	=NULL;
	ULONG				ProtocolBindingContext=0;
	PNDIS_COMMON_OPEN_BLOCK_2k3_early OpenQueue=NULL;
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
	
		if (OpenQueue = g_pNpfProtocolBlock->OpenQueue)
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

