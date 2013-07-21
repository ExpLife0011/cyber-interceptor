
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

//注意别在该函数里面HOOK miniport里面的handler
//因为外部会循环调用HookSend，而多个open block可能只对应一个minport
//这样第2次HOOK miniport的时候，可能取到的old handler是第一次HOOK的后留下的new handler
BOOLEAN	HookSendXP(PNDIS_COMMON_OPEN_BLOCK p_open_block)
{


	NDIS_COMMON_OPEN_BLOCK_2k3_early	*pOpen_block_2k3;
	PNDIS_HOOK_INFO	pHI	;
	PULONG	ptmp;


	pHI	=	kmalloc(sizeof(NDIS_HOOK_INFO));
	ptmp=NULL;
	RtlZeroMemory(pHI, sizeof(NDIS_HOOK_INFO));


	pOpen_block_2k3	=	(NDIS_COMMON_OPEN_BLOCK_2k3_early*)p_open_block;
	STARTLOCK(&g_HookInfoLock2, KKRWLOCK_FOR_WRITE);

	if (GetWindowsVersion()==Windows_2K)
	{

		pHI->pReserveContext1	=	pOpen_block_2k3;
		pHI->Address2Restore	=	&(pOpen_block_2k3->send_handler_for_2k);
		pHI->NewHandler	=	my_WSendPacketsHandler;
		pHI->OldHandler	=	pOpen_block_2k3->send_handler_for_2k;
		pHI->HandlerSign	=	'sens';
		pHI->pSignContext	=	pOpen_block_2k3->MiniportAdapterContext;	//需要确认下2K的这个偏移
		pHI->szFuncname	=	"my_WSendPacketsHandler Windows_2K";
		pHI->uHandlerType	=	'send';
		pHI->pMiniBlock		=	(ULONG)pOpen_block_2k3->MiniportHandle;
		pHI->pOpenblock		=	(ULONG)pOpen_block_2k3;
		InsertHeadList(&g_pHookInfoHeader.Next, &pHI->Next);

		ptmp	=	(ULONG*)&(pOpen_block_2k3->send_handler_for_2k);
		*ptmp	=	(ULONG)my_WSendPacketsHandler;


	}
	else
	{

		if (pOpen_block_2k3->WSendPacketsHandler==NULL)
		{

			if (pOpen_block_2k3->WSendHandler==NULL)
			{
				kprintf("wow,something really goes wrong...\n\n");
			}
			pHI->pReserveContext1	=	pOpen_block_2k3;
			pHI->pSignContext	=	pOpen_block_2k3->MiniportAdapterContext;
			pHI->Address2Restore	=	&(pOpen_block_2k3->WSendHandler);
			pHI->NewHandler	=	my_WSendHandler;
			pHI->OldHandler	=	pOpen_block_2k3->WSendHandler;
			pHI->HandlerSign	=	'sen1';	//只有1个packet
			pHI->szFuncname	=	"WSendHandler";
			pHI->pMiniBlock	=	(ULONG)pOpen_block_2k3->MiniportHandle;
			pHI->pOpenblock	=	(ULONG)pOpen_block_2k3;
			pHI->pMiniportAdaptContext	=	(ULONG)pOpen_block_2k3->MiniportAdapterContext;

			InsertHeadList(&g_pHookInfoHeader.Next, &pHI->Next);

			ptmp	=	(ULONG*)&(pOpen_block_2k3->WSendHandler);
			*ptmp	=	(ULONG)my_WSendHandler;
		}
		else
		{
			pHI->pReserveContext1	=	pOpen_block_2k3;
			pHI->pSignContext	=	pOpen_block_2k3->MiniportAdapterContext;
			pHI->Address2Restore	=	&(pOpen_block_2k3->WSendPacketsHandler);
			pHI->NewHandler	=	my_WSendPacketsHandler;
			pHI->OldHandler	=	pOpen_block_2k3->WSendPacketsHandler;
			pHI->HandlerSign	=	'sens';//多个packets
			pHI->szFuncname	=	"WSendPacketsHandler";
			pHI->pMiniBlock	=	(ULONG)pOpen_block_2k3->MiniportHandle;
			pHI->pMiniportAdaptContext	=	(ULONG)pOpen_block_2k3->MiniportAdapterContext;
			pHI->pOpenblock	=	(ULONG)pOpen_block_2k3;
			InsertHeadList(&g_pHookInfoHeader.Next, &pHI->Next);
			kprintf("Hook Openblock 0x%x\n", pOpen_block_2k3);
			ptmp	=	(ULONG*)&(pOpen_block_2k3->WSendPacketsHandler);
			*ptmp	=	(ULONG)my_WSendPacketsHandler;
		}


		pHI->uHandlerType	=	'send';

		//再HOOK send complete 为了支持发送完成的时候释放
		//所以也要把完成函数HOOK了
		pHI	=	kmalloc(sizeof(NDIS_HOOK_INFO));
		pHI->pReserveContext1	=	pOpen_block_2k3;
		pHI->pSignContext	=	pOpen_block_2k3->ProtocolBindingContext;
		pHI->Address2Restore	=	&(pOpen_block_2k3->SendCompleteHandler);
		pHI->NewHandler	=	my_WSendPacketsHandlerComplete;
		pHI->OldHandler	=	pOpen_block_2k3->SendCompleteHandler;
		pHI->HandlerSign	=	'senc';
		pHI->szFuncname	=	"my_WSendPacketsHandlerComplete";
		pHI->pMiniBlock	=	(ULONG)pOpen_block_2k3->MiniportHandle;
		pHI->pMiniportAdaptContext	=	(ULONG)pOpen_block_2k3->MiniportAdapterContext;
		pHI->pOpenblock	=	(ULONG)pOpen_block_2k3;

		InsertHeadList(&g_pHookInfoHeader.Next, &pHI->Next);

		ptmp	=	(ULONG*)&(pOpen_block_2k3->SendCompleteHandler);
		*ptmp	=	(ULONG)my_WSendPacketsHandlerComplete;
		pHI->uHandlerType	=	'senc';


	}
	InterlockedIncrement(&g_pHookInfoHeader.Count);

	//InterlockedIncrementLong(&g_pHookInfoHeader.Count, &g_HookInfoLock);
	ENDLOCK(&g_HookInfoLock2);
	return TRUE;

}
////////////////////////////////////////////////////////////////////////////////

BOOLEAN	HookRecvXP(PNDIS_MINIPORT_BLOCK p_mini_block)
{

	PULONG	ptmp=NULL;
	PNDIS_HOOK_INFO	pHI	=	NULL;

	pHI	=	kmalloc(sizeof(NDIS_HOOK_INFO));
	RtlZeroMemory(pHI, sizeof(NDIS_HOOK_INFO));

	STARTLOCK(&g_HookInfoLock2,KKRWLOCK_FOR_WRITE);


	pHI->Address2Restore	=	&(p_mini_block->PacketIndicateHandler);
	pHI->NewHandler			=	my_ethFilterDprIndicateReceivePacket;
	pHI->OldHandler			=	p_mini_block->PacketIndicateHandler;
	pHI->HandlerSign			=	'recv';
	pHI->uHandlerType	=	'recv';
	pHI->pSignContext		=	p_mini_block;
	pHI->szFuncname			=	"my_ethFilterDprIndicateReceivePacket";
	pHI->pMiniBlock			=	(ULONG)p_mini_block;
	InsertHeadList(&g_pHookInfoHeader.Next,&pHI->Next);

	ptmp	=	(ULONG*)&(p_mini_block->PacketIndicateHandler);
	*ptmp	=	(ULONG)my_ethFilterDprIndicateReceivePacket;
	InterlockedIncrement(&g_pHookInfoHeader.Count);

	pHI	=	kmalloc(sizeof(NDIS_HOOK_INFO));
	pHI->pReserveContext1	=	p_mini_block;
	pHI->pSignContext	=	p_mini_block;
	pHI->Address2Restore	=	&(p_mini_block->SendCompleteHandler);
	pHI->NewHandler	=	my_NdisSendComplete;
	pHI->OldHandler	=	p_mini_block->SendCompleteHandler;
	pHI->HandlerSign	=	'senc';
	pHI->szFuncname	=	"my_NdisSendComplete";
	pHI->pMiniBlock			=	(ULONG)p_mini_block;
	InsertHeadList(&g_pHookInfoHeader.Next, &pHI->Next);

	ptmp	=	(ULONG*)&(p_mini_block->SendCompleteHandler);
	*ptmp	=	(ULONG)my_NdisSendComplete;
	InterlockedIncrement(&g_pHookInfoHeader.Count);
	//ExInterlockedIncrementLong(&g_pHookInfoHeader.Count, &g_HookInfoLock);

	ENDLOCK(&g_HookInfoLock2);
	return TRUE;

}
//////////////////////////////////////////////////////////////////////////

#define MaxHookedMiniports	(0x10)
PNDIS_MINIPORT_BLOCK	g_HookedMiniports[MaxHookedMiniports];
NTSTATUS	DoHookExXP(DWORD uProtocolHeader)
{

	PNDIS_MINIPORT_BLOCK pMiniBlock=NULL;
	ULONG	uIndex	=	0;
	BOOLEAN	bHooked	=	FALSE;
	PKK_NDIS_PROTOCOL_BLOCK	pProtocol	=	(PKK_NDIS_PROTOCOL_BLOCK)uProtocolHeader;
	PNDIS_COMMON_OPEN_BLOCK_2k3_early	pOpenBlock=NULL;
	RtlZeroMemory(g_HookedMiniports, sizeof(g_HookedMiniports));
	if (uProtocolHeader==0)
	{
		return STATUS_UNSUCCESSFUL;
	}
	while (pProtocol)	
	{

		if (pProtocol->OpenQueue==NULL)
		{
			goto __Continue;
		}
		pOpenBlock	=	pProtocol->OpenQueue;

		pMiniBlock	=	pOpenBlock->MiniportHandle;

		if (IsPhysicalMiniport(pMiniBlock)==0)
		{
			goto __Continue;
		}


		//判断是否HOOK过了,
		bHooked	=	FALSE;
		for (uIndex=0; uIndex<MaxHookedMiniports; uIndex++)
		{
			if (g_HookedMiniports[uIndex]==0)
			{
				continue;
			}
			if (g_HookedMiniports[uIndex]==pMiniBlock)
			{
				bHooked	=	TRUE;
				break;
			}
		}
		if (bHooked)
		{
			goto __Continue;
		}
		HookRecvXP(pMiniBlock);
		while(pOpenBlock)
		{
			HookSendXP((PNDIS_COMMON_OPEN_BLOCK)pOpenBlock);
			pOpenBlock	=	pOpenBlock->MiniportNextOpen;
		}
		for (uIndex=0; uIndex<MaxHookedMiniports; uIndex++)
		{
			if (g_HookedMiniports[uIndex]==0)
			{
				//保存进去
				g_HookedMiniports[uIndex]=pMiniBlock;
				break;
			}
		}

__Continue:
		pProtocol	=	pProtocol->NextProtocol;
	}


	return NDIS_STATUS_SUCCESS;
}
//////////////////////////////////////////////////////////////////////////

DWORD	GetProtocolHeaderXP()
{
	NDIS_STATUS                        Status;
	NDIS_PROTOCOL_CHARACTERISTICS      PChars;
	NDIS_HANDLE ProtHandle;
	NDIS_STRING                        Name;
	PKK_NDIS_PROTOCOL_BLOCK			pHeader=NULL;


	//
	// Now register the protocol.
	//
	NdisZeroMemory(&PChars, sizeof(NDIS_PROTOCOL_CHARACTERISTICS));
	PChars.MajorNdisVersion = 4;
	PChars.MinorNdisVersion = 0;

	//
	// Make sure the protocol-name matches the service-name
	// (from the INF) under which this protocol is installed.
	// This is needed to ensure that NDIS can correctly determine
	// the binding and call us to bind to miniports below.
	//
	NdisInitUnicodeString(&Name, L"SUPERCI");    // Protocol name
	PChars.Name = Name;

	// 	PChars.OpenAdapterCompleteHandler = PtOpenAdapterComplete;
	// 	PChars.CloseAdapterCompleteHandler = PtCloseAdapterComplete;
	// 	PChars.SendCompleteHandler = PtSendComplete;
	// 	PChars.TransferDataCompleteHandler = PtTransferDataComplete;
	// 
	// 	PChars.ResetCompleteHandler = PtResetComplete;
	// 	PChars.RequestCompleteHandler = PtRequestComplete;
	// 	PChars.ReceiveHandler = PtReceive;
	// 	PChars.ReceiveCompleteHandler = PtReceiveComplete;
	// 	PChars.StatusHandler = PtStatus;
	// 	PChars.StatusCompleteHandler = PtStatusComplete;
	// 	PChars.BindAdapterHandler = PtBindAdapter;
	// 	PChars.UnbindAdapterHandler = PtUnbindAdapter;
	// 	PChars.UnloadHandler = PtUnloadProtocol;
	// 
	// 	PChars.ReceivePacketHandler = PtReceivePacket;

	PChars.BindAdapterHandler = PtBindAdapter;
	PChars.UnbindAdapterHandler = PtUnbindAdapter;

	//GetReal_NdisRegisterProtocol
	//if NdisRegisterProtocol is hook by eat.
	//we can search ff 15 xxxxxx,it means a long call [xxxxxx] instruction
	NdisRegisterProtocol(&Status,
		&ProtHandle,
		&PChars,
		sizeof(NDIS_PROTOCOL_CHARACTERISTICS));
	if (Status != NDIS_STATUS_SUCCESS||ProtHandle==0)
	{
		return 0;
	}

	pHeader	=	(PKK_NDIS_PROTOCOL_BLOCK)ProtHandle;
	ProtHandle	=	(NDIS_HANDLE)pHeader->NextProtocol;
	NdisDeregisterProtocol(&Status, pHeader);
	if (Status != NDIS_STATUS_SUCCESS)
	{
		kprintf("NdisDeregisterProtocol() fail in ReturnProtocolHeader()\n ");
		return 0;
	}
	return (ULONG)ProtHandle;

}
//////////////////////////////////////////////////////////////////////////
