
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

DWORD	g_u_recv_offset_in_miniport_vista_later=0x19c;
DWORD	g_u_send_offset_in_miniport_vista	=	0xa00;
DWORD	g_u_send_offset_in_miniport_win7	=	0xe04;


//////////////////////////////////////////////////////////////////////////

VOID
NdisProtOpenAdapterComplete(
							IN NDIS_HANDLE                  ProtocolBindingContext,
							IN NDIS_STATUS                  Status,
							IN NDIS_STATUS                  OpenErrorCode
							)
{

	UNREFERENCED_PARAMETER(Status);
	UNREFERENCED_PARAMETER(ProtocolBindingContext);
	UNREFERENCED_PARAMETER(OpenErrorCode);
}

VOID
NdisProtCloseAdapterComplete(
							 IN NDIS_HANDLE                  ProtocolBindingContext,
							 IN NDIS_STATUS                  Status
							 )
{

	UNREFERENCED_PARAMETER(Status);
	UNREFERENCED_PARAMETER(ProtocolBindingContext);

}
//////////////////////////////////////////////////////////////////////////

NDIS_STATUS
NdisprotUnbindAdapterWin7(
    IN NDIS_HANDLE                  UnbindContext,
    IN NDIS_HANDLE                  ProtocolBindingContext
    )
/*++

Routine Description:

    NDIS calls this when it wants us to close the binding to an adapter.

Arguments:

    ProtocolBindingContext - pointer to open context structure
    UnbindContext - to use in NdisCompleteUnbindAdapter if we return pending

Return Value:

    pending or success

--*/
{

	UNREFERENCED_PARAMETER(UnbindContext);
	UNREFERENCED_PARAMETER(ProtocolBindingContext);

    return NDIS_STATUS_SUCCESS;
}
//////////////////////////////////////////////////////////////////////////
NDIS_STATUS
NdisprotBindAdapter(
					IN NDIS_HANDLE                  ProtocolDriverContext,
					IN NDIS_HANDLE                  BindContext,
					IN NDIS_HANDLE        BindParameters
					)
{

	UNREFERENCED_PARAMETER(ProtocolDriverContext);
	UNREFERENCED_PARAMETER(BindContext);
	UNREFERENCED_PARAMETER(BindParameters);

	return NDIS_STATUS_SUCCESS;
}
//////////////////////////////////////////////////////////////////////////
DWORD	GetProtocolHeaderWin7()
{


	NDIS_STATUS                        Status;
	NDIS50_PROTOCOL_CHARACTERISTICS_WIN7      PChars;
	NDIS_HANDLE ProtHandle;
	NDIS_STRING                        Name;
	PNDIS_PROTOCOL_BLOCKWin7			pHeader=NULL;


	//
	// Now register the protocol.
	//
	NdisZeroMemory(&PChars, sizeof(NDIS50_PROTOCOL_CHARACTERISTICS_WIN7));
	PChars.Ndis40Chars.MajorNdisVersion = 5;
	PChars.Ndis40Chars.MinorNdisVersion = 0;

	//
	// Make sure the protocol-name matches the service-name
	// (from the INF) under which this protocol is installed.
	// This is needed to ensure that NDIS can correctly determine
	// the binding and call us to bind to miniports below.
	//
	NdisInitUnicodeString(&Name, L"SUPERCI");    // Protocol name
	PChars.Ndis40Chars.Name = Name;

	PChars.Ndis40Chars.OpenAdapterCompleteHandler = NdisProtOpenAdapterComplete;
	PChars.Ndis40Chars.CloseAdapterCompleteHandler = NdisProtCloseAdapterComplete;
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

	PChars.Ndis40Chars.BindAdapterHandler = PtBindAdapter;
	PChars.Ndis40Chars.UnbindAdapterHandler = PtUnbindAdapter;

	//GetReal_NdisRegisterProtocol
	//if NdisRegisterProtocol is hook by eat.
	//we can search ff 15 xxxxxx,it means a long call [xxxxxx] instruction
	NdisRegisterProtocol(&Status,
		&ProtHandle,
		(PNDIS_PROTOCOL_CHARACTERISTICS)&PChars,
		sizeof(NDIS50_PROTOCOL_CHARACTERISTICS_WIN7));
	if (Status != NDIS_STATUS_SUCCESS||ProtHandle==0)
	{
		return 0;
	}

	pHeader	=	(PNDIS_PROTOCOL_BLOCKWin7)ProtHandle;
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

//////////////////////////////////////////////////////////////////////////
VOID	HookRecvWin7(ULONG_PTR	mini_block)
{

	PDWORD	ptmp;
	PNDIS_HOOK_INFO	pHI	;
	PNDIS_MINIPORT_BLOCK	p_mini_block	=	(PNDIS_MINIPORT_BLOCK)mini_block;
	pHI	=	kmalloc(sizeof(NDIS_HOOK_INFO));
	ptmp=NULL;
	RtlZeroMemory(pHI, sizeof(NDIS_HOOK_INFO));

	pHI->Address2Restore	=	(PVOID)(mini_block+g_u_recv_offset_in_miniport_vista_later);
	pHI->OldHandler			=	(PVOID)*(PDWORD)(mini_block+g_u_recv_offset_in_miniport_vista_later);

	//替换
	*(PDWORD)(mini_block+g_u_recv_offset_in_miniport_vista_later)	=	(DWORD)KKNdisMIndicateReceiveNetBufferListsInternal_vista_later;
	pHI->uHandlerType	=	'recv';
	pHI->HandlerSign	=	'recs';
	pHI->pMiniBlock		=	mini_block;
	pHI->szFuncname		=	"KKNdisMIndicateReceiveNetBufferListsInternal_vista_later";
	pHI->NewHandler		=	KKNdisMIndicateReceiveNetBufferListsInternal_vista_later;
	pHI->pSignContext	=	(PVOID)mini_block;

	STARTLOCK(&g_HookInfoLock2, KKRWLOCK_FOR_WRITE);

	InsertHeadList(&g_pHookInfoHeader.Next, &pHI->Next);

	InterlockedIncrement(&g_pHookInfoHeader.Count);

	ENDLOCK(&g_HookInfoLock2);
	return ;
}

//////////////////////////////////////////////////////////////////////////

VOID	HookSendWIN7(ULONG_PTR	mini_block)
{
	PDWORD	ptmp;
	PNDIS_HOOK_INFO	pHI	;
	PNDIS_MINIPORT_BLOCK	pMiniBLock=NULL;

	pMiniBLock	=	(PNDIS_MINIPORT_BLOCK)mini_block;
	pHI	=	kmalloc(sizeof(NDIS_HOOK_INFO));
	ptmp=NULL;
	RtlZeroMemory(pHI, sizeof(NDIS_HOOK_INFO));

	if (GetWindowsVersion()==Windows_Vista)
	{
		ptmp	=	(PDWORD)(mini_block+g_u_send_offset_in_miniport_vista);
	}
	if (GetWindowsVersion()==Windows_7)
	{
		ptmp	=	(PDWORD)(mini_block+g_u_send_offset_in_miniport_win7);
	}

	ptmp	=	(PDWORD)*ptmp;	//_NDIS_M_DRIVER_BLOCK
	ptmp	=	(PDWORD)((DWORD)ptmp+0x60);



	pHI->uHandlerType	=	'send';

	//再HOOK send complete 为了支持发送完成的时候释放
	//所以也要把完成函数HOOK了
	pHI	=	kmalloc(sizeof(NDIS_HOOK_INFO));

	pHI->pSignContext	=	pMiniBLock->MiniportAdapterContext;
	pHI->Address2Restore	=	ptmp;
	pHI->NewHandler	=	KKMPSendNetBufferLists;
	pHI->OldHandler	=	(PVOID)*ptmp;
	pHI->HandlerSign	=	'senc';
	pHI->szFuncname	=	"KKMPSendNetBufferLists";
	pHI->pMiniBlock	=	mini_block;
	pHI->pMiniportAdaptContext	=	(ULONG_PTR)pMiniBLock->MiniportAdapterContext;


	*ptmp	=	(DWORD)KKMPSendNetBufferLists;
	pHI->uHandlerType	=	'sens';


	STARTLOCK(&g_HookInfoLock2, KKRWLOCK_FOR_WRITE);

	InsertHeadList(&g_pHookInfoHeader.Next, &pHI->Next);

	InterlockedIncrement(&g_pHookInfoHeader.Count);

	ENDLOCK(&g_HookInfoLock2);

}


//////////////////////////////////////////////////////////////////////////
#define MaxHookedMiniports	(0x10)
PNDIS_MINIPORT_BLOCK	g_HookedMiniports[MaxHookedMiniports];


NTSTATUS	DoHookExWin7(DWORD uProtocolHeader)
{
	NTSTATUS	status	=	STATUS_SUCCESS;
	PNDIS_PROTOCOL_BLOCKWin7	pProtocol=(PNDIS_PROTOCOL_BLOCKWin7)uProtocolHeader;
	PNDIS_OPEN_BLOCKWIN7	pOpenBlock=NULL;
	PNDIS_MINIPORT_BLOCK	pMiniBlock=NULL;
	ULONG	uIndex	=	0;
	BOOLEAN	bHooked	=	FALSE;

	RtlZeroMemory(g_HookedMiniports, sizeof(g_HookedMiniports));
	if (uProtocolHeader==0)
	{
		return STATUS_UNSUCCESSFUL;
	}

	do 
	{

		while (pProtocol)	
		{

			if (pProtocol->OpenQueue==0)
			{
				goto __Continue;
			}
			pOpenBlock	=	(PNDIS_OPEN_BLOCKWIN7)pProtocol->OpenQueue;

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
			//windows 7下，物理网卡的miniport 肯定是6.0版本的，所以不需要过滤
			HookRecvWin7((ULONG_PTR)pMiniBlock);
		
			HookSendWIN7((ULONG_PTR)pMiniBlock);
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
			pProtocol	=	(PNDIS_PROTOCOL_BLOCKWin7)pProtocol->NextProtocol;
		}


	} while (0);





	return status;

}