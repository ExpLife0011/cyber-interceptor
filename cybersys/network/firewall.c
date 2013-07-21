
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
//ȫ�ֱ�����
NDIS_HOOK_INFO	g_HookTcpipFireWallList;
NDIS_RW_LOCK	g_HookTcpipFireWallLock;		//�����������д��

AcceptedPort	g_AcceptedPortListHeader;	//����ڵ�Ƚ϶�Ļ������Ǵ�lookside������
//KSPIN_LOCK		g_AcceptedPortListLock;
NDIS_RW_LOCK	g_AcceptedPortListLock2;		//�����������д��



LIST_ENTRY		g_AskUserConnectListHeader;
KSPIN_LOCK		g_AskUserConnectListLock;

ULONG			g_InterceptTCPIPRcv	=	0;
ULONG			g_AlreadyHookTCPIP	=	0;

//////////////////////////////////////////////////////////////////////////
//��ʼ��
NTSTATUS	InitFW()
{

	InitializeListHead(&g_AcceptedPortListHeader.Next);
	NdisInitializeReadWriteLock(&g_AcceptedPortListLock2);	//ʹ�ù����������д��


	InitializeListHead(&g_AskUserConnectListHeader);
	KeInitializeSpinLock(&g_AskUserConnectListLock);


	InitializeListHead(&g_HookTcpipFireWallList.Next);
	NdisInitializeReadWriteLock(&g_HookTcpipFireWallLock);

	return STATUS_SUCCESS;
}
//////////////////////////////////////////////////////////////////////////
NTSTATUS	UninitFW()
{

	FWUnhookTcpipRecvHandler();
	FWReleasePortRuleList();

	return STATUS_SUCCESS;

}
//ʧ�ܷ���0
ULONG	GetTcpipProtocolBlock()
{

	UNICODE_STRING	uniTCPIP;
	ULONG			uHeader=0;
	NTSTATUS		status = STATUS_SUCCESS;
	struct my_NDIS_PROTOCOL_BLOCK	*pProtoBLock=NULL;
	BOOLEAN			bFound	=	FALSE;
	struct my_NDIS_PROTOCOL_BLOCK	*pTcpipProtocolBlock=NULL;
	do 
	{
		RtlInitUnicodeString(&uniTCPIP, L"tcpip");
		uHeader	=	GetProtocolHeader();
		if (uHeader==0)
		{
			status	=	STATUS_UNSUCCESSFUL;
			break;
		}
		pProtoBLock	=	(struct my_NDIS_PROTOCOL_BLOCK	*)uHeader;
		while(pProtoBLock)
		{
			if (RtlEqualUnicodeString(&pProtoBLock->ProtocolCharacteristics.Ndis40Chars.Name, &uniTCPIP,TRUE))
			{
				bFound	=	TRUE;
				break;
			}
			pProtoBLock	=	pProtoBLock->NextProtocol;
		}

		if (!bFound)
		{
			kprintf("Can not find tcpip.sys by its protocol name: tcpip\n");
			break;
		}
		pTcpipProtocolBlock	=	pProtoBLock;

		//NdisDeregisterProtocol(&status, (NDIS_HANDLE)uHeader);	// deregister it


	} while (0);

	return (ULONG)pTcpipProtocolBlock;

}
//////////////////////////////////////////////////////////////////////////
__inline PVOID	GetTcpipArpRcvOldHandler(PVOID pSgin,PVOID pNewHandler);
PVOID	GetTcpipArpRcvOldHandler(PVOID pSgin,PVOID pNewHandler)
{
	LIST_ENTRY			*pNextHook	=NULL;
	PNDIS_HOOK_INFO		pHI			=NULL;
	PVOID				uHandler	=0;
	//DbgBreakPoint();
	PLOCK_STATE	pLockState1=NULL;

	pLockState1	=	kmalloc(sizeof(LOCK_STATE));
	NdisAcquireReadWriteLock(&g_HookTcpipFireWallLock, KKRWLOCK_FOR_READ, pLockState1);


	pNextHook =	g_HookTcpipFireWallList.Next.Flink;
	while (pNextHook != &g_HookTcpipFireWallList.Next)
	{
		if (pNextHook)
		{
			pHI = CONTAINING_RECORD(pNextHook, NDIS_HOOK_INFO, Next);
			if (pHI->NewHandler	==	pNewHandler&& pHI->OldHandler!=NULL)
			{
				//���ͬһ��newhandler ��Ӧ���oldhandler����������
				if (pHI->pSignContext==pSgin)
				{
					uHandler=  pHI->OldHandler;
					goto __find_OldHandler;
				}

			}
			pNextHook	=	pNextHook->Flink;

		}
		else
		{
			kprintf("GetTcpipArpRcvOldHandler ()  what the fuck??!!!\n");
			
		}
	}
__find_OldHandler:
	if (pLockState1)
	{
		NdisReleaseReadWriteLock(&g_HookTcpipFireWallLock, pLockState1);
		kfree(pLockState1);
	}

	return uHandler;

}
//////////////////////////////////////////////////////////////////////////
NDIS_STATUS
BypassTcpipArpRcv(
				 IN  NDIS_HANDLE         ProtocolBindingContext,
				 IN  NDIS_HANDLE         MacReceiveContext,
				 IN  PVOID               HeaderBuffer,
				 IN  UINT                HeaderBufferSize,
				 IN  PVOID               LookAheadBuffer,
				 IN  UINT                LookAheadBufferSize,
				 IN  UINT                PacketSize
				 )
{

	PVOID	uHandler	=0;
	NDIS_STATUS	status =STATUS_SUCCESS;

	uHandler	=	GetTcpipArpRcvOldHandler((PVOID)ProtocolBindingContext, (PVOID)KKNewTcpipArpRcv);
	if (uHandler==0)
	{
		DbgBreakPoint();
	}
	_asm
	{
		push PacketSize
		push LookAheadBufferSize
		push LookAheadBuffer
		push HeaderBufferSize
		push HeaderBuffer
		push MacReceiveContext
		push ProtocolBindingContext
		call uHandler
		mov status,eax
	}

	return status;
}
//////////////////////////////////////////////////////////////////////////

__inline	BOOLEAN	CheckIsSynConnectPacket(PVOID	pBuffer)
{
	Tcp_Header	*pTcpHdr	=	NULL;

	pTcpHdr	=	(Tcp_Header	*)pBuffer;

#define TCPSYN	(0x02)

	return (pTcpHdr->flags==TCPSYN);


}
//////////////////////////////////////////////////////////////////////////
BOOLEAN	FindPort(USHORT uPort, PortStatus	*PStatus)
{
	BOOLEAN	bFound	=	FALSE;
	
	LIST_ENTRY	*pNext	=NULL;
	AcceptedPort	*pAPort	=NULL;
	PLOCK_STATE	pLockState1=NULL;
	
	pLockState1	=	kmalloc(sizeof(LOCK_STATE));
	NdisAcquireReadWriteLock(&g_AcceptedPortListLock2, KKRWLOCK_FOR_READ, pLockState1);
	pNext	=	g_AcceptedPortListHeader.Next.Flink;
	while(pNext&&(pNext!=&g_AcceptedPortListHeader.Next))
	{
		pAPort	=	CONTAINING_RECORD(pNext, AcceptedPort, Next);
		if (pAPort==NULL)
		{
			DbgBreakPoint();
		}
		if (pAPort->uPort==uPort)
		{
			bFound	=	TRUE;
			*PStatus	=	pAPort->PStatus;
			break;
		}
		pNext	=	pNext->Flink;
	}
	NdisReleaseReadWriteLock(&g_AcceptedPortListLock2, pLockState1);
	kfree(pLockState1);
	return bFound;
}
//////////////////////////////////////////////////////////////////////////
//ȡ��pendding��IRP������ɣ��û����첽�õ�֪ͨ
VOID	AskUserWorker(PDEVICE_OBJECT  DeviceObject, PVOID	pContext)
{

	PIO_WORKITEM	pWorkItem	=	NULL;
	PASKUserWorkItemContext	pAskContext	=NULL;
	PIRP		Irp=NULL;
	PLIST_ENTRY	pListEntry=NULL;
	NTSTATUS			Status = STATUS_SUCCESS;
	PIO_STACK_LOCATION	irpStack;
	PVOID				ioBuf;
	ULONG				inBufLength, outBufLength;
	PFIREWALL_ASKUSER	pFireAskUser=NULL;
	KIRQL				CIrql,CIrql2;
	CIrql=CIrql2=0;

	CIrql	=	KeGetCurrentIrql();

	pAskContext	=	(PASKUserWorkItemContext)pContext;
	do 
	{
		if (pAskContext==NULL)
		{
			break;
		}
		while(!IsListEmpty(&g_AskUserConnectListHeader))
		{

			//find a pendding irp 2 ask user decision
			pListEntry	=	ExInterlockedRemoveHeadList(&g_AskUserConnectListHeader, &g_AskUserConnectListLock);
			Irp = CONTAINING_RECORD(pListEntry, IRP, Tail.Overlay.ListEntry);		
			break;

		}
		if (Irp==NULL)
		{
			break;
		}

		irpStack = IoGetCurrentIrpStackLocation(Irp);

		ioBuf = Irp->AssociatedIrp.SystemBuffer;
		inBufLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
		outBufLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

		pFireAskUser	=	(PFIREWALL_ASKUSER)ioBuf;
		//��DST��SRC IP��PORT����ȥ�������ٴ�����
		//let ring3 know what the port is asking for permission
		*pFireAskUser	=	*(PFIREWALL_ASKUSER)pAskContext->pContext;
		Status = STATUS_SUCCESS;
		Irp->IoStatus.Status = Status;
		Irp->IoStatus.Information	=	sizeof(FIREWALL_ASKUSER);
		IoCompleteRequest(Irp, IO_NO_INCREMENT);

	} while (0);
	if (pAskContext)
	{
		IoFreeWorkItem(pAskContext->pWorkItem);
		kfree(pAskContext->pContext);
		kfree(pAskContext);

	}
	if (KeGetCurrentIrql()>CIrql)
	{
		KeLowerIrql(CIrql);
	}
	if (KeGetCurrentIrql()<CIrql)
	{
		KeRaiseIrql(CIrql, &CIrql2);
	}

}
//////////////////////////////////////////////////////////////////////////
NDIS_STATUS
KKNewTcpipArpRcv(
		  IN  NDIS_HANDLE         ProtocolBindingContext,
		  IN  NDIS_HANDLE         MacReceiveContext,
		  IN  PVOID               HeaderBuffer,
		  IN  UINT                HeaderBufferSize,
		  IN  PVOID               LookAheadBuffer,
		  IN  UINT                LookAheadBufferSize,
		  IN  UINT                PacketSize
		  )
{

	Tcp_Header	*pTcpHdr	=	NULL;
	Ip_Header	*pIPHdr		=	NULL;
	Dlc_Header	*pDlcHdr		=	NULL;
	NTSTATUS		status	=	STATUS_SUCCESS;
	PortStatus		PStatus;
	BOOLEAN			bFound	=	FALSE;
	
	//�����أ�ֱ��bypass
	if (g_InterceptTCPIPRcv==0)
	{
		goto __BypassTcpipArpRcv;
	}

	if (HeaderBufferSize!=sizeof(Dlc_Header))
	{

		goto __BypassTcpipArpRcv;
	}
	if (
		LookAheadBufferSize<=(sizeof(Tcp_Header)+sizeof(Ip_Header))
		)
	{
		//������TCP���������ˣ�Ҳ��transfdata��
		goto __BypassTcpipArpRcv;
	}



	pDlcHdr	=	(Dlc_Header	*)HeaderBuffer;
	pIPHdr	=	(Ip_Header	*)LookAheadBuffer;
	pTcpHdr	=	(Tcp_Header	*) ((PUCHAR)LookAheadBuffer	+	sizeof(Ip_Header));
	if (pDlcHdr->ethertype!=ntohs(ETHPROTO_IP))
	{
		kprintf("KKNewTcpipArpRcv(),ethertype!= ETHPROTO_IP\n");
		goto __BypassTcpipArpRcv;
	}
	if (pIPHdr->proto!=IPPROTO_TCP)
	{
		goto __BypassTcpipArpRcv;;
	}
	if (
		LookAheadBufferSize>=(sizeof(Tcp_Header)+sizeof(Ip_Header)+20)
		)
	{
		//̫���ˣ��϶�����syn��
		goto __BypassTcpipArpRcv;
	}
	if (!CheckIsSynConnectPacket(pTcpHdr))
	{
		goto __BypassTcpipArpRcv;
	}
	
	bFound	=	FindPort(ntohs(pTcpHdr->dstport), &PStatus);
	if (bFound)
	{
		//�ҵ���˵�������ڴ������ߴ������
		if (PStatus==PortAccept)
		{
			kprintf("Port:%d accepted\n", ntohs(pTcpHdr->dstport));
			goto __BypassTcpipArpRcv;
		}
		if (PStatus==PortDeny)
		{
			kprintf("Port:%d PortDeny\n", ntohs(pTcpHdr->dstport));
		}
		goto	__DROP;	//deny�϶�Ҫdrop,unkown�Ļ���˵�����ڷ����û���Ҳdrop
	}
	else
	{
		//û�ҵ����Ǿ͵õ�����ѯ���û���
		//�Ȱ�����˿ڼӵ�������
		AcceptedPort	*pAPort	=NULL;
		PIO_WORKITEM	pWorkItem	=	NULL;
		PASKUserWorkItemContext	pAskContext	=NULL;
		PLOCK_STATE	pLockState1=NULL;
		PFIREWALL_ASKUSER	pFAS=NULL;

		pLockState1	=	kmalloc(sizeof(LOCK_STATE));
		pWorkItem = IoAllocateWorkItem(g_CtlDevice);
		pAskContext	=	kmalloc(sizeof(ASKUserWorkItemContext));
		pFAS		=	kmalloc(sizeof(FIREWALL_ASKUSER));
		pAPort	=	kmalloc(sizeof(AcceptedPort));
		pAPort->uPort	=	ntohs(pTcpHdr->dstport);
		pAPort->PStatus	=	PortUnknow;
		pAskContext->pWorkItem	=	pWorkItem;
		
		pAskContext->pContext	=	(PVOID)pFAS;
		pAPort->ProtocolBindingContext	=	(ULONG_PTR)ProtocolBindingContext;
		pAPort->MacReceiveContext		=	(ULONG_PTR)MacReceiveContext;
		RtlMoveMemory(pAPort->cMacSrcDst, HeaderBuffer, sizeof(pAPort->cMacSrcDst));
		pAPort->SrcIP	=	pIPHdr->sourceIP;
		pAPort->DstIP	=	pIPHdr->destIP;	//�����Щ��Ϣ,�������������syn��ʱ�����õ�
		
		pFAS->DstIP		=	pAPort->DstIP;
		pFAS->SrcIP		=	pAPort->SrcIP;
		pFAS->uPort		=	pAPort->uPort;
		//ֱ�ӱ��������������ύ��ʱ��ֱ�����Ͻ������ˣ������Լ����
		pAPort->HeaderBufferSize	=	HeaderBufferSize;
		RtlMoveMemory(pAPort->HeaderBuffer, HeaderBuffer, HeaderBufferSize);
		pAPort->LookAheadBufferSize	=	LookAheadBufferSize;
		RtlMoveMemory(pAPort->LookAheadBuffer, LookAheadBuffer, LookAheadBufferSize);
		NdisAcquireReadWriteLock(&g_AcceptedPortListLock2, KKRWLOCK_FOR_WRITE, pLockState1);
		InsertHeadList(&g_AcceptedPortListHeader.Next, &pAPort->Next);
		NdisReleaseReadWriteLock(&g_AcceptedPortListLock2, pLockState1);
		kfree(pLockState1);
		IoQueueWorkItem(pWorkItem, AskUserWorker, DelayedWorkQueue, pAskContext);
		goto	__DROP;
		
	}


__BypassTcpipArpRcv:
	return	BypassTcpipArpRcv(ProtocolBindingContext, MacReceiveContext, HeaderBuffer, HeaderBufferSize, LookAheadBuffer, LookAheadBufferSize, PacketSize);

__DROP:
	return	NDIS_STATUS_NOT_ACCEPTED;
}
//////////////////////////////////////////////////////////////////////////
//�Ѽ�¼�Ķ˿��Ƿ������Ϣ�����ͷŵ�
NTSTATUS	FWReleasePortRuleList()
{
	AcceptedPort	*pAPort	=NULL;
	PLOCK_STATE		pLockState1=NULL;
	PLIST_ENTRY		pNext	=NULL;

	kprintf("Enter FWReleasePortRuleList()\n");
	pLockState1	=	kmalloc(sizeof(LOCK_STATE));
	
	NdisAcquireReadWriteLock(&g_AcceptedPortListLock2, KKRWLOCK_FOR_WRITE, pLockState1);
	while(!IsListEmpty(&g_AcceptedPortListHeader.Next))
	{
		pNext	=	RemoveHeadList(&g_AcceptedPortListHeader.Next);
		if (pNext==NULL)
		{
			break;
		}
		pAPort	=	CONTAINING_RECORD(pNext, AcceptedPort, Next);
		if (pAPort==NULL)
		{
			break;
		}
		kprintf("Releasing Port :%d, Rule:%s\n", pAPort->uPort, pAPort->PStatus==PortDeny?"Deny":"Accept");
		kfree(pAPort);
	}
	NdisReleaseReadWriteLock(&g_AcceptedPortListLock2, pLockState1);

	kfree(pLockState1);

	kprintf("Leave FWReleasePortRuleList()\n");
	return	STATUS_SUCCESS;

}
//////////////////////////////////////////////////////////////////////////
NTSTATUS	FWUnhookTcpipRecvHandler()
{
	PKK_NDIS_PROTOCOL_BLOCK	pTcpipProtocolBlcok=NULL;
	PKK_NDIS_PROTOCOL_BLOCK	pProtocolBlockHeader=NULL;
	ULONG	ut1,ut2;
	PNDIS_COMMON_OPEN_BLOCK_2k3_early	pOpenBlock=NULL;
	NTSTATUS	status	=	STATUS_SUCCESS;
	PNDIS_HOOK_INFO	pHI	;
	PULONG	ptmp;
	PLIST_ENTRY	pNext	=	NULL;
	PLOCK_STATE	pLockState1=NULL;


	pLockState1	=	kmalloc(sizeof(LOCK_STATE));

	kprintf("Enter FWUnhookTcpipRecvHandler()\n");
	NdisAcquireReadWriteLock(&g_HookTcpipFireWallLock, KKRWLOCK_FOR_WRITE, pLockState1);
	while (!IsListEmpty(&g_HookTcpipFireWallList.Next))
	{
		pNext	=	RemoveHeadList(&g_HookTcpipFireWallList.Next);
		if (pNext==NULL)
		{
			kprintf("FWUnhookTcpipRecvHandler() fail Return Null on ExInterlockedRemoveHeadList\n");
			DbgBreakPoint();
		}
		pHI	=	CONTAINING_RECORD(pNext, NDIS_HOOK_INFO, Next);
		if (pHI==NULL)
		{
			kprintf("FWUnhookTcpipRecvHandler() fail Return Null on CONTAINING_RECORD\n");
			DbgBreakPoint();
		}
		kprintf("FWUnhookTcpipRecvHandler Name:%s, OldHandler:0x%x\n", pHI->szFuncname, pHI->OldHandler);
		*(PULONG_PTR)pHI->Address2Restore	=	(ULONG_PTR)pHI->OldHandler;
		kfree(pHI);

	}
	NdisReleaseReadWriteLock(&g_HookTcpipFireWallLock, pLockState1);
	kprintf("Leave FWUnhookTcpipRecvHandler()\n");
	if (pLockState1)
	{
		kfree(pLockState1);
	}
	return status;
}
//////////////////////////////////////////////////////////////////////////

NTSTATUS	FWHookTcpipRecvHandler()
{
	PKK_NDIS_PROTOCOL_BLOCK	pTcpipProtocolBlcok=NULL;
	PKK_NDIS_PROTOCOL_BLOCK	pProtocolBlockHeader=NULL;
	ULONG	ut1,ut2;
	PNDIS_COMMON_OPEN_BLOCK_2k3_early	pOpenBlock=NULL;
	NTSTATUS	status	=	STATUS_SUCCESS;
	PNDIS_HOOK_INFO	pHI	;
	PULONG	ptmp;
	PLOCK_STATE	pLockState1=NULL;

#ifdef VMPROTECT
	VMProtectBeginVirtualization("FWHookTcpipRecvHandler");
#endif


	pLockState1	=	kmalloc(sizeof(LOCK_STATE));

	ut1	=	ut2	=	0;

	do 
	{
		pTcpipProtocolBlcok	=	(PKK_NDIS_PROTOCOL_BLOCK)GetTcpipProtocolBlock();

		if (pTcpipProtocolBlcok==0)
		{
			status	=	STATUS_UNSUCCESSFUL;
			break;
		}
		pOpenBlock	=	pTcpipProtocolBlcok->OpenQueue;
		NdisAcquireReadWriteLock(&g_HookTcpipFireWallLock, KKRWLOCK_FOR_WRITE, pLockState1);

		while(pOpenBlock)
		{

// 			if (!IsPhysicalMiniport(pOpenBlock->MiniportHandle))
// 			{
// 				goto __nextpOpenBlock;
// 			}
			pHI	=	kmalloc(sizeof(NDIS_HOOK_INFO));
			ptmp=NULL;
			RtlZeroMemory(pHI, sizeof(NDIS_HOOK_INFO));
			pHI->OldHandler	=	(PVOID)pOpenBlock->ReceiveHandler;
			pHI->Address2Restore	=	&(pOpenBlock->ReceiveHandler);
			pHI->pMiniBlock	=	(ULONG)pOpenBlock->MiniportHandle;
			pHI->pSignContext	=	(PVOID)pOpenBlock->ProtocolBindingContext;
			pHI->pProtocolBindingContext	=	(ULONG)pOpenBlock->ProtocolBindingContext;
			pHI->pOpenblock	=	(ULONG_PTR)pOpenBlock;
			pHI->szFuncname	=	"KKNewTcpipArpRcv";
			pHI->NewHandler	=	(PVOID)KKNewTcpipArpRcv;
			*(PULONG)&(pOpenBlock->ReceivePacketHandler)=0;	//�������0��

			InsertHeadList(&g_HookTcpipFireWallList.Next, &pHI->Next);


			ptmp	=	(ULONG*)pHI->Address2Restore;
			*ptmp	=	(ULONG)KKNewTcpipArpRcv;

//__nextpOpenBlock:
			pOpenBlock	=	(PNDIS_COMMON_OPEN_BLOCK_2k3_early)pOpenBlock->ProtocolNextOpen;
		}
		NdisReleaseReadWriteLock(&g_HookTcpipFireWallLock, pLockState1);



	} while (0);

	if (pLockState1)
	{
		kfree(pLockState1);
	}
#ifdef VMPROTECT
	VMProtectEnd();
#endif
	
	return status;
}
//////////////////////////////////////////////////////////////////////////
//���ö˿ڹ���
NTSTATUS	SetupPortStatus(FIREWALL_ASKUSER *pFAS, ULONG uNumbers)
{

	NTSTATUS	status	=	STATUS_SUCCESS;

	AcceptedPort	*pAPort	=NULL;
	PLOCK_STATE		pLockState1=NULL;
	PLIST_ENTRY		pNext	=NULL;
	ULONG			utmp=0;
	BOOLEAN			bFound	=	FALSE;

	kprintf("Enter SetupPortStatus()\n");
	pLockState1	=	kmalloc(sizeof(LOCK_STATE));

	NdisAcquireReadWriteLock(&g_AcceptedPortListLock2, KKRWLOCK_FOR_WRITE, pLockState1);
	for (utmp=0; utmp<uNumbers; utmp++)
	{
		pNext	=	g_AcceptedPortListHeader.Next.Flink;
		while(pNext&&(pNext!=&g_AcceptedPortListHeader.Next))
		{
			pAPort	=	CONTAINING_RECORD(pNext, AcceptedPort, Next);
			if (pAPort==NULL)
			{
				DbgBreakPoint();
			}

			if (pAPort->uPort==pFAS[utmp].uPort)
			{
				bFound	=	TRUE;//�ҵ��������״̬
				pAPort->PStatus	=	pFAS[utmp].PStatus;
				break;
			}
			pNext	=	pNext->Flink;
		}
		if (!bFound)
		{
			//����Ҳ�����˵�����¼ӵģ�
			pAPort	=	kmalloc(sizeof(AcceptedPort));
			pAPort->uPort	=	pFAS[utmp].uPort;
			pAPort->PStatus	=	pFAS[utmp].PStatus;
			InsertHeadList(&g_AcceptedPortListHeader.Next, &pAPort->Next);
		}

	}
	
	NdisReleaseReadWriteLock(&g_AcceptedPortListLock2, pLockState1);
	kfree(pLockState1);
	return status;
}
//////////////////////////////////////////////////////////////////////////
//work item����indicate syn���߳�

NTSTATUS	ResponsePortAskWorkerForIndicateupPacket(PDEVICE_OBJECT  DeviceObject, PVOID	pContext)
{
	PASKUserWorkItemContext	pPAskContext=NULL;
	NTSTATUS		status	=	STATUS_SUCCESS;
	PAcceptedPort	pIndicateContext=NULL;
	KIRQL			CIrql=0, CIrql2=0;
	//__asm int 3
	CIrql	=	KeGetCurrentIrql();
	pPAskContext	=	(PASKUserWorkItemContext)pContext;
	if (pPAskContext==NULL)
	{
		return status;
	}
	pIndicateContext	=	(PAcceptedPort)pPAskContext->pContext;
	IoFreeWorkItem(pPAskContext->pWorkItem);
	kfree(pPAskContext);
	
	//�Զ��������ύһ��
	status = BypassTcpipArpRcv((NDIS_HANDLE)pIndicateContext->ProtocolBindingContext, (NDIS_HANDLE)pIndicateContext->MacReceiveContext, pIndicateContext->HeaderBuffer, pIndicateContext->HeaderBufferSize,\
		pIndicateContext->LookAheadBuffer, pIndicateContext->LookAheadBufferSize, pIndicateContext->LookAheadBufferSize);
	if (KeGetCurrentIrql()>CIrql)
	{
		KeLowerIrql(CIrql);
	}
	if (KeGetCurrentIrql()<CIrql)
	{
		KeRaiseIrql(CIrql, &CIrql2);
	}
	kfree(pIndicateContext);
	return status;

}
//////////////////////////////////////////////////////////////////////////
//���û���ĳ���˿ڵķ������þ����������������
//�˺�����ͬSetupPortStatus��ResponsePortAsk������Ҫ�����������indicateһ�� syn��
NTSTATUS	ResponsePortAsk(FIREWALL_ASKUSER	*pPAsk)
{
	NTSTATUS	status	=	STATUS_SUCCESS;

	AcceptedPort	*pAPort	=NULL;
	PLOCK_STATE		pLockState1=NULL;
	PLIST_ENTRY		pNext	=NULL;
	ULONG			utmp=0;
	BOOLEAN			bFound	=	FALSE;
	PAcceptedPort	pIndicateContext=NULL;
#ifdef VMPROTECT
	VMProtectBeginVirtualization("Response ask");

#endif

	pIndicateContext	=	kmalloc(sizeof(AcceptedPort));	//
	pLockState1	=	kmalloc(sizeof(LOCK_STATE));

	NdisAcquireReadWriteLock(&g_AcceptedPortListLock2, KKRWLOCK_FOR_READ, pLockState1);
	pNext	=	g_AcceptedPortListHeader.Next.Flink;
	while(pNext&&(pNext!=&g_AcceptedPortListHeader.Next))
	{
		pAPort	=	CONTAINING_RECORD(pNext, AcceptedPort, Next);
		if (pAPort==NULL)
		{
			DbgBreakPoint();
		}

		if (pAPort->uPort==pPAsk->uPort&&pAPort->SrcIP==pPAsk->SrcIP)
		{
			bFound	=	TRUE;//�ҵ��������״̬
			pAPort->PStatus	=	pPAsk->PStatus;
			break;
		}
		pNext	=	pNext->Flink;
	}
	if (bFound)
	{
		*pIndicateContext	=	*pAPort;	//Ϊ�˰�ȫ����һ�ݿ�����
	}
	NdisReleaseReadWriteLock(&g_AcceptedPortListLock2, pLockState1);
	if (bFound&&pPAsk->PStatus==PortAccept)
	{
		//�ҵ��������ǽ���״̬������Ҫ�ϴ�һ����һ�����ֵ�syn���ݰ�
		PIO_WORKITEM	pWorkItem	=	NULL;
		PASKUserWorkItemContext	pAskContext	=NULL;
		
		pWorkItem = IoAllocateWorkItem(g_CtlDevice);
		pAskContext	=	kmalloc(sizeof(ASKUserWorkItemContext));
		pAskContext->pWorkItem	=	pWorkItem;
		pAskContext->pContext	=	pIndicateContext;
		IoQueueWorkItem(pWorkItem, ResponsePortAskWorkerForIndicateupPacket, DelayedWorkQueue, pAskContext);
		pIndicateContext=NULL;
	}
	if (pIndicateContext)
	{
		kfree(pIndicateContext);pIndicateContext=NULL;
	}
	kfree(pLockState1);
#ifdef VMPROTECT
	VMProtectEnd();

#endif
	return status;
}
//////////////////////////////////////////////////////////////////////////
NTSTATUS	ReleasePenddingCheckPortIrp()
{
	PIRP					Irp;
	PLIST_ENTRY			pListEntry;
	NTSTATUS			Status=STATUS_SUCCESS;

	while(!IsListEmpty(&g_AskUserConnectListHeader))
	{

		//find a pendding irp 2 ask user decision
		pListEntry	=	ExInterlockedRemoveHeadList(&g_AskUserConnectListHeader, &g_AskUserConnectListLock);
		Irp = CONTAINING_RECORD(pListEntry, IRP, Tail.Overlay.ListEntry);		
		if (Irp==NULL)
		{
			break;
		}
		Irp->IoStatus.Status = Status;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
	}

	return	Status;
}
//////////////////////////////////////////////////////////////////////////
NTSTATUS	GetPortRules(PVOID pBuffer, ULONG *pBufferLen)
{
	ULONG	utmp=0;

	FIREWALL_ASKUSER	*pFAS=NULL;
	LIST_ENTRY	*pNext	=NULL;
	AcceptedPort	*pAPort	=NULL;
	PLOCK_STATE	pLockState1=NULL;

	pFAS	=	(FIREWALL_ASKUSER*)pBuffer;

	pLockState1	=	kmalloc(sizeof(LOCK_STATE));
	NdisAcquireReadWriteLock(&g_AcceptedPortListLock2, KKRWLOCK_FOR_READ, pLockState1);
	pNext	=	g_AcceptedPortListHeader.Next.Flink;
	while(pNext&&(pNext!=&g_AcceptedPortListHeader.Next))
	{
		pAPort	=	CONTAINING_RECORD(pNext, AcceptedPort, Next);
		if (pAPort==NULL)
		{
			DbgBreakPoint();
		}
		utmp++;
		pNext	=	pNext->Flink;
	}
	NdisReleaseReadWriteLock(&g_AcceptedPortListLock2, pLockState1);
	
	if (*pBufferLen<utmp*sizeof(FIREWALL_ASKUSER))
	{
		//ֻ�����ȡbuffer����
		*pBufferLen	=	utmp*sizeof(FIREWALL_ASKUSER);
		return STATUS_INFO_LENGTH_MISMATCH;
	}
	utmp=0;
	NdisAcquireReadWriteLock(&g_AcceptedPortListLock2, KKRWLOCK_FOR_READ, pLockState1);
	pNext	=	g_AcceptedPortListHeader.Next.Flink;
	while(pNext&&(pNext!=&g_AcceptedPortListHeader.Next))
	{
		pAPort	=	CONTAINING_RECORD(pNext, AcceptedPort, Next);
		if (pAPort==NULL)
		{
			DbgBreakPoint();
		}
		pFAS[utmp].PStatus	=	pAPort->PStatus;
		pFAS[utmp].uPort	=	pAPort->uPort;
		utmp++;
		pNext	=	pNext->Flink;
	}
	NdisReleaseReadWriteLock(&g_AcceptedPortListLock2, pLockState1);
	kfree(pLockState1);
	*pBufferLen=utmp*sizeof(FIREWALL_ASKUSER);
	return STATUS_SUCCESS;

}
//////////////////////////////////////////////////////////////////////////

NTSTATUS FWDispatch(
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

	switch (ioControlCode)
	{
	case IOCTL_SETUPFW:
		{
			//

			if (g_AlreadyHookTCPIP)
			{
				InterlockedExchange(&g_InterceptTCPIPRcv, 1);
			}
			else
			{
				Status=	FWHookTcpipRecvHandler();
				if (NT_SUCCESS(Status))
				{
					InterlockedExchange(&g_InterceptTCPIPRcv, 1);
					g_AlreadyHookTCPIP	=	1;
				}
			}
			break;
		}
	case IOCTL_UNSETFW:
		{
			//
			InterlockedExchange(&g_InterceptTCPIPRcv, 0);
			//UNHOOK����Ϊ�ͷŵ�����ж��ʱ����
			break;
		}
	case IOCTL_PENDDINGCHECKPORT:
		{
			//pendding��ȥ
			IoMarkIrpPending(Irp);
			ExInterlockedInsertHeadList(&g_AskUserConnectListHeader, &Irp->Tail.Overlay.ListEntry, &g_AskUserConnectListLock);
			Status= STATUS_PENDING;
			Irp->IoStatus.Status = Status;
			return Status;
			break;
		}
	case IOCTL_SETONEPORTSTATUS:
		{
			Status = SetupPortStatus(ioBuf, 1);
			break;
		}
	case IOCTL_RESPONSEPORTASK:
		{
			Status = ResponsePortAsk((PFIREWALL_ASKUSER)ioBuf);
			break;
		}
	case IOCTL_ReleasePENDDINGCHECKPORT:
		{
			Status = ReleasePenddingCheckPortIrp();
			break;
		}
	case IOCTL_GETPORTSTATUS:
		{
			Status = GetPortRules(ioBuf, &outBufLength);
			if (Status==STATUS_INFO_LENGTH_MISMATCH)
			{
				Status	=	STATUS_SUCCESS;
			}
			Irp->IoStatus.Information	=	outBufLength;
			break;
		}

	default:
		{
			//Status = STATUS_INVALID_PARAMETER;
			kprintf("[SuperCI]  Unknown IOCTL: 0x%X (%04X,%04X)\n",
				ioControlCode, DEVICE_TYPE_FROM_CTL_CODE(ioControlCode),
				IoGetFunctionCodeFromCtlCode(ioControlCode));


			break;
		}
	}


	Irp->IoStatus.Status = Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);


	return Status;

}
