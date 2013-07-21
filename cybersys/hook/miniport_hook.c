
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


// A structure representing the instance information associated with
// a particular device
//


NDIS_HANDLE         NdisWrapperHandle;
NDIS_HANDLE         DriverHandle = NULL;
ULONG				g_u_mini_driver_block_head;
//BOOLEAN				g_bMiniportHook	=	FALSE;
PDEVICE_OBJECT		g_CtlDevice	=	NULL;

//////////////////////////////////////////////////////////////////////////

NDIS_HOOK_INFO	g_pHookInfoHeader;
NDIS_RW_LOCK	g_HookInfoLock2;

////////////////////////////////////////////////////////////////////////////////

BOOLEAN	UnHookAndRelease(void)
{
	LIST_ENTRY			*pNextHook	=NULL;
	PNDIS_HOOK_INFO		pHI			=NULL;


	kprintf("Enter UnHook\n");
	STARTLOCK(&g_HookInfoLock2, KKRWLOCK_FOR_WRITE);

	while (!IsListEmpty(&g_pHookInfoHeader.Next))
	{
		pNextHook = RemoveHeadList(&g_pHookInfoHeader.Next);
		if (pNextHook)
		{
			
			pHI = CONTAINING_RECORD(pNextHook, NDIS_HOOK_INFO, Next);
			*(PULONG)pHI->Address2Restore	=	(ULONG)pHI->OldHandler;
			kprintf("unhooking hooktype %x, Handler Name=%s, OldHandler = 0x%x\n", pHI->HandlerSign, pHI->szFuncname, pHI->OldHandler);

			InterlockedDecrement(&g_pHookInfoHeader.Count);
			kfree(pHI);
		}
	}
	ENDLOCK(&g_HookInfoLock2);

	return TRUE;
}
//////////////////////////////////////////////////////////////////////////
BOOLEAN	UnHook(void)
{

	return UnHookAndRelease();

}
//////////////////////////////////////////////////////////////////////////
BOOLEAN	ReleaseHookInfo(void)
{
	LIST_ENTRY			*pNextHook	=NULL;
	PNDIS_HOOK_INFO		pHI			=NULL;


	kprintf("Enter UnHook\n");
	STARTLOCK(&g_HookInfoLock2, KKRWLOCK_FOR_WRITE);

	while (!IsListEmpty(&g_pHookInfoHeader.Next))
	{
		pNextHook = RemoveHeadList(&g_pHookInfoHeader.Next);
		if (pNextHook)
		{

			pHI = CONTAINING_RECORD(pNextHook, NDIS_HOOK_INFO, Next);
			if (pHI==NULL)
			{
				break;
			}
			kfree(pHI);
		}
	}
	ENDLOCK(&g_HookInfoLock2);

	return TRUE;
}
//////////////////////////////////////////////////////////////////////////



PVOID	GetOldHandler(PVOID pSgin,PVOID pNewHandler)
{
	LIST_ENTRY			*pNextHook	=NULL;
	PNDIS_HOOK_INFO		pHI			=NULL;
	PVOID				pHandler	=NULL;
	//DbgBreakPoint();
	STARTLOCK(&g_HookInfoLock2,KKRWLOCK_FOR_READ);

	pNextHook =	g_pHookInfoHeader.Next.Flink;
	while (pNextHook != &g_pHookInfoHeader.Next)
	{
		if (pNextHook)
		{
			pHI = CONTAINING_RECORD(pNextHook, NDIS_HOOK_INFO, Next);
			if (pHI->NewHandler	==	pNewHandler&& pHI->OldHandler!=NULL)
			{
				//如果同一个newhandler 对应多个oldhandler，会有问题
				if (pHI->pSignContext==pSgin)
				{
					pHandler =  pHI->OldHandler;
				}

			}
			pNextHook	=	pNextHook->Flink;

		}
		else
		{
			kprintf("what the fuck??!!! handler no found\n");
		}
	}
	ENDLOCK(&g_HookInfoLock2);
	return pHandler;

}
//////////////////////////////////////////////////////////////////////////

DWORD	GetProtocolHeader()
{
	ULONG	ulVersion	=	GetWindowsVersion();
	DWORD	ulHeader	=0;

	switch (ulVersion)
	{
	case Windows_XP:
	case Windows_2k3:
		{
			ulHeader = GetProtocolHeaderXP();
			break;
		}

	case  Windows_7:
	case Windows_Vista:
		{
			ulHeader =	GetProtocolHeaderWin7();
			break;
		}

	default:
		{

			break;
		}
	}

	return ulHeader;
}
//////////////////////////////////////////////////////////////////////////

//获取MDriverList的头
//发现这个获取不太好。使用了之后，协议驱动没法安装，而且自身的那个mini_driver_block也拆除不下来
ULONG	GetMDriverBlockHeader()
{

	NDIS_STATUS                        Status;
    myNDIS51_MINIPORT_CHARACTERISTICS      MChars;
    NDIS_STRING                        Name;
	PDRIVER_EXTENSION					pDriverExten=NULL;
	PDRIVER_OBJECT			DriverObject	=	g_pDriverObject	;

	return 1;
/*

	Status = NDIS_STATUS_SUCCESS;
	//貌似不能重复地假注册
	if (g_u_mini_driver_block_head)
	{
		return g_u_mini_driver_block_head;
	}
	NdisMInitializeWrapper(&NdisWrapperHandle, DriverObject, &g_RegistryPath, NULL);
	
	NdisZeroMemory(&MChars, sizeof(myNDIS51_MINIPORT_CHARACTERISTICS));
	
	MChars.Ndis50Chars.MajorNdisVersion = 5;
	if (GetWindowsVersion()!=Windows_2K)
	{
		MChars.Ndis50Chars.MinorNdisVersion = 1;
	}
	
	/ *
	MChars.InitializeHandler = NULL;
	MChars.QueryInformationHandler = NULL;
	MChars.SetInformationHandler = NULL;
	MChars.ResetHandler = NULL;
	MChars.TransferDataHandler = NULL;
	MChars.HaltHandler = NULL;

	MChars.CancelSendPacketsHandler = NULL;
	MChars.PnPEventNotifyHandler = NULL;
    MChars.AdapterShutdownHandler = NULL;
	MChars.SendHandler = NULL;    // MPSend;
	MChars.SendPacketsHandler = NULL;
	* /
	MChars.PnPEventNotifyHandler = MPDevicePnPEvent;
	MChars.AdapterShutdownHandler	=	MPAdapterShutdown;
	Status = NdisIMRegisterLayeredMiniport(NdisWrapperHandle,(PNDIS_MINIPORT_CHARACTERISTICS)&MChars,sizeof(MChars),&DriverHandle);
	if (Status!=NDIS_STATUS_SUCCESS)
	{
		KdPrint(("[SuperCI]  NdisIMRegisterLayeredMiniport fail, error : 0x%X\n", Status));
		return 0;	//
	}

	g_u_mini_driver_block_head	=	*(ULONG*)DriverHandle;	//取出

	NdisIMDeregisterLayeredMiniport(DriverHandle);	//取消注册，貌似这函数什么都不干
	NdisTerminateWrapper(NdisWrapperHandle, NULL);
	kprintf("IRQL=%X, ThreadObj =%x, NdisIMRegisterLayeredMiniport ori_driver_block_list_head :%p, NdisWrapperHandle:0x%X, DriverHandle : 0x%X\n", KeGetCurrentIrql(), KeGetCurrentThread(), g_u_mini_driver_block_head, NdisWrapperHandle, DriverHandle);
	pDriverExten	=	DriverObject->DriverExtension;
	pDriverExten->AddDevice	=	NULL;	//NdisIMRegisterLayeredMiniport函数的调用会给这个AddDevice赋值NDIS!xxunload函数，导致不能动态卸载，NULL后就可以了

	return g_u_mini_driver_block_head;*/

}


//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////

NTSTATUS	StartMiniportHookEx()
{


	ULONG	ulVersion	=	GetWindowsVersion();
	DWORD	ulHeader	=0;
	NTSTATUS	status	=	STATUS_UNSUCCESSFUL;
	ulHeader	=GetProtocolHeader();


	switch (ulVersion)
	{
	case Windows_XP:
	case Windows_2k3:
		{
			status = DoHookExXP(ulHeader);
			break;
		}

	case  Windows_7:
	case Windows_Vista:
		{
			status	=	DoHookExWin7(ulHeader);
			break;
		}

	default:
		{
			kprintf("StartMiniportHookEx() fail,os Version is not supported\n");
			break;
		}
		
	}

	return status;

}
//////////////////////////////////////////////////////////////////////////
NTSTATUS
InitMiniPortHook()
{
	NTSTATUS			Status = STATUS_SUCCESS;    
	NTSTATUS			Status_createthread = STATUS_SUCCESS;  
	HANDLE				hthread;
	UNICODE_STRING		ntDeviceName;
	UNICODE_STRING		dosDeviceName;
	PDEVICE_EXTENSION	deviceExtension;
	PDEVICE_OBJECT		deviceObject = NULL;
	ULONG				uIndex=0;
	UNICODE_STRING	uniRoutineName;


	kprintf("InitMiniPortHookEntry\n");

	
	RtlInitUnicodeString(&uniRoutineName, L"NdisAllocateNetBufferAndNetBufferList");
	g_pfnNdisAllocateNetBufferAndNetBufferList = NdisGetRoutineAddress(&uniRoutineName);

	RtlInitUnicodeString(&uniRoutineName, L"NdisAllocateNetBufferListPool");
	g_pfnNdisAllocateNetBufferListPool = NdisGetRoutineAddress(&uniRoutineName);

	RtlInitUnicodeString(&uniRoutineName, L"NdisFreeNetBufferListPool");
	g_pfnNdisFreeNetBufferListPool = NdisGetRoutineAddress(&uniRoutineName);

	RtlInitUnicodeString(&uniRoutineName, L"NdisCopyFromNetBufferToNetBuffer");
	g_pfnNdisCopyFromNetBufferToNetBuffer = NdisGetRoutineAddress(&uniRoutineName);

	RtlInitUnicodeString(&uniRoutineName, L"NdisFreeNetBufferList");
	g_pfnNdisFreeNetBufferList = NdisGetRoutineAddress(&uniRoutineName);


	Status = StartMiniportHookEx();

	if (Status!= NDIS_STATUS_SUCCESS)
	{
		//	不成功的话，就不HOOK了
		kprintf("StartMiniportHookEx fail\n");
		return Status;
	}

	//g_bMiniportHook	=	TRUE;


	//////////////////////////////////////////////////////////////////////////
	return Status;
}
//////////////////////////////////////////////////////////////////////////
VOID
PtBindAdapter(
			  OUT PNDIS_STATUS              Status,
			  IN  NDIS_HANDLE               BindContext,
			  IN  PNDIS_STRING              DeviceName,
			  IN  PVOID                     SystemSpecific1,
			  IN  PVOID                     SystemSpecific2
			  )
{
	UNREFERENCED_PARAMETER(Status);
	UNREFERENCED_PARAMETER(BindContext);
	UNREFERENCED_PARAMETER(DeviceName);
	UNREFERENCED_PARAMETER(SystemSpecific1);
	UNREFERENCED_PARAMETER(SystemSpecific2);

}
VOID
PtUnbindAdapter(
				OUT PNDIS_STATUS           Status,
				IN  NDIS_HANDLE            ProtocolBindingContext,
				IN  NDIS_HANDLE            UnbindContext
				)
{
	UNREFERENCED_PARAMETER(Status);
	UNREFERENCED_PARAMETER(ProtocolBindingContext);
	UNREFERENCED_PARAMETER(UnbindContext);

}

VOID
MPDevicePnPEvent(
    IN NDIS_HANDLE              MiniportAdapterContext,
    IN NDIS_DEVICE_PNP_EVENT    DevicePnPEvent,
    IN PVOID                    InformationBuffer,
    IN ULONG                    InformationBufferLength
    )
/*++

Routine Description:

    This handler is called to notify us of PnP events directed to
    our miniport device object.

Arguments:

    MiniportAdapterContext    - pointer to ADAPT structure
    DevicePnPEvent - the event
    InformationBuffer - Points to additional event-specific information
    InformationBufferLength - length of above

Return Value:

    None
--*/
{
    // TBD - add code/comments about processing this.

    UNREFERENCED_PARAMETER(MiniportAdapterContext);
    UNREFERENCED_PARAMETER(DevicePnPEvent);
    UNREFERENCED_PARAMETER(InformationBuffer);
    UNREFERENCED_PARAMETER(InformationBufferLength);
    
    return;
}

VOID
MPAdapterShutdown(
    IN NDIS_HANDLE                MiniportAdapterContext
    )
/*++

Routine Description:

    This handler is called to notify us of an impending system shutdown.

Arguments:

    MiniportAdapterContext    - pointer to ADAPT structure

Return Value:

    None
--*/
{
    UNREFERENCED_PARAMETER(MiniportAdapterContext);
    
    return;
}