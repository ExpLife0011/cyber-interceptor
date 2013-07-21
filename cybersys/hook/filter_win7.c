
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
NDIS_HANDLE	g_NetBufferListPool=NULL;

PVOID		g_pfnNdisAllocateNetBufferListPool=NULL;
PVOID		g_pfnNdisAllocateNetBufferAndNetBufferList=NULL;
PVOID		g_pfnNdisFreeNetBufferListPool=NULL;
PVOID		g_pfnNdisCopyFromNetBufferToNetBuffer=NULL;
PVOID		g_pfnNdisFreeNetBufferList=NULL;
//////////////////////////////////////////////////////////////////////////

FilterType SendNetBufferCallBackWin7(PNET_BUFFER_LIST_KK NetBufferLists, DWORD NumberOfNetBufferLists)
{


	NetBufferListSinfferCallback(NetBufferLists, NumberOfNetBufferLists);
	RedirectNetBufferSendCallbackWin7(NetBufferLists, NumberOfNetBufferLists);


	return Bypass;
}
//////////////////////////////////////////////////////////////////////////
FilterType RecvNetBufferCallBackWin7(PNET_BUFFER_LIST_KK NetBufferLists, DWORD NumberOfNetBufferLists)
{

	NetBufferListSinfferCallback(NetBufferLists, NumberOfNetBufferLists);
	RedirectNetBufferRecvCallbackWin7(NetBufferLists,NumberOfNetBufferLists);

	return Bypass;
}

//////////////////////////////////////////////////////////////////////////
VOID
KKMPSendNetBufferLists(
					   NDIS_HANDLE             MiniportAdapterContext,
					   PNET_BUFFER_LIST_KK        NetBufferLists,
					   PVOID					PortNumber,
					   DWORD                   SendFlags)
{
	//	__asm int 3
	PVOID pOldHandler =NULL;


	if (pOldHandler==NULL)
	{

		pOldHandler	=	GetOldHandler(MiniportAdapterContext, KKMPSendNetBufferLists);

	}
	if (pOldHandler==NULL)
	{
		kprintf("KKNdisMIndicateReceiveNetBufferListsInternal_vista_later fail....oh god, crash me!!\n");
		DbgBreakPoint();
	}

	SendNetBufferCallBackWin7(NetBufferLists, 1);

	kprintf("KKMPSendNetBufferLists invoked\n");
	_asm
	{
		push SendFlags
		push PortNumber
		push NetBufferLists
		push MiniportAdapterContext
		call pOldHandler
	}

	return ;
}

//////////////////////////////////////////////////////////////////////////

void KKNdisMIndicateReceiveNetBufferListsInternal_vista_later(
	DWORD MiniportAdapterHandle,
	PNET_BUFFER_LIST_KK NetBufferLists,
	DWORD PortNumber,
	DWORD NumberOfNetBufferLists,
	DWORD ReceiveFlags
	)
{

	PVOID pOldHandler =NULL;


	if (pOldHandler==NULL)
	{

		pOldHandler	=	GetOldHandler((PVOID)MiniportAdapterHandle, KKNdisMIndicateReceiveNetBufferListsInternal_vista_later);

	}
	if (pOldHandler==NULL)
	{
		kprintf("KKNdisMIndicateReceiveNetBufferListsInternal_vista_later fail....oh god, crash me!!\n");
		DbgBreakPoint();
	}
	kprintf("KKNdisMIndicateReceiveNetBufferListsInternal_vista_later is invoked\n");

	RecvNetBufferCallBackWin7(NetBufferLists, NumberOfNetBufferLists);

	_asm{
		push ReceiveFlags
		push NumberOfNetBufferLists
		push PortNumber
		push NetBufferLists
		push MiniportAdapterHandle
		call pOldHandler
	}

	return ;
}

//////////////////////////////////////////////////////////////////////////

NDIS_STATUS
CopyBytesFromNetBuffer(  PNET_BUFFER_KK        NetBuffer,  PULONG             cbDest, PVOID Dest)
/*++

Routine Description:

    Copies the first cbDest bytes from a NET_BUFFER. In order to show how the various data structures fit together, this 
    implementation copies the data by iterating through the MDLs for the NET_BUFFER. The NdisGetDataBuffer API also allows you
    to copy a contiguous block of data from a NET_BUFFER. 

    Runs at IRQL <= DISPATCH_LEVEL.

Arguments:

    NetBuffer                   The NB to read
    cbDest                      On input, the number of bytes in the buffer Dest
                                On return, the number of bytes actually copied
    Dest                        On return, receives the first cbDest bytes of
                                the network frame in NetBuffer

Return Value:

    None.

Notes:

    If the output buffer is larger than the NB's frame size, *cbDest will
    contain the number of bytes in the frame size.

    If the output buffer is smaller than the NB's frame size, only the first
    *cbDest bytes will be copied (the buffer will receive a truncated copy of
    the frame).

--*/
{
    NDIS_STATUS Status = NDIS_STATUS_SUCCESS;
    //
    // Start copy from current MDL
    //
    PMDL CurrentMdl = NET_BUFFER_CURRENT_MDL(NetBuffer);
    //
    // Data on current MDL may be offset from start of MDL
    //
    ULONG DestOffset = 0;
    while (DestOffset < *cbDest && CurrentMdl)
    {
        //
        // Map MDL memory to System Address Space. LowPagePriority means mapping may fail if 
        // system is low on memory resources. 
        //
        PUCHAR SrcMemory = MmGetSystemAddressForMdlSafe(CurrentMdl, LowPagePriority);
        ULONG Length = MmGetMdlByteCount(CurrentMdl);
        if (!SrcMemory)
        {
            Status = NDIS_STATUS_RESOURCES;
            break;
        }

        if(DestOffset==0)
        {
            //
            // The first MDL segment should be accessed from the current MDL offset
            //
            ULONG MdlOffset = NET_BUFFER_CURRENT_MDL_OFFSET(NetBuffer);
            SrcMemory += MdlOffset;
            Length -= MdlOffset;
        }

        Length = min(Length, *cbDest-DestOffset);

        //
        // Copy Memory
        //
        NdisMoveMemory((PUCHAR)Dest+DestOffset, SrcMemory, Length);
        DestOffset += Length;

        //
        // Get next MDL (if any available) 
        //
        CurrentMdl = NDIS_MDL_LINKAGE(CurrentMdl);
    }

    if(Status == NDIS_STATUS_SUCCESS)
    {
        *cbDest = DestOffset;
    }

    return Status;
}
//////////////////////////////////////////////////////////////////////////

PNET_BUFFER_LIST_KK MyNdisAllocateNetBufferAndNetBufferList( NDIS_HANDLE PoolHandle, __in DWORD ContextSize, __in DWORD ContextBackFill, __in_opt __drv_aliasesMem PMDL MdlChain, __in DWORD DataOffset, __in DWORD DataLength )
{
	PNET_BUFFER_LIST_KK	pNetList=NULL;
	static PVOID	pHandler=NULL;
	UNICODE_STRING	uniRoutineName;
	ULONG	ulret=0;

	if (pHandler==NULL)
	{
	//	RtlInitUnicodeString(&uniRoutineName, L"NdisAllocateNetBufferAndNetBufferList");
	//	pHandler = NdisGetRoutineAddress(&uniRoutineName);
		pHandler	=	g_pfnNdisAllocateNetBufferAndNetBufferList;

	}
	if (pHandler==NULL)
	{
		kprintf("NdisAllocateNetBufferAndNetBufferList() ....this is fucked\n");
		return pNetList;
	}
	_asm
	{
		push DataLength
		push DataOffset
		push MdlChain
		push ContextBackFill
		push ContextSize
		push PoolHandle
		call pHandler
		mov pNetList,eax

	}
	return pNetList;

}
//////////////////////////////////////////////////////////////////////////

VOID FreeNetBufferList(PNET_BUFFER_LIST_KK pNetBufferList)
{
	PMDL                pMdl;
	UINT                TotalLength;
	UINT                BufferLength;
	PUCHAR              pCopyData = NULL;
	ULONG               ReturnFlags = 0;

	if (pNetBufferList==NULL)
	{
		return ;
	}
	do
	{
		pMdl = NET_BUFFER_FIRST_MDL(NET_BUFFER_LIST_FIRST_NB(pNetBufferList));
		TotalLength = NET_BUFFER_DATA_LENGTH(NET_BUFFER_LIST_FIRST_NB(pNetBufferList));

		if (pMdl==NULL)
		{
			kprintf("FreeNetBufferList()pMdl==Null\n");
			break;
		}

		NdisQueryMdl(
			pMdl,
			(PVOID *)&pCopyData,
			&BufferLength,
			NormalPagePriority);

		if (BufferLength!=TotalLength)
		{
			kprintf("FreeNetBufferList() NPROT_ASSERT(BufferLength == TotalLength)\n");
			break;
		}

		if (pCopyData==NULL)
		{
			kprintf("FreeNetBufferList() pCopyData==Null\n");
			break;
		}

		if (1)
		{

			if (g_pfnNdisFreeNetBufferList==0)
			{
				break;
			}
			_asm 
			{
				push pNetBufferList
				call g_pfnNdisFreeNetBufferList
			}
		}

		//NdisFreeNetBufferList(pNetBufferList);

		IoFreeMdl(pMdl);

		kfree(pCopyData);
		break;


	}
	while (FALSE);


}
//////////////////////////////////////////////////////////////////////////
//驱动退出的时候应该调用这个
VOID	ReleaseNetBufferListPool()
{
	UNICODE_STRING	uniRoutineName;


	RtlInitUnicodeString(&uniRoutineName, L"NdisFreeNetBufferListPool");
	if (g_pfnNdisFreeNetBufferListPool==0)
	{
		return ;
	}
	if (g_NetBufferListPool==NULL)
	{
		return ;
	}
	_asm 
	{
		push g_NetBufferListPool
		mov eax,g_pfnNdisFreeNetBufferListPool
		call eax
	}
}
//////////////////////////////////////////////////////////////////////////

PNET_BUFFER_LIST_KK
AllocateNetBufferList(
    IN DWORD                          DataLength,
    OUT PUCHAR *                     ppDataBuffer
    )
/*++

Routine Description:

    Allocate resources to copy and queue a received net buffer list

Arguments:

    DataLength - total length in bytes of the net buffer list's first net buffer
    ppDataBuffer - place to return pointer to allocated buffer

Return Value:

    Pointer to NDIS packet if successful, else NULL.

--*/
{
    PNET_BUFFER_LIST_KK            pNetBufList;
    PMDL                        pMdl;
    PUCHAR                      pDataBuffer;

    pNetBufList = NULL;
    pMdl = NULL;
    pDataBuffer = NULL;

    do
    {
		pDataBuffer = kmalloc(DataLength);


        if (pDataBuffer == NULL)
        {
			kprintf("AllocRcvNbl: , failed to alloc data buffer %d bytes\n", DataLength);
            break;
        }

        //
        //  Make this an NDIS buffer.
        //
//         #pragma prefast(suppress:6014, "The instance is freed by calling NdisFreeMdl(pMdl)")
//         pMdl = NdisAllocateMdl(pOpenContext->BindingHandle, pDataBuffer, DataLength);
        pMdl	=	IoAllocateMdl(pDataBuffer, DataLength, FALSE, FALSE, NULL);
        if (pMdl == NULL)
        {
			kprintf("AllocateRcvNbl:  failed to alloc MDL, %d bytes\n", DataLength);
            break;
        }
// 		__asm int 3
 		MmBuildMdlForNonPagedPool(pMdl);
		if (g_NetBufferListPool==NULL)
		{

			NET_BUFFER_LIST_POOL_PARAMETERSWin7 PoolParameters;
			UNICODE_STRING	uniRoutineName;
			ULONG	ulret=0;
			NdisZeroMemory(&PoolParameters, sizeof(NET_BUFFER_LIST_POOL_PARAMETERSWin7));
#define NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1 1
			PoolParameters.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
			PoolParameters.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
			PoolParameters.Header.Size = sizeof(PoolParameters);
			PoolParameters.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT ;
			PoolParameters.ContextSize = 0;
			PoolParameters.fAllocateNetBuffer = TRUE;
			PoolParameters.PoolTag = 'ggoo';

			
			if (g_pfnNdisAllocateNetBufferListPool==0)
			{
				break;
			}
			_asm
			{

					lea ebx, PoolParameters
					push ebx
					push 0
					call g_pfnNdisAllocateNetBufferListPool
					mov g_NetBufferListPool, eax
			}

		}
		if (g_NetBufferListPool==NULL)
		{
			break;
		}
 

        pNetBufList = MyNdisAllocateNetBufferAndNetBufferList(
                        g_NetBufferListPool,
                        0,                              // ContextSize
                        0,                              // ContextBackfill
                        pMdl,                    // MdlChain
                        0,                              // DataOffset
                        DataLength);                   // DataLength
                         
        if (pNetBufList == NULL)
        {
			kprintf("AllocateRcvNbl:  failed to alloc Net Buffer List, %d bytes\n", DataLength);
            break;
        }


        *ppDataBuffer = pDataBuffer;

    }
    while (FALSE);

    if (pNetBufList == NULL)
    {
        //
        //  Clean up
        //
        if (pMdl != NULL)
        {
            IoFreeMdl(pMdl);
        }

        if (pDataBuffer != NULL)
        {
            kfree(pDataBuffer);
        }
    }

    return (pNetBufList);
}

//////////////////////////////////////////////////////////////////////////


//copy buffer_len of pbuffer bytes to Net_Buffer
NDIS_STATUS copy_buffer_to_netbuffer(PNET_BUFFER_KK pNet_Buffer, PUCHAR pbuffer, ULONG buffer_len)
{
	ULONG			Length;
	NDIS_STATUS		Status = NDIS_STATUS_SUCCESS;
	PUCHAR			SrcMemory;
	PMDL			CurrentMdl;
	ULONG			MdlOffset;
	BOOLEAN			bfirstmdl=TRUE;
	bfirstmdl=TRUE;

	if (NET_BUFFER_DATA_LENGTH(pNet_Buffer)< buffer_len)
	{
		DbgPrint(("[] fuck, what the hell is going on\r\n"));
	}


	//
	// Start copy from current MDL
	//
	CurrentMdl = NET_BUFFER_CURRENT_MDL(pNet_Buffer);

	// Data on current MDL may be offset from start of MDL
	// 
	while(CurrentMdl &&buffer_len)
	{
		SrcMemory = MmGetSystemAddressForMdlSafe(CurrentMdl, LowPagePriority);
		Length = MmGetMdlByteCount(CurrentMdl);
		if (!SrcMemory)
		{
			Status = NDIS_STATUS_RESOURCES;
			break;
		}
		if (bfirstmdl)
		{
			MdlOffset = NET_BUFFER_CURRENT_MDL_OFFSET(pNet_Buffer);
			SrcMemory += MdlOffset;
			Length -= MdlOffset;
			bfirstmdl =FALSE;
		}
		buffer_len	=	buffer_len-Length;
		NdisMoveMemory(SrcMemory, pbuffer, Length);
		pbuffer	=	pbuffer+Length;

		CurrentMdl = NDIS_MDL_LINKAGE(CurrentMdl);

		DbgPrint(("[**] copy_buffer_to_netbuffer in while\r\n"));
	}
	return Status;
}
////////////////////////////////////////////////////////////////////////////////