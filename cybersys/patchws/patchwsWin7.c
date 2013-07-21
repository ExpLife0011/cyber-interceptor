
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
//module for: patching sinffer for WIN7
//////////////////////////////////////////////////////////////////////////


PNDIS_PROTOCOL_BLOCKWin7 g_pNpfProtocolBlockWin7=NULL;
DWORD			g_ReceiveHandlerOffset=0x84;
DWORD			g_ReceivePacketHandlerOffset=0x8c;
DWORD			g_ReceiveNetBufferListsHandlerOffset=0x58;
DWORD			g_PatchwsVersion=0;

DWORD			g_ReceiveNetBufferListsHandler=0;

//////////////////////////////////////////////////////////////////////////

VOID	__declspec(naked) NewReceiveNetBufferListsHandler(
							  /*IN NDIS_HANDLE */DWORD                 ProtocolBindingContext,
							  /*IN PNET_BUFFER_LIST*/DWORD             pNetBufferLists,
							  /*IN NDIS_PORT_NUMBER*/DWORD             PortNumber,
							  IN DWORD                        NumberOfNetBufferLists,
							  IN DWORD                        ReceiveFlags
							  )
{
	_asm
	{
			mov     edi,edi
			push    ebp
			mov     ebp,esp
			mov		eax,g_ReceiveNetBufferListsHandler
			add		 eax,5
			jmp eax
	}
};
//////////////////////////////////////////////////////////////////////////
NTSTATUS	UndoPatchwsWin7()
{
	NTSTATUS		status = STATUS_SUCCESS;
	/*
	aa801300 8bff            mov     edi,edi
	aa801302 55              push    ebp
	aa801303 8bec            mov     ebp,esp
	*/
	ULONG			uRestoreCode	=	0x8b55ff8b;

	if (!g_bAlreadyPatchWS)
	{
		kprintf("have not patched ws yet\n");
		return status;
	}
	if (g_ReceiveNetBufferListsHandler)
	{
		WPOFF();
		*(PULONG)g_ReceiveNetBufferListsHandler =uRestoreCode;	
		WPON();

	}
	g_bAlreadyPatchWS	=	FALSE;
	return status;

}
//////////////////////////////////////////////////////////////////////////

NTSTATUS	doPatchwsWin7(char *ProName, DWORD dwLen)
{

	NTSTATUS		status = STATUS_SUCCESS;
	ULONG			uPatchRet3	=	0xcc001cc2;
	ULONG			uPatchRet5	=	0x900014c2;

	PDWORD			pdwTmp	=	NULL;
	DWORD			dwTmp	=	0;

	if (g_bAlreadyPatchWS)
	{
		return status;
	}
	do 
	{
		g_pNpfProtocolBlockWin7	=	(PNDIS_PROTOCOL_BLOCKWin7)GetTargetProtocolBlockWin7(ProName, dwLen);

		if (g_pNpfProtocolBlockWin7==NULL)
		{
			status	=	STATUS_UNSUCCESSFUL;
			break;
		}
		//只搞版本号为5的
		g_PatchwsVersion	=	g_pNpfProtocolBlockWin7->MajorNdisVersion;
		if (g_PatchwsVersion<=5)
		{


			dwTmp	=	(DWORD)g_pNpfProtocolBlockWin7;
			pdwTmp	=	(PDWORD)(dwTmp+g_ReceiveHandlerOffset);
			//Get the old recv
			g_NPFReceiveHandler		=	(ULONG)*pdwTmp;
			
			dwTmp	=	(DWORD)g_pNpfProtocolBlockWin7;
			pdwTmp	=	(PDWORD)(dwTmp+g_ReceivePacketHandlerOffset);
			
			//Get the old recvpacket
			g_NPFReceivePacketHandler		=	(ULONG)*pdwTmp;
			if (g_NPFReceivePacketHandler)
			{
				WPOFF();
				*(PULONG)g_NPFReceivePacketHandler =uPatchRet3;	
				WPON();

			}
			else
			{
				if (g_NPFReceiveHandler==0)
				{
					kprintf("what???  there is no receive handler for npf??\n");
					status	=	STATUS_UNSUCCESSFUL;
					break;
				}
				WPOFF();
				*(PULONG)g_NPFReceiveHandler =uPatchRet3;	
				WPON();

			}
			g_bAlreadyPatchWS	=	TRUE;
			break;
		}////end for只搞版本号为5的

		//ndis 6
		if (g_PatchwsVersion==6)
		{

			dwTmp	=	(DWORD)g_pNpfProtocolBlockWin7;
			pdwTmp	=	(PDWORD)(dwTmp+g_ReceiveNetBufferListsHandlerOffset);
			//Get the old recvlist
			g_ReceiveNetBufferListsHandler		=	*pdwTmp;
			if (g_ReceiveNetBufferListsHandler)
			{
				WPOFF();
				*(PULONG)g_ReceiveNetBufferListsHandler =uPatchRet5;	
				WPON();

			}
			else
			{
				status	=	STATUS_UNSUCCESSFUL;
			}
			
		break;
		}
		


	} while (0);


	return status;


}
//////////////////////////////////////////////////////////////////////////


//失败返回0
ULONG	GetTargetProtocolBlockWin7(char *ProName, DWORD dwLen)
{

	UNICODE_STRING	uniNPF;
	ULONG			uHeader=0;
	NTSTATUS		status = STATUS_SUCCESS;
	PNDIS_PROTOCOL_BLOCKWin7	pProtoBLock=NULL;
	BOOLEAN			bFound	=	FALSE;
	PNDIS_PROTOCOL_BLOCKWin7	pNpfProtocolBlock=NULL;
	char szBuffer[1024];
	ANSI_STRING	aniStr1;

	RtlZeroMemory(szBuffer, sizeof(szBuffer));

	if (dwLen>sizeof(szBuffer))
	{
		return STATUS_UNSUCCESSFUL;
	}

	RtlMoveMemory(szBuffer, ProName, dwLen);

	RtlInitAnsiString(&aniStr1, szBuffer);
	RtlAnsiStringToUnicodeString(&uniNPF, &aniStr1, TRUE);


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
			if (RtlEqualUnicodeString(&pProtoBLock->Name, &uniNPF,TRUE))
			{
				bFound	=	TRUE;
				break;
			}
			pProtoBLock	=	(PNDIS_PROTOCOL_BLOCKWin7)pProtoBLock->NextProtocol;
		}

		if (!bFound)
		{
			kprintf("Can not find  protocol name: %s\n", ProName);
			break;
		}
		pNpfProtocolBlock	=	pProtoBLock;

		//NdisDeregisterProtocol(&status, (NDIS_HANDLE)uHeader);	// deregister it

	} while (0);

	RtlFreeUnicodeString(&uniNPF);

	return (ULONG)pNpfProtocolBlock;

}
