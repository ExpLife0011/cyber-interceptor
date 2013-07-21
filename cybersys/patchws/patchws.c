
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


//module for: patching sinffer for xp or 2003

//////////////////////////////////////////////////////////////////////////

ULONG_PTR	g_NPFReceiveHandler=0;
ULONG_PTR	g_NPFReceivePacketHandler=0;
struct my_NDIS_PROTOCOL_BLOCK	*g_pNpfProtocolBlock=NULL;
BOOLEAN	g_bAlreadyPatchWS	=	FALSE;
//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////

__declspec(naked) VOID NewNPFReceiveHandler()
{
	_asm
	{
			mov     edi,edi
			push    ebp
			mov     ebp,esp
			mov		eax,g_NPFReceiveHandler
			add		 eax,5
			jmp eax
	}
}
__declspec(naked) VOID NewNPFReceivePacketHandler()
{
	_asm
	{
			mov     edi,edi
			push    ebp
			mov     ebp,esp
			mov		eax,g_NPFReceivePacketHandler
			add		 eax,5
			jmp eax
	}
}

//////////////////////////////////////////////////////////////////////////
NTSTATUS	UnDoPatchWS2(char *pp,DWORD dwlen)
{
	NTSTATUS		status = STATUS_SUCCESS;
/*
aa801300 8bff            mov     edi,edi
aa801302 55              push    ebp
aa801303 8bec            mov     ebp,esp
*/
	ULONG	uRestoreCode	=	0x8b55ff8b;

	if (g_PatchwsVersion==6)
	{
		return UndoPatchwsWin7();
	}

	
	if (!g_bAlreadyPatchWS)
	{
		kprintf("have not patched ws yet\n");
		return status;
	}
	if (g_NPFReceivePacketHandler)
	{
		WPOFF();
		*(PULONG)g_NPFReceivePacketHandler =uRestoreCode;	
		WPON();

	}
	else
	{
		if (g_NPFReceiveHandler==0)
		{
			kprintf("what???  there is no receive handler for npf??\n");
			status	=	STATUS_UNSUCCESSFUL;
			return status;
		}
		WPOFF();
		*(PULONG)g_NPFReceiveHandler =uRestoreCode;	
		WPON();

	}
	g_bAlreadyPatchWS	=	FALSE;
	return status;

}
//////////////////////////////////////////////////////////////////////////

NTSTATUS	DoPatchWS2(char *ProName, DWORD dwLen)
{

	NTSTATUS		status = STATUS_SUCCESS;
	ULONG			uPatchRet3	=	0xcc001cc2;


	if (GetWindowsVersion()==Windows_7)
	{
		return doPatchwsWin7(ProName, dwLen);
	}

	if (g_bAlreadyPatchWS)
	{
		return status;
	}
	do 
	{
		g_pNpfProtocolBlock	=	(struct my_NDIS_PROTOCOL_BLOCK	*)GetProtocolBlockXP(ProName, dwLen);

		if (g_pNpfProtocolBlock==NULL)
		{
			status	=	STATUS_UNSUCCESSFUL;
			break;
		}
		g_NPFReceiveHandler	=	(ULONG)g_pNpfProtocolBlock->ProtocolCharacteristics.Ndis40Chars.ReceiveHandler;
		g_NPFReceivePacketHandler	=	(ULONG)g_pNpfProtocolBlock->ProtocolCharacteristics.Ndis40Chars.ReceivePacketHandler;
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

	} while (0);

	
	return status;

}


//////////////////////////////////////////////////////////////////////////

//失败返回0
ULONG	GetProtocolBlockXP(char *ProName, DWORD dwlen)
{
	
	UNICODE_STRING	uniNPF;
	ULONG			uHeader=0;
	NTSTATUS		status = STATUS_SUCCESS;
	struct my_NDIS_PROTOCOL_BLOCK	*pProtoBLock=NULL;
	BOOLEAN			bFound	=	FALSE;
	struct my_NDIS_PROTOCOL_BLOCK	*pNpfProtocolBlock=NULL;

	char szBuffer[1024];
	ANSI_STRING	aniStr1;

	RtlZeroMemory(szBuffer, sizeof(szBuffer));

	if (dwlen>sizeof(szBuffer))
	{
		return STATUS_UNSUCCESSFUL;
	}

	RtlMoveMemory(szBuffer, ProName, dwlen);

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
		pProtoBLock	=	(struct my_NDIS_PROTOCOL_BLOCK	*)uHeader;
		while(pProtoBLock)
		{
			if (RtlEqualUnicodeString(&pProtoBLock->ProtocolCharacteristics.Ndis40Chars.Name, &uniNPF,TRUE))
			{
				bFound	=	TRUE;
				break;
			}
			pProtoBLock	=	pProtoBLock->NextProtocol;
		}
		
		if (!bFound)
		{
			kprintf("Can not find npf.sys by its protocol name: PACKETDRIVER\n");
			break;
		}
		pNpfProtocolBlock	=	pProtoBLock;

		//NdisDeregisterProtocol(&status, (NDIS_HANDLE)uHeader);	// deregister it
		

	} while (0);
	RtlFreeUnicodeString(&uniNPF);
	return (ULONG)pNpfProtocolBlock;

}





//////////////////////////////////////////////////////////////////////////
/*
lkd> lmvmnpf
start    end        module name
aa7fd000 aa80c000   npf        (no symbols)           
Loaded symbol image file: \SystemRoot\system32\drivers\npf.sys
Image path: \SystemRoot\system32\drivers\npf.sys
Image name: npf.sys
Timestamp:        Wed Oct 21 01:57:28 2009 (4ADDFA08)
CheckSum:         0001060B
ImageSize:        0000F000

lkd> s -b aa7fd000 aa80c000 8B 7D 08 8D 0C 40 C1 E1 04 83 84 39
aa80134c  8b 7d 08 8d 0c 40 c1 e1-04 83 84 39 fc 0f 00 00  .}...@.....9....

 text:0001434C 8B 7D 08          mov     edi, [ebp+arg_0]
.text:0001434F 8D 0C 40          lea     ecx, [eax+eax*2]
.text:00014352 C1 E1 04          shl     ecx, 4
.text:00014355 83 84 39 FC 0F 00+add     dword ptr [ecx+edi+0FFCh], 1
.text:0001435D F6 05 00 B0 01 00+test    byte ptr dword_1B000, 1

lkd> dd aa80134c
aa80134c  8d087d8b e1c1400c 39848304 00000ffc
*/

NTSTATUS	DoPatchWS()
{
	ULONG	hc1,hc2,hc3;
	PULONG	target=NULL;
	ULONG	ulModuleSize=0;
	BOOLEAN	bFound	=	FALSE;
	NTSTATUS	status=STATUS_SUCCESS;


	hc1	=	0x8d087d8b;
	hc2	=	0xe1c1400c;
	hc3	=	0x39848304;
	
	target	=	(PULONG)GetMoudleBase("npf", &ulModuleSize);
	if (target==0 || ulModuleSize==0)
	{
		return STATUS_UNSUCCESSFUL;
	}
	for (; target<target+ulModuleSize; target++)
	{
		__try
		{
			//MmIsAddressValid判断有效性有点蛋疼
			if (!MmIsAddressValid(target))
			{
				target+=0x1000;
				target--;
				continue;
				
			}
			if (target[0]==hc1&&target[1]==hc2&&target[2]==hc3)
			{
				bFound	=	TRUE;
				break;
			}
		}
		__except(1)
		{
			return GetExceptionCode();
		}
	}
	if (!bFound)
	{
		return STATUS_UNSUCCESSFUL;
	}


	return status;

}


//////////////////////////////////////////////////////////////////////////


NTSTATUS	CheckProtocolExist(char *ProName, DWORD dwLen)
{
	UNICODE_STRING	uniDrvName;
	NTSTATUS	st	=	STATUS_SUCCESS;
	PDRIVER_OBJECT	DriverObject;
	ANSI_STRING	aniStr1;
	ANSI_STRING	aniStr2;
	ULONG		ulVersion=0;
	ULONG	ulret=0;

	char szBuffer[1024];
	char szBuffer2[1024];
	RtlZeroMemory(szBuffer, sizeof(szBuffer));
	
	RtlZeroMemory(szBuffer2, sizeof(szBuffer));
	
	if (dwLen>sizeof(szBuffer))
	{
		return STATUS_UNSUCCESSFUL;
	}
	RtlMoveMemory(szBuffer2, ProName, dwLen);

	ulVersion	=	GetWindowsVersion();
	if (ulVersion==Windows_7)
	{
		
		ulret = GetTargetProtocolBlockWin7(ProName, dwLen);
		if (ulret==0)
		{
			st	=	STATUS_UNSUCCESSFUL;
		}
	}
	else
	{
		if (ulVersion==Windows_2k3||ulVersion==Windows_XP)
		{
			ulret	=	GetProtocolBlockXP(ProName, dwLen);
			if (ulret==0)
			{
				st	=	STATUS_UNSUCCESSFUL;
			}
		}
	}


// 	sprintf_s(szBuffer, sizeof(szBuffer), "\\driver\\%s", szBuffer2);
// 
// 	RtlInitAnsiString(&aniStr1, szBuffer);
// 	RtlAnsiStringToUnicodeString(&uniDrvName, &aniStr1, TRUE);
// 
// 	st	=	ObReferenceObjectByName(&uniDrvName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType,KernelMode, NULL, &DriverObject);
// 	if (NT_SUCCESS(st))
// 	{
// 		ObDereferenceObject(DriverObject);
// 	}
// 	RtlFreeUnicodeString(&uniDrvName);

	return st;

}